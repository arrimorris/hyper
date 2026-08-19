//! HTTP/3 client connections.
//!
//! The shape mirrors [`proto::h2::client`](crate::proto::h2::client). Requests
//! arrive through hyper's dispatch channel, which is also what keeps the
//! QUIC-backend type parameters out of the public
//! [`SendRequest`](crate::client::conn::http3::SendRequest): everything
//! generic stays inside [`ClientTask`].

use std::error::Error as StdError;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Buf;
use futures_core::ready;
use http::{Request, Response, Version};
use tokio::sync::mpsc;

use crate::body::{Body, DecodedLength, Incoming as IncomingBody};
use crate::client::dispatch::{Callback, TrySendError};
use crate::common::future::poll_fn;
use crate::headers;
use crate::proto::h3::{glue, ClientRecvBody, TaskGuard};
use crate::proto::{strip_connection_headers, MessageKind};
use crate::rt::bounds::Http3ClientConnExec;
use crate::rt::quic;

type ClientRx<B> = crate::client::dispatch::Receiver<Request<B>, Response<IncomingBody>>;

/// Settings for an HTTP/3 client connection.
#[derive(Clone, Debug, Default)]
pub(crate) struct Config {
    pub(crate) max_field_section_size: Option<u64>,
    pub(crate) send_grease: Option<bool>,
    pub(crate) enable_extended_connect: Option<bool>,
    pub(crate) enable_datagram: Option<bool>,
}

impl Config {
    fn h3_builder(&self) -> h3::client::Builder {
        let mut builder = h3::client::builder();
        if let Some(size) = self.max_field_section_size {
            builder.max_field_section_size(size);
        }
        if let Some(grease) = self.send_grease {
            builder.send_grease(grease);
        }
        if let Some(enabled) = self.enable_extended_connect {
            builder.enable_extended_connect(enabled);
        }
        if let Some(enabled) = self.enable_datagram {
            builder.enable_datagram(enabled);
        }
        builder
    }
}

type Opener<Q, B> = <glue::Conn<Q> as h3::quic::Connection<B>>::OpenStreams;

/// Complete the HTTP/3 handshake over a QUIC connection.
pub(crate) async fn handshake<Q, B, E>(
    quic: Q,
    req_rx: ClientRx<B>,
    config: &Config,
    exec: E,
) -> crate::Result<ClientTask<Q, B, E>>
where
    Q: quic::Connection<B::Data> + Send + 'static,
    Q::BidiStream: Send + 'static,
    Q::SendStream: Send + 'static,
    Q::RecvStream: Send + 'static,
    Q::OpenStreams: Clone + Send + 'static,
    <Q::BidiStream as quic::BidiStream<B::Data>>::SendStream: Send + 'static,
    <Q::BidiStream as quic::BidiStream<B::Data>>::RecvStream: Send + Sync + 'static,
    B: Body + Send + 'static,
    B::Data: Send + Sync + 'static,
    B::Error: Into<Box<dyn StdError + Send + Sync>>,
    E: Http3ClientConnExec + Send + 'static,
{
    let (h3_conn, send_request) = config
        .h3_builder()
        .build(glue::Conn(quic))
        .await
        .map_err(|err| super::conn_error(err).unwrap_or_else(crate::Error::new_canceled))?;

    let (tasks_tx, tasks_rx) = mpsc::unbounded_channel();

    Ok(ClientTask {
        h3: h3_conn,
        send_request,
        req_rx,
        exec,
        closing: false,
        inflight: 0,
        tasks_tx,
        tasks_rx,
    })
}

/// The future that drives an HTTP/3 client connection.
pub(crate) struct ClientTask<Q, B, E>
where
    Q: quic::Connection<B::Data>,
    B: Body,
{
    h3: h3::client::Connection<glue::Conn<Q>, B::Data>,
    send_request: h3::client::SendRequest<Opener<Q, B::Data>, B::Data>,
    req_rx: ClientRx<B>,
    exec: E,
    closing: bool,
    /// Requests that have been dispatched but are not finished with the
    /// connection yet. A request stays counted until its exchange, its upload
    /// and its response body have all been dropped.
    inflight: usize,
    tasks_tx: mpsc::UnboundedSender<()>,
    tasks_rx: mpsc::UnboundedReceiver<()>,
}

impl<Q, B, E> ClientTask<Q, B, E>
where
    Q: quic::Connection<B::Data> + Send + 'static,
    Q::BidiStream: Send + 'static,
    Q::SendStream: Send + 'static,
    Q::RecvStream: Send + 'static,
    Q::OpenStreams: Clone + Send + 'static,
    <Q::BidiStream as quic::BidiStream<B::Data>>::SendStream: Send + 'static,
    <Q::BidiStream as quic::BidiStream<B::Data>>::RecvStream: Send + Sync + 'static,
    B: Body + Send + 'static,
    B::Data: Send + Sync + 'static,
    B::Error: Into<Box<dyn StdError + Send + Sync>>,
    E: Http3ClientConnExec + Send + 'static,
{
    pub(crate) fn poll_task(&mut self, cx: &mut Context<'_>) -> Poll<crate::Result<()>> {
        loop {
            // Pick up any requests handed over by a `SendRequest`.
            if !self.closing {
                match self.req_rx.poll_recv(cx) {
                    Poll::Ready(Some((req, cb))) => {
                        self.dispatch(req, cb);
                        continue;
                    }
                    Poll::Ready(None) => {
                        trace!("http3 client dropped all senders");
                        self.closing = true;
                        continue;
                    }
                    Poll::Pending => {}
                }
            }

            // Reap finished requests. Dropping every `SendRequest` means "no
            // more requests", not "abandon the responses I am still reading",
            // so the connection only ends once nothing is in flight.
            while let Poll::Ready(Some(())) = self.tasks_rx.poll_recv(cx) {
                self.inflight -= 1;
            }
            if self.closing && self.inflight == 0 {
                trace!("http3 client connection idle, closing");
                return Poll::Ready(Ok(()));
            }

            // Drive the connection itself. This resolves only when the QUIC
            // connection ends — including when it has simply been quiet for a
            // long time and the transport's idle timeout finally fires.
            let err = ready!(self.h3.poll_close(cx));
            return Poll::Ready(match super::conn_error(err) {
                Some(err) => Err(err),
                None => Ok(()),
            });
        }
    }

    fn dispatch(&mut self, req: Request<B>, cb: Callback<Request<B>, Response<IncomingBody>>) {
        let send_request = self.send_request.clone();
        let exec = self.exec.clone();

        self.inflight += 1;
        let guard = Arc::new(TaskGuard::new(self.tasks_tx.clone()));

        self.exec.execute_h3_future(H3ClientFuture::new(async move {
            exchange(send_request, req, cb, exec, guard).await;
        }));
    }
}

/// A single HTTP/3 client exchange, spawned on the executor.
///
/// Boxed for the same reason as the server's `H3Stream`: h3 only exposes
/// `async fn` for sending, and the QPACK encoder needed to write a header
/// block is private to h3.
#[must_use = "futures do nothing unless polled"]
pub struct H3ClientFuture {
    inner: Pin<Box<dyn Future<Output = ()> + Send>>,
}

impl H3ClientFuture {
    fn new<F>(fut: F) -> Self
    where
        F: Future<Output = ()> + Send + 'static,
    {
        H3ClientFuture {
            inner: Box::pin(fut),
        }
    }
}

impl Future for H3ClientFuture {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.inner.as_mut().poll(cx)
    }
}

impl std::fmt::Debug for H3ClientFuture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("H3ClientFuture").finish()
    }
}

async fn exchange<O, B, E>(
    mut send_request: h3::client::SendRequest<O, B::Data>,
    req: Request<B>,
    mut cb: Callback<Request<B>, Response<IncomingBody>>,
    mut exec: E,
    guard: Arc<TaskGuard>,
) where
    O: h3::quic::OpenStreams<B::Data> + Clone + Send + 'static,
    O::BidiStream: h3::quic::BidiStream<B::Data> + Send + 'static,
    <O::BidiStream as h3::quic::BidiStream<B::Data>>::SendStream: Send + 'static,
    <O::BidiStream as h3::quic::BidiStream<B::Data>>::RecvStream: Send + Sync + 'static,
    B: Body + Send + 'static,
    B::Data: Buf + Send + Sync + 'static,
    B::Error: Into<Box<dyn StdError + Send + Sync>>,
    E: Http3ClientConnExec + Send + 'static,
{
    let (mut parts, body) = req.into_parts();

    // Everything `send_request` below can fail on — the peer having sent
    // GOAWAY, opening the QUIC stream, encoding the header block — happens
    // before a single byte of this request reaches the wire. So unlike
    // HTTP/2, where the head is on a shared connection by the time anything
    // can go wrong, HTTP/3 can always hand the request back for the caller to
    // retry elsewhere. That is what `TrySendError::take_message` is for, and
    // it is what lets a pool survive the peer going away mid-flight instead
    // of failing the request outright.
    //
    // Taken before the rewrites below so what comes back is the caller's own
    // request, not hyper's HTTP/3 rendering of it — the retry may well go out
    // over a different protocol.
    let retry = parts.clone();

    strip_connection_headers(&mut parts.headers, MessageKind::Request);
    if let Some(len) = body.size_hint().exact() {
        if len != 0 || headers::method_has_defined_payload_semantics(&parts.method) {
            headers::set_content_length_if_missing(&mut parts.headers, len);
        }
    }
    parts.version = Version::HTTP_3;

    let stream = match send_request
        .send_request(Request::from_parts(parts, ()))
        .await
    {
        Ok(stream) => stream,
        Err(err) => {
            cb.send(Err(TrySendError {
                error: crate::Error::new_h3_stream(err),
                message: Some(Request::from_parts(retry, body)),
            }));
            return;
        }
    };

    // Split so the request body can keep uploading while the response is
    // read. A server that rejects a large upload early — say a `413` — is
    // heard immediately instead of after the whole body has gone out.
    let (mut send, mut recv) = stream.split();

    // Lets this task tell the upload to stop if the caller gives up. Sending
    // means "cancelled"; the sender simply being dropped means this task
    // finished normally and the upload should carry on.
    let (cancel_tx, cancel_rx) = tokio::sync::oneshot::channel::<()>();

    let upload_guard = Arc::clone(&guard);
    exec.execute_h3_future(H3ClientFuture::new(async move {
        let _guard = upload_guard;
        let outcome = {
            let mut pump = std::pin::pin!(send_body(&mut send, body));
            let mut cancel = cancel_rx;
            let mut watching = true;
            poll_fn(|cx| {
                if watching {
                    match Pin::new(&mut cancel).poll(cx) {
                        Poll::Ready(Ok(())) => return Poll::Ready(Upload::Cancelled),
                        // The request task is done with us; keep uploading.
                        Poll::Ready(Err(_)) => watching = false,
                        Poll::Pending => {}
                    }
                }
                pump.as_mut().poll(cx).map(Upload::Finished)
            })
            .await
        };

        match outcome {
            Upload::Cancelled => send.stop_stream(h3::error::Code::H3_REQUEST_CANCELLED),
            Upload::Finished(Err(_err)) => {
                debug!("http3 error sending request body: {}", _err);
                send.stop_stream(h3::error::Code::H3_REQUEST_CANCELLED);
            }
            Upload::Finished(Ok(())) => {
                if let Err(_err) = send.finish().await {
                    debug!("http3 error finishing request: {}", _err);
                }
            }
        }
    }));

    // Wait for the response head, but give up the moment the caller drops the
    // future it is waiting on. Dropping an in-flight request is how hyper
    // cancels one, and on HTTP/3 — as on HTTP/2 — that must reset this single
    // stream rather than leaving the peer streaming a response into the void.
    let received = {
        let mut response = std::pin::pin!(recv.recv_response());
        poll_fn(|cx| {
            // Cancellation is checked first on purpose. If the caller drops
            // the future in the same wake-up that the response head lands,
            // the head is discarded rather than delivered to nobody — the
            // caller said it no longer wants this. Do not "fix" this by
            // preferring the response.
            if cb.poll_canceled(cx).is_ready() {
                return Poll::Ready(None);
            }
            response.as_mut().poll(cx).map(Some)
        })
        .await
    };

    let head = match received {
        Some(Ok(head)) => head,
        Some(Err(err)) => {
            cb.send(Err(TrySendError {
                error: crate::Error::new_h3_stream(err),
                message: None,
            }));
            return;
        }
        None => {
            trace!("http3 request canceled by caller");
            let _ = cancel_tx.send(());
            recv.stop_sending(h3::error::Code::H3_REQUEST_CANCELLED);
            return;
        }
    };

    let content_length: DecodedLength = headers::content_length_parse_all(head.headers()).into();
    let mut res = head.map(|()| {
        IncomingBody::h3(
            Box::new(ClientRecvBody::new(recv, Some(guard))),
            content_length,
        )
    });
    *res.version_mut() = Version::HTTP_3;

    cb.send(Ok(res));
}

/// How the request-body upload ended.
enum Upload {
    /// The caller dropped the request before the response arrived.
    Cancelled,
    Finished(crate::Result<()>),
}

/// Pump a request body onto a request stream.
///
/// `send_data` awaits the QUIC stream's flow-control window before the next
/// frame is polled off the body, so a server that stops reading stops the
/// upload being produced rather than having it pile up in memory.
async fn send_body<S, B, Bd>(
    send: &mut h3::client::RequestStream<S, B>,
    body: Bd,
) -> crate::Result<()>
where
    S: h3::quic::SendStream<B>,
    B: Buf,
    Bd: Body<Data = B>,
    Bd::Error: Into<Box<dyn StdError + Send + Sync>>,
{
    let mut body = std::pin::pin!(body);

    loop {
        let frame = match poll_fn(|cx| body.as_mut().poll_frame(cx)).await {
            Some(Ok(frame)) => frame,
            Some(Err(err)) => return Err(crate::Error::new_user_body(err)),
            None => return Ok(()),
        };

        match frame.into_data() {
            Ok(data) => {
                if data.has_remaining() {
                    send.send_data(data)
                        .await
                        .map_err(crate::Error::new_h3_stream)?;
                }
            }
            Err(frame) => {
                if let Ok(trailers) = frame.into_trailers() {
                    send.send_trailers(trailers)
                        .await
                        .map_err(crate::Error::new_h3_stream)?;
                    return Ok(());
                }
                // Frame kinds hyper doesn't know how to send are skipped.
            }
        }
    }
}
