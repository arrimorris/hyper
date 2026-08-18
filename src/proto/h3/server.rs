//! HTTP/3 server connections.
//!
//! The shape mirrors [`proto::h2::server`](crate::proto::h2::server): one
//! future drives the connection, accepting QUIC streams and handing each to the
//! executor as its own task, so a slow request body never blocks the ones next
//! to it.

use std::error::Error as StdError;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Buf;
use futures_core::ready;
use http::{Response, Version};
use tokio::sync::mpsc;

use crate::body::{Body, DecodedLength, Incoming as IncomingBody};
use crate::common::date;
use crate::common::future::poll_fn;
use crate::headers;
use crate::proto::h3::{glue, ServerRecvBody};
use crate::proto::{strip_connection_headers, MessageKind};
use crate::rt::bounds::Http3ServerConnExec;
use crate::rt::quic;
use crate::service::HttpService;

/// Settings for an HTTP/3 server connection.
#[derive(Clone, Debug)]
pub(crate) struct Config {
    pub(crate) max_field_section_size: Option<u64>,
    pub(crate) send_grease: Option<bool>,
    pub(crate) enable_extended_connect: Option<bool>,
    pub(crate) enable_datagram: Option<bool>,
    pub(crate) date_header: bool,
    pub(crate) max_late_requests: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            max_field_section_size: None,
            send_grease: None,
            enable_extended_connect: None,
            enable_datagram: None,
            date_header: true,
            max_late_requests: 0,
        }
    }
}

impl Config {
    fn h3_builder(&self) -> h3::server::Builder {
        let mut builder = h3::server::builder();
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

type H3Conn<Q, B> = h3::server::Connection<glue::Conn<Q>, B>;

/// h3's handshake (opening the control stream and sending SETTINGS) is only
/// available as an `async fn`, and it is emphatically not cancel-safe —
/// restarting it would open a second control stream. So it is driven as a
/// single boxed future, once per connection.
type Handshaking<Q, B> =
    Pin<Box<dyn Future<Output = Result<H3Conn<Q, B>, h3::error::ConnectionError>> + Send>>;

/// Likewise for sending GOAWAY. The connection is moved into the future and
/// handed back when it resolves, so the write is never cancelled part-way and
/// the frame cannot be left half-queued.
type GoingAway<Q, B> = Pin<
    Box<dyn Future<Output = (Box<H3Conn<Q, B>>, Result<(), h3::error::ConnectionError>)> + Send>,
>;

enum State<Q, B>
where
    Q: quic::Connection<B>,
    Q::BidiStream: quic::BidiStream<B>,
    B: Buf,
{
    Handshaking(Handshaking<Q, B>),
    /// Boxed so a large `h3::server::Connection` does not inflate every
    /// variant of this enum.
    Accepting(Box<H3Conn<Q, B>>),
    GoingAway(GoingAway<Q, B>),
    Done,
}

/// The future that drives an HTTP/3 server connection.
pub(crate) struct Server<Q, S, B, E>
where
    Q: quic::Connection<B>,
    Q::BidiStream: quic::BidiStream<B>,
    B: Buf,
{
    state: State<Q, B>,
    service: S,
    exec: E,
    config: Config,
    /// Set when the user asks for a graceful shutdown.
    goaway_requested: bool,
    /// Set once GOAWAY has actually been written.
    goaway_sent: bool,
    /// Cloned into every in-flight request task; dropped when the task ends.
    ///
    /// Taking this out and then polling `tasks_rx` to `None` is how the
    /// connection learns that every request it accepted has been answered.
    /// h3 keeps that bookkeeping to itself, so hyper keeps its own.
    tasks_tx: Option<mpsc::UnboundedSender<()>>,
    tasks_rx: mpsc::UnboundedReceiver<()>,
}

impl<Q, S, B, E> Server<Q, S, B, E>
where
    Q: quic::Connection<B> + Send + 'static,
    Q::BidiStream: quic::BidiStream<B> + Send + 'static,
    Q::SendStream: Send + 'static,
    Q::RecvStream: Send + 'static,
    Q::OpenStreams: Send + 'static,
    <Q::BidiStream as quic::BidiStream<B>>::SendStream: Send + 'static,
    <Q::BidiStream as quic::BidiStream<B>>::RecvStream: Send + Sync + 'static,
    B: Buf + Send + Sync + 'static,
{
    pub(crate) fn new(quic: Q, service: S, config: Config, exec: E) -> Self {
        let builder = config.h3_builder();
        let handshake = Box::pin(async move { builder.build(glue::Conn(quic)).await });
        let (tasks_tx, tasks_rx) = mpsc::unbounded_channel();

        Server {
            state: State::Handshaking(handshake),
            service,
            exec,
            config,
            goaway_requested: false,
            goaway_sent: false,
            tasks_tx: Some(tasks_tx),
            tasks_rx,
        }
    }

    /// Start a graceful shutdown: send GOAWAY, then finish answering the
    /// requests that were already accepted before resolving.
    pub(crate) fn graceful_shutdown(&mut self) {
        self.goaway_requested = true;
    }
}

impl<Q, S, B, E, Bd> Server<Q, S, B, E>
where
    Q: quic::Connection<B> + Send + 'static,
    Q::BidiStream: quic::BidiStream<B> + Send + 'static,
    Q::SendStream: Send + 'static,
    Q::RecvStream: Send + 'static,
    Q::OpenStreams: Send + 'static,
    <Q::BidiStream as quic::BidiStream<B>>::SendStream: Send + 'static,
    <Q::BidiStream as quic::BidiStream<B>>::RecvStream: Send + Sync + 'static,
    B: Buf + Send + Sync + 'static,
    S: HttpService<IncomingBody, ResBody = Bd> + Clone + Send + 'static,
    S::Error: Into<Box<dyn StdError + Send + Sync>>,
    S::Future: Send,
    Bd: Body<Data = B> + Send + 'static,
    Bd::Error: Into<Box<dyn StdError + Send + Sync>>,
    E: Http3ServerConnExec,
{
    pub(crate) fn poll_server(&mut self, cx: &mut Context<'_>) -> Poll<crate::Result<()>> {
        loop {
            // Drive the states that own a future first. Each arm either
            // advances `self.state` and loops, or returns.
            match &mut self.state {
                State::Handshaking(handshake) => {
                    let result = ready!(handshake.as_mut().poll(cx));
                    match result {
                        Ok(conn) => {
                            trace!("http3 handshake complete");
                            self.state = State::Accepting(Box::new(conn));
                        }
                        Err(err) => {
                            self.state = State::Done;
                            return Poll::Ready(finish(err));
                        }
                    }
                    continue;
                }
                State::GoingAway(fut) => {
                    let (conn, result) = ready!(fut.as_mut().poll(cx));
                    self.goaway_sent = true;
                    // No further requests will be accepted, so stop holding a
                    // sender open; `tasks_rx` can now reach its end.
                    self.tasks_tx = None;
                    if let Err(err) = result {
                        self.state = State::Done;
                        return Poll::Ready(finish(err));
                    }
                    trace!("http3 sent GOAWAY");
                    self.state = State::Accepting(conn);
                    continue;
                }
                State::Done => return Poll::Ready(Ok(())),
                State::Accepting(_) => {}
            }

            if self.goaway_requested && !self.goaway_sent {
                let State::Accepting(mut conn) = std::mem::replace(&mut self.state, State::Done)
                else {
                    unreachable!("state was just matched as Accepting");
                };
                let max_late = self.config.max_late_requests;
                self.state = State::GoingAway(Box::pin(async move {
                    let result = conn.shutdown(max_late).await;
                    (conn, result)
                }));
                continue;
            }

            match self.poll_accept(cx) {
                Poll::Ready(Ok(true)) => continue,
                Poll::Ready(Ok(false)) => {
                    if !self.goaway_sent {
                        // Answer the peer's GOAWAY with our own before going.
                        self.goaway_requested = true;
                        continue;
                    }
                    self.state = State::Done;
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Err(err)) => {
                    self.state = State::Done;
                    return Poll::Ready(Err(err));
                }
                Poll::Pending => {}
            }

            // GOAWAY is out; the connection is finished once every request it
            // already accepted has been answered.
            if self.goaway_sent {
                if let Poll::Ready(None) = self.tasks_rx.poll_recv(cx) {
                    trace!("http3 graceful shutdown complete");
                    self.state = State::Done;
                    return Poll::Ready(Ok(()));
                }
            }

            return Poll::Pending;
        }
    }

    /// Accept at most one request stream.
    ///
    /// `Ok(true)` means a request was dispatched and the caller should loop
    /// again; `Ok(false)` means the connection has no more requests coming.
    fn poll_accept(&mut self, cx: &mut Context<'_>) -> Poll<crate::Result<bool>> {
        let State::Accepting(conn) = &mut self.state else {
            unreachable!("poll_accept called outside of Accepting");
        };

        let stream = match ready!(conn.poll_accept_request_stream(cx)) {
            Ok(Some(stream)) => stream,
            Ok(None) => return Poll::Ready(Ok(false)),
            Err(err) => return Poll::Ready(finish(err).map(|()| false)),
        };

        let resolver = conn.create_resolver(h3::frame::FrameStream::new(
            h3::stream::BufRecvStream::new(stream),
        ));
        suppress_further_grease(conn);

        let guard = self.tasks_tx.clone();
        let service = self.service.clone();
        let date_header = self.config.date_header;

        self.exec.execute_h3stream(H3Stream::new(async move {
            // Dropped when this request finishes, which is what tells the
            // connection future that a graceful shutdown may complete.
            let _guard = guard;
            serve_stream(resolver, service, date_header).await;
        }));

        Poll::Ready(Ok(true))
    }
}

/// Send the GREASE frame on the first request of a connection only.
///
/// h3 seeds this flag from its builder's `send_grease`, copies it into every
/// `RequestResolver`, and emits the frame from `RequestStream::finish`. The
/// "once per connection" part comes from `Connection::accept` clearing the
/// connection-level flag immediately after it builds the first resolver.
/// hyper drives the poll-based accept path instead of `accept`, so it has to
/// clear the flag too; otherwise every response would carry a GREASE frame and
/// pay for an extra frame write.
///
/// This is the one place hyper touches a *field* of h3's `Connection` rather
/// than calling a method, and h3 marks that field as a deliberate, temporary
/// break in its own encapsulation. Written against h3 0.0.8.
///
/// The upstream fix is one line: move the `send_grease_frame = false` out of
/// `Connection::accept` and into `create_resolver_internal`, which every
/// caller — `accept` and embedders alike — already goes through. That makes
/// the public `create_resolver` correct on its own and lets this function be
/// deleted. It changes `create_resolver` to take `&mut self`, which is exactly
/// the kind of change the `i-implement-a-third-party-backend...` feature
/// exists to permit.
///
/// Until then: if a future h3 renames or removes the field this fails to
/// compile rather than misbehaving, which is the failure mode to want.
fn suppress_further_grease<C, B>(conn: &mut h3::server::Connection<C, B>)
where
    C: h3::quic::Connection<B>,
    B: Buf,
{
    conn.inner.send_grease_frame = false;
}

/// A connection that ended with `H3_NO_ERROR` ended cleanly.
fn finish(err: h3::error::ConnectionError) -> crate::Result<()> {
    match super::conn_error(err) {
        Some(err) => Err(err),
        None => Ok(()),
    }
}

/// A single HTTP/3 request/response exchange, spawned on the executor.
///
/// This is a boxed future rather than a hand-written state machine because
/// h3 0.0.8 only offers `async fn` for the send half of a request stream
/// (`send_response`, `send_data`, `send_trailers`, `finish`), and a header
/// block cannot be produced without them — QPACK encoding is private to h3.
/// One allocation per request is the price; it disappears if h3 grows a
/// poll-based send API.
#[must_use = "futures do nothing unless polled"]
pub struct H3Stream {
    inner: Pin<Box<dyn Future<Output = ()> + Send>>,
}

impl H3Stream {
    fn new<F>(fut: F) -> Self
    where
        F: Future<Output = ()> + Send + 'static,
    {
        H3Stream {
            inner: Box::pin(fut),
        }
    }
}

impl Future for H3Stream {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.inner.as_mut().poll(cx)
    }
}

impl std::fmt::Debug for H3Stream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("H3Stream").finish()
    }
}

async fn serve_stream<C, B, S, Bd>(
    resolver: h3::server::RequestResolver<C, B>,
    mut service: S,
    date_header: bool,
) where
    C: h3::quic::Connection<B>,
    C::BidiStream: h3::quic::BidiStream<B>,
    <C::BidiStream as h3::quic::BidiStream<B>>::RecvStream: Send + Sync + 'static,
    B: Buf + Send + Sync + 'static,
    S: HttpService<IncomingBody, ResBody = Bd>,
    S::Error: Into<Box<dyn StdError + Send + Sync>>,
    Bd: Body<Data = B>,
    Bd::Error: Into<Box<dyn StdError + Send + Sync>>,
{
    let (head, stream) = match resolver.resolve_request().await {
        Ok(req) => req,
        Err(_err) => {
            debug!("http3 error reading request head: {}", _err);
            return;
        }
    };

    // Split so the request body can be read while the response is written.
    // This is why `rt::quic::BidiStream` exists.
    let (mut send, recv) = stream.split();

    let content_length: DecodedLength = headers::content_length_parse_all(head.headers()).into();
    let mut req =
        head.map(|()| IncomingBody::h3(Box::new(ServerRecvBody::new(recv)), content_length));
    *req.version_mut() = Version::HTTP_3;

    let res = match service.call(req).await {
        Ok(res) => res,
        Err(err) => {
            let _err = crate::Error::new_user_service(err);
            warn!("http3 service errored: {}", _err);
            send.stop_stream(h3::error::Code::H3_INTERNAL_ERROR);
            return;
        }
    };

    let (mut head, body) = res.into_parts();
    strip_connection_headers(&mut head.headers, MessageKind::Response);
    if date_header {
        head.headers
            .entry(http::header::DATE)
            .or_insert_with(date::update_and_header_value);
    }

    if let Err(_err) = send.send_response(Response::from_parts(head, ())).await {
        debug!("http3 error sending response: {}", _err);
        return;
    }

    if let Err(_err) = send_body(&mut send, body).await {
        debug!("http3 error sending response body: {}", _err);
        send.stop_stream(h3::error::Code::H3_INTERNAL_ERROR);
        return;
    }

    if let Err(_err) = send.finish().await {
        debug!("http3 error finishing response: {}", _err);
    }
}

/// Pump a response body onto a request stream.
///
/// `send_data` awaits the QUIC stream's flow-control window before the next
/// frame is polled off the body, so a peer that stops reading stops the body
/// being produced rather than having it pile up in memory.
async fn send_body<S, B, Bd>(
    send: &mut h3::server::RequestStream<S, B>,
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
