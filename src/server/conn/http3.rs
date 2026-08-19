//! HTTP/3 Server Connections.
//!
//! HTTP/3 runs over QUIC, which multiplexes streams in the transport itself
//! rather than on top of a single byte stream. So unlike
//! [`http1`](super::http1) and [`http2`](super::http2), which are handed
//! something that implements [`Read`](crate::rt::Read) + [`Write`](crate::rt::Write),
//! this module is handed a whole QUIC connection: anything implementing
//! [`hyper::rt::quic::Connection`](crate::rt::quic::Connection).
//!
//! # ALPN
//!
//! HTTP/3 is identified by the ALPN token `h3` ([RFC 9114 §3.1]), negotiated
//! by the QUIC layer's TLS configuration. That happens below anything this
//! module can see, so hyper cannot check it or set it for you: a peer that
//! offers a different token fails the QUIC handshake, and the connection
//! never reaches [`Builder::serve_connection`]. Configure it wherever your QUIC
//! backend takes its TLS settings — for quinn, `rustls`'s
//! `alpn_protocols`; see the `http3_server` example.
//!
//! [RFC 9114 §3.1]: https://www.rfc-editor.org/rfc/rfc9114.html#section-3.1
//!
//! # Example
//!
//! ```no_run
//! # use std::convert::Infallible;
//! # use bytes::Bytes;
//! # use http_body_util::Full;
//! # use hyper::{Request, Response};
//! # use hyper::body::Incoming;
//! # use hyper::rt::quic;
//! # use hyper::server::conn::http3;
//! # async fn run<Q, E>(quic: Q, exec: E) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
//! # where
//! #     Q: quic::Connection<Bytes> + Send + 'static,
//! #     Q::BidiStream: Send + 'static,
//! #     Q::SendStream: Send + 'static,
//! #     Q::RecvStream: Send + Sync + 'static,
//! #     Q::OpenStreams: Send + 'static,
//! #     <Q::BidiStream as quic::BidiStream<Bytes>>::SendStream: Send + 'static,
//! #     <Q::BidiStream as quic::BidiStream<Bytes>>::RecvStream: Send + Sync + 'static,
//! #     E: hyper::rt::bounds::Http3ServerConnExec,
//! # {
//! async fn hello(_: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
//!     Ok(Response::new(Full::new(Bytes::from("Hello, HTTP/3!"))))
//! }
//!
//! http3::Builder::new(exec)
//!     .serve_connection(quic, hyper::service::service_fn(hello))
//!     .await?;
//! # Ok(())
//! # }
//! ```

use std::error::Error as StdError;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use pin_project_lite::pin_project;

use crate::body::{Body, Incoming as IncomingBody};
use crate::proto;
use crate::rt::bounds::Http3ServerConnExec;
use crate::rt::quic;
use crate::service::HttpService;

pin_project! {
    /// A [`Future`](core::future::Future) representing an HTTP/3 connection, bound to a
    /// [`Service`](crate::service::Service), returned from
    /// [`Builder::serve_connection`](struct.Builder.html#method.serve_connection).
    ///
    /// To drive HTTP on this connection this future **must be polled**, typically with
    /// `.await`. If it isn't polled, no progress will be made on this connection.
    ///
    /// Individual requests are run on the executor, not on this future, so one
    /// slow request cannot hold up the others sharing the connection.
    #[must_use = "futures do nothing unless polled"]
    pub struct Connection<Q, S, E>
    where
        S: HttpService<IncomingBody>,
        Q: quic::Connection<<S::ResBody as Body>::Data>,
    {
        conn: proto::h3::server::Server<Q, S, <S::ResBody as Body>::Data, E>,
    }
}

/// A configuration builder for HTTP/3 server connections.
///
/// **Note**: The default values of options are *not considered stable*. They
/// are subject to change at any time.
#[derive(Clone, Debug)]
pub struct Builder<E> {
    exec: E,
    h3_builder: proto::h3::server::Config,
}

// ===== impl Connection =====

impl<Q, S, E> fmt::Debug for Connection<Q, S, E>
where
    S: HttpService<IncomingBody>,
    Q: quic::Connection<<S::ResBody as Body>::Data>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Connection").finish()
    }
}

impl<Q, S, B, E> Connection<Q, S, E>
where
    S: HttpService<IncomingBody, ResBody = B> + Clone + Send + 'static,
    S::Error: Into<Box<dyn StdError + Send + Sync>>,
    S::Future: Send,
    B: Body + Send + 'static,
    B::Data: Send + Sync + 'static,
    B::Error: Into<Box<dyn StdError + Send + Sync>>,
    Q: quic::Connection<B::Data> + Send + 'static,
    Q::BidiStream: Send + 'static,
    Q::SendStream: Send + 'static,
    Q::RecvStream: Send + Sync + 'static,
    Q::OpenStreams: Send + 'static,
    <Q::BidiStream as quic::BidiStream<B::Data>>::SendStream: Send + 'static,
    <Q::BidiStream as quic::BidiStream<B::Data>>::RecvStream: Send + Sync + 'static,
    E: Http3ServerConnExec,
{
    /// Start a graceful shutdown process for this connection.
    ///
    /// A `GOAWAY` frame is sent, telling the peer not to start new requests,
    /// and this `Connection` then resolves once every request it had already
    /// accepted has been answered. If nothing was in flight, it resolves as
    /// soon as the frame is written — see
    /// [`max_late_requests`](Builder::max_late_requests) for what that means
    /// for requests still crossing the network.
    ///
    /// # Note
    ///
    /// This should only be called while the `Connection` future is still
    /// pending. If called after `Connection::poll` has resolved, this does
    /// nothing.
    pub fn graceful_shutdown(self: Pin<&mut Self>) {
        self.project().conn.graceful_shutdown();
    }
}

impl<Q, S, B, E> Future for Connection<Q, S, E>
where
    S: HttpService<IncomingBody, ResBody = B> + Clone + Send + 'static,
    S::Error: Into<Box<dyn StdError + Send + Sync>>,
    S::Future: Send,
    B: Body + Send + 'static,
    B::Data: Send + Sync + 'static,
    B::Error: Into<Box<dyn StdError + Send + Sync>>,
    Q: quic::Connection<B::Data> + Send + 'static,
    Q::BidiStream: Send + 'static,
    Q::SendStream: Send + 'static,
    Q::RecvStream: Send + Sync + 'static,
    Q::OpenStreams: Send + 'static,
    <Q::BidiStream as quic::BidiStream<B::Data>>::SendStream: Send + 'static,
    <Q::BidiStream as quic::BidiStream<B::Data>>::RecvStream: Send + Sync + 'static,
    E: Http3ServerConnExec,
{
    type Output = crate::Result<()>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.project().conn.poll_server(cx)
    }
}

// ===== impl Builder =====

impl<E> Builder<E> {
    /// Create a new connection builder.
    ///
    /// This starts with the default options, and an executor which is a type
    /// that implements the [`Http3ServerConnExec`] trait.
    ///
    /// [`Http3ServerConnExec`]: crate::rt::bounds::Http3ServerConnExec
    pub fn new(exec: E) -> Self {
        Self {
            exec,
            h3_builder: proto::h3::server::Config::default(),
        }
    }

    /// Set the maximum size of a received header field section.
    ///
    /// This is advertised to the peer in `SETTINGS`; see the
    /// [header size constraints] section of RFC 9114.
    ///
    /// [header size constraints]: https://www.rfc-editor.org/rfc/rfc9114.html#name-header-size-constraints
    pub fn max_field_section_size(&mut self, max: u64) -> &mut Self {
        self.h3_builder.max_field_section_size = Some(max);
        self
    }

    /// Set whether to send "grease" frames and settings.
    ///
    /// Grease exercises peers' handling of unknown frame and setting types, so
    /// the protocol can be extended later without breaking them. See
    /// [RFC 9114 §7.2.8].
    ///
    /// Default is whatever the underlying HTTP/3 implementation prefers.
    ///
    /// [RFC 9114 §7.2.8]: https://www.rfc-editor.org/rfc/rfc9114.html#section-7.2.8
    pub fn send_grease(&mut self, enabled: bool) -> &mut Self {
        self.h3_builder.send_grease = Some(enabled);
        self
    }

    /// Set whether the extended CONNECT protocol is enabled.
    ///
    /// This is required by extensions built on HTTP/3, such as WebTransport.
    pub fn enable_extended_connect(&mut self, enabled: bool) -> &mut Self {
        self.h3_builder.enable_extended_connect = Some(enabled);
        self
    }

    /// Set whether HTTP/3 datagrams are accepted.
    ///
    /// See [RFC 9297].
    ///
    /// [RFC 9297]: https://www.rfc-editor.org/rfc/rfc9297.html
    pub fn enable_datagram(&mut self, enabled: bool) -> &mut Self {
        self.h3_builder.enable_datagram = Some(enabled);
        self
    }

    /// Set how many request streams past the last one already accepted are
    /// still worth serving once a
    /// [graceful shutdown](Connection::graceful_shutdown) has begun.
    ///
    /// This widens the stream-id limit advertised in `GOAWAY`. Requests the
    /// peer had already put on the wire when the frame went out land inside
    /// the window and are served; ones beyond it are rejected with
    /// `H3_REQUEST_REJECTED`, which tells the peer to retry them elsewhere.
    /// Default is 0.
    ///
    /// # Note
    ///
    /// The window only applies for as long as the connection is still
    /// draining. If nothing is in flight when `GOAWAY` goes out, the
    /// connection resolves right away and a request still crossing the
    /// network is not waited for — the window widens what is *accepted*, it
    /// does not hold an idle connection open. Waiting would mean waiting on a
    /// peer that may simply have nothing more to send, and hyper has no clock
    /// here to bound that. HTTP/2 gets the equivalent guarantee from its
    /// `PING`-acknowledged two-stage `GOAWAY` (RFC 9113 §6.8); HTTP/3
    /// describes the same procedure in [RFC 9114 §5.2], but `h3` exposes no
    /// way to wait for the acknowledgement.
    ///
    /// [RFC 9114 §5.2]: https://www.rfc-editor.org/rfc/rfc9114.html#section-5.2
    pub fn max_late_requests(&mut self, max: usize) -> &mut Self {
        self.h3_builder.max_late_requests = max;
        self
    }

    /// Set whether the `date` header should be included in HTTP responses.
    ///
    /// Note that including the `date` header is recommended by RFC 9110.
    ///
    /// Default is true.
    pub fn auto_date_header(&mut self, enabled: bool) -> &mut Self {
        self.h3_builder.date_header = enabled;
        self
    }

    /// Bind a QUIC connection together with a [`Service`](crate::service::Service).
    ///
    /// This returns a Future that must be polled in order for HTTP to be
    /// driven on the connection. Each request that arrives on the connection is
    /// dispatched to the executor as its own task and routed through `service`.
    pub fn serve_connection<S, Q, Bd>(&self, quic: Q, service: S) -> Connection<Q, S, E>
    where
        S: HttpService<IncomingBody, ResBody = Bd> + Clone + Send + 'static,
        S::Error: Into<Box<dyn StdError + Send + Sync>>,
        S::Future: Send,
        Bd: Body + Send + 'static,
        Bd::Data: Send + Sync + 'static,
        Bd::Error: Into<Box<dyn StdError + Send + Sync>>,
        Q: quic::Connection<Bd::Data> + Send + 'static,
        Q::BidiStream: Send + 'static,
        Q::SendStream: Send + 'static,
        Q::RecvStream: Send + Sync + 'static,
        Q::OpenStreams: Send + 'static,
        <Q::BidiStream as quic::BidiStream<Bd::Data>>::SendStream: Send + 'static,
        <Q::BidiStream as quic::BidiStream<Bd::Data>>::RecvStream: Send + Sync + 'static,
        E: Http3ServerConnExec,
    {
        Connection {
            conn: proto::h3::server::Server::new(
                quic,
                service,
                self.h3_builder.clone(),
                self.exec.clone(),
            ),
        }
    }
}
