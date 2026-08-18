//! HTTP/3.
//!
//! hyper does not implement the HTTP/3 wire format itself; it drives the `h3`
//! crate the same way it drives `h2` for HTTP/2. What lives here is the part
//! hyper *does* own: bridging [`hyper::rt::quic`](crate::rt::quic) to
//! `h3::quic` (see [`glue`]), turning h3's streams into
//! [`Incoming`](crate::body::Incoming) bodies, and routing requests through a
//! [`Service`](crate::service::Service).

use std::task::{Context, Poll};

use bytes::{Buf, Bytes};
use futures_core::ready;
use http_body::Frame;

pub(crate) mod glue;

#[cfg(feature = "client")]
pub(crate) mod client;
#[cfg(feature = "server")]
pub(crate) mod server;

// ===== errors =====

/// Map an h3 connection error onto a `hyper::Error`.
///
/// A connection that ended with `H3_NO_ERROR` ended cleanly; that is not a
/// failure and must not be reported as one.
pub(crate) fn conn_error(err: h3::error::ConnectionError) -> Option<crate::Error> {
    if err.is_h3_no_error() {
        None
    } else {
        Some(crate::Error::new_h3(err))
    }
}

// ===== in-flight request tracking =====

/// Held for as long as one request is still in flight.
///
/// A request is not finished when its task is: the response body outlives the
/// exchange that produced it, and the request body may still be uploading. So
/// this is shared (via `Arc`) by every piece a single request owns, and the
/// connection only hears about the request once the last of them is dropped.
pub(crate) struct TaskGuard(tokio::sync::mpsc::UnboundedSender<()>);

impl TaskGuard {
    pub(crate) fn new(tx: tokio::sync::mpsc::UnboundedSender<()>) -> Self {
        TaskGuard(tx)
    }
}

impl Drop for TaskGuard {
    fn drop(&mut self) {
        // The connection future decrements its in-flight count for each of
        // these. A send failure just means the connection is already gone.
        let _ = self.0.send(());
    }
}

// ===== bodies =====

/// The receiving half of an HTTP/3 request or response body.
///
/// [`Incoming`](crate::body::Incoming) is a concrete type, but an h3 stream is
/// generic over the QUIC backend, so the two meet behind this trait. The
/// implementations below hold the h3 stream itself rather than pumping it
/// through a channel: polling for a frame reads straight from the QUIC stream,
/// so *not* polling leaves the data in the transport's receive window and the
/// peer stops sending. That is what keeps QUIC's flow control connected to
/// `Body` backpressure.
pub(crate) trait RecvBody: Send + Sync + 'static {
    /// Poll for the next body frame.
    fn poll_frame(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, crate::Error>>>;

    /// Whether the stream is known to be finished.
    fn is_end_stream(&self) -> bool;
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RecvState {
    Data,
    Trailers,
    Done,
}

/// Convert whatever `Buf` the backend produced into `Bytes`.
///
/// For a backend that already hands out `Bytes` — which is every backend worth
/// having — `copy_to_bytes` is a refcount bump, not a copy.
fn to_bytes(mut buf: impl Buf) -> Bytes {
    buf.copy_to_bytes(buf.remaining())
}

/// Generate a [`RecvBody`] over one of h3's two `RequestStream` types.
///
/// `h3::server::RequestStream` and `h3::client::RequestStream` have the same
/// receive API but are distinct types, and neither exposes a shared trait for
/// it, so the implementation is generated for each.
macro_rules! recv_body {
    ($name:ident, $stream:ty) => {
        pub(crate) struct $name<S, B>
        where
            S: h3::quic::RecvStream,
            B: Buf,
        {
            stream: $stream,
            state: RecvState,
            /// Keeps the connection alive while this body is still readable.
            _guard: Option<std::sync::Arc<TaskGuard>>,
        }

        impl<S, B> $name<S, B>
        where
            S: h3::quic::RecvStream,
            B: Buf,
        {
            pub(crate) fn new(stream: $stream, guard: Option<std::sync::Arc<TaskGuard>>) -> Self {
                Self {
                    stream,
                    state: RecvState::Data,
                    _guard: guard,
                }
            }
        }

        impl<S, B> RecvBody for $name<S, B>
        where
            S: h3::quic::RecvStream + Send + Sync + 'static,
            B: Buf + Send + Sync + 'static,
        {
            fn poll_frame(
                &mut self,
                cx: &mut Context<'_>,
            ) -> Poll<Option<Result<Frame<Bytes>, crate::Error>>> {
                if self.state == RecvState::Data {
                    match ready!(self.stream.poll_recv_data(cx)) {
                        Ok(Some(buf)) => return Poll::Ready(Some(Ok(Frame::data(to_bytes(buf))))),
                        Ok(None) => self.state = RecvState::Trailers,
                        Err(err) => {
                            self.state = RecvState::Done;
                            // An early response resets the request stream with
                            // `H3_NO_ERROR`. Like HTTP/2's `RST_STREAM(NO_ERROR)`,
                            // that ends the body, it does not fail it.
                            return Poll::Ready(if err.is_h3_no_error() {
                                None
                            } else {
                                Some(Err(crate::Error::new_h3_stream(err)))
                            });
                        }
                    }
                }

                if self.state == RecvState::Trailers {
                    let trailers = ready!(self.stream.poll_recv_trailers(cx));
                    self.state = RecvState::Done;
                    return Poll::Ready(match trailers {
                        Ok(Some(map)) => Some(Ok(Frame::trailers(map))),
                        Ok(None) => None,
                        Err(err) if err.is_h3_no_error() => None,
                        Err(err) => Some(Err(crate::Error::new_h3_stream(err))),
                    });
                }

                Poll::Ready(None)
            }

            fn is_end_stream(&self) -> bool {
                self.state == RecvState::Done
            }
        }

        impl<S, B> Drop for $name<S, B>
        where
            S: h3::quic::RecvStream,
            B: Buf,
        {
            fn drop(&mut self) {
                if self.state != RecvState::Done {
                    // The body was dropped without being read to the end —
                    // usually a handler that ignored the request body. Tell the
                    // peer to stop sending rather than letting it push bytes at
                    // a window nobody will ever drain.
                    //
                    // `H3_NO_ERROR` is the code the spec asks for here, not a
                    // stand-in for a cancellation code: RFC 9114 §4.1 says
                    // "H3_NO_ERROR SHOULD be used when requesting that the
                    // client stop sending on the request stream". Nothing went
                    // wrong; the rest of the body is simply not wanted.
                    self.stream.stop_sending(h3::error::Code::H3_NO_ERROR);
                }
            }
        }
    };
}

#[cfg(feature = "server")]
recv_body!(ServerRecvBody, h3::server::RequestStream<S, B>);
#[cfg(feature = "client")]
recv_body!(ClientRecvBody, h3::client::RequestStream<S, B>);
