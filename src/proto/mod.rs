//! Pieces pertaining to the HTTP message protocol.

cfg_feature! {
    #![feature = "http1"]

    pub(crate) mod h1;

    pub(crate) use self::h1::Conn;

    #[cfg(feature = "client")]
    pub(crate) use self::h1::dispatch;
    #[cfg(feature = "server")]
    pub(crate) use self::h1::ServerTransaction;
}

#[cfg(feature = "http2")]
pub(crate) mod h2;

#[cfg(all(feature = "http3", hyper_unstable_quic))]
pub(crate) mod h3;

// ===== connection header handling, shared by HTTP/2 and HTTP/3 =====
//
// Both protocols multiplex over a shared connection, so both forbid the
// hop-by-hop headers that HTTP/1 used to negotiate that connection. The rules
// in RFC 9113 §8.2.2 and RFC 9114 §4.2 are the same, so the code is too.

#[cfg(any(feature = "http2", all(feature = "http3", hyper_unstable_quic)))]
pub(crate) use self::connection_headers::{strip_connection_headers, MessageKind};

#[cfg(any(feature = "http2", all(feature = "http3", hyper_unstable_quic)))]
mod connection_headers {
    use http::header::{HeaderName, CONNECTION, TRANSFER_ENCODING, UPGRADE};
    use http::HeaderMap;

    // List of connection headers from RFC 9110 Section 7.6.1
    //
    // TE headers are allowed in requests as long as the value is "trailers", so they're
    // tested separately.
    static CONNECTION_HEADERS: [HeaderName; 4] = [
        HeaderName::from_static("keep-alive"),
        HeaderName::from_static("proxy-connection"),
        TRANSFER_ENCODING,
        UPGRADE,
    ];

    pub(crate) enum MessageKind {
        #[cfg(feature = "client")]
        Request,
        #[cfg(feature = "server")]
        Response,
    }

    pub(crate) fn strip_connection_headers(headers: &mut HeaderMap, kind: MessageKind) {
        for header in &CONNECTION_HEADERS {
            if headers.remove(header).is_some() {
                warn!("Connection header illegal in HTTP/2+: {}", header.as_str());
            }
        }

        // Each half is gated on its own feature. Written as one `if`/`else`
        // under `cfg(feature = "client")`, the `else` disappears along with
        // the `if` in a server-only build and responses stop having their
        // `TE` stripped at all.
        #[cfg(feature = "client")]
        if matches!(kind, MessageKind::Request)
            && headers
                .get(http::header::TE)
                .map_or(false, |te_header| te_header != "trailers")
        {
            warn!("TE headers not set to \"trailers\" are illegal in HTTP/2+ requests");
            headers.remove(http::header::TE);
        }

        #[cfg(feature = "server")]
        if matches!(kind, MessageKind::Response) && headers.remove(http::header::TE).is_some() {
            warn!("TE headers illegal in HTTP/2+ responses");
        }

        #[cfg(not(any(feature = "client", feature = "server")))]
        let _ = kind;

        if let Some(header) = headers.remove(CONNECTION) {
            warn!(
                "Connection header illegal in HTTP/2+: {}",
                CONNECTION.as_str()
            );
            // A `Connection` header may have a comma-separated list of names of other headers that
            // are meant for only this specific connection.
            //
            // Iterate these names and remove them as headers. Connection-specific headers are
            // forbidden in HTTP/2 and HTTP/3, as that information has been moved into frame types
            // of the respective protocol.
            if let Ok(header_contents) = header.to_str() {
                for name in header_contents.split(',') {
                    let name = name.trim();
                    headers.remove(name);
                }
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn headers(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
            let mut headers = HeaderMap::new();
            for (name, value) in pairs {
                headers.append(
                    HeaderName::from_static(name),
                    http::HeaderValue::from_static(value),
                );
            }
            headers
        }

        #[test]
        fn strips_the_connection_headers() {
            let mut h = headers(&[
                ("keep-alive", "timeout=5"),
                ("proxy-connection", "keep-alive"),
                ("transfer-encoding", "chunked"),
                ("upgrade", "websocket"),
                ("connection", "x-hop"),
                ("x-hop", "gone"),
                ("x-keep", "kept"),
            ]);

            #[cfg(feature = "client")]
            strip_connection_headers(&mut h, MessageKind::Request);
            #[cfg(all(feature = "server", not(feature = "client")))]
            strip_connection_headers(&mut h, MessageKind::Response);

            assert_eq!(h.len(), 1);
            assert_eq!(h["x-keep"], "kept");
        }

        #[cfg(feature = "client")]
        #[test]
        fn a_request_keeps_te_trailers_but_nothing_else() {
            let mut h = headers(&[("te", "trailers")]);
            strip_connection_headers(&mut h, MessageKind::Request);
            assert_eq!(h["te"], "trailers");

            let mut h = headers(&[("te", "gzip")]);
            strip_connection_headers(&mut h, MessageKind::Request);
            assert!(!h.contains_key("te"));
        }

        /// Gated on `server` alone: this used to ride along on the `client`
        /// feature, so a server-only build never ran it.
        #[cfg(feature = "server")]
        #[test]
        fn a_response_never_keeps_te() {
            for value in ["trailers", "gzip"] {
                let mut h = HeaderMap::new();
                h.append(http::header::TE, http::HeaderValue::from_static(value));
                strip_connection_headers(&mut h, MessageKind::Response);
                assert!(!h.contains_key("te"), "TE: {value} survived a response");
            }
        }
    }
}

/// An Incoming Message head. Includes request/status line, and headers.
#[cfg(feature = "http1")]
#[derive(Debug, Default)]
pub(crate) struct MessageHead<S> {
    /// HTTP version of the message.
    pub(crate) version: http::Version,
    /// Subject (request line or status line) of Incoming message.
    pub(crate) subject: S,
    /// Headers of the Incoming message.
    pub(crate) headers: http::HeaderMap,
    /// Extensions.
    extensions: http::Extensions,
}

/// An incoming request message.
#[cfg(feature = "http1")]
pub(crate) type RequestHead = MessageHead<RequestLine>;

#[derive(Debug, Default, PartialEq)]
#[cfg(feature = "http1")]
pub(crate) struct RequestLine(pub(crate) http::Method, pub(crate) http::Uri);

/// An incoming response message.
#[cfg(all(feature = "http1", feature = "client"))]
pub(crate) type ResponseHead = MessageHead<http::StatusCode>;

#[derive(Debug)]
#[cfg(feature = "http1")]
pub(crate) enum BodyLength {
    /// `Content-Length`.
    Known(u64),
    /// `Transfer-Encoding: chunked` (if h1).
    Unknown,
}

/// Status of when a Dispatcher future completes.
#[cfg(any(feature = "http1", feature = "http2"))]
pub(crate) enum Dispatched {
    /// Dispatcher completely shutdown connection.
    Shutdown,
    /// Dispatcher has pending upgrade, and so did not shutdown.
    #[cfg(feature = "http1")]
    Upgrade(crate::upgrade::Pending),
}

#[cfg(all(feature = "client", feature = "http1"))]
impl MessageHead<http::StatusCode> {
    fn into_response<B>(self, body: B) -> http::Response<B> {
        let mut res = http::Response::new(body);
        *res.status_mut() = self.subject;
        *res.headers_mut() = self.headers;
        *res.version_mut() = self.version;
        *res.extensions_mut() = self.extensions;
        res
    }
}
