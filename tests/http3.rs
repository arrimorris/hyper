//! End-to-end HTTP/3 tests against a real QUIC stack (quinn).
//!
//! Beyond the happy path, these deliberately abuse the connection in the ways a
//! mobile client actually gets abused: the client's network changes underneath
//! an in-flight request, and every packet in both directions is dropped for
//! long enough that a naive stack would give up.
//!
//! Run with:
//!
//! ```notrust
//! RUSTFLAGS="--cfg hyper_unstable_quic" \
//!     cargo test --features http3,client,server --test http3
//! ```

#![deny(rust_2018_idioms)]

use std::convert::Infallible;
use std::error::Error as StdError;
use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Once};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Empty, Full, StreamBody};
use hyper::body::{Body, Frame, Incoming};
use hyper::client::conn::http3 as client_http3;
use hyper::server::conn::http3 as server_http3;
use hyper::service::service_fn;
use hyper::{HeaderMap, Request, Response, StatusCode, Version};
use quinn::{ClientConfig, Endpoint, IdleTimeout, ServerConfig, TransportConfig};
use tokio::sync::oneshot;

#[path = "support/quic.rs"]
mod quic;

type BoxError = Box<dyn StdError + Send + Sync>;
type TestBody = BoxBody<Bytes, Infallible>;

const ALPN: &[u8] = b"h3";

/// How long a connection may go without receiving a single packet before QUIC
/// declares it dead.
///
/// This is the number that decides whether a client survives a tunnel, and it
/// is the *transport's* number, not hyper's — hyper never times a connection
/// out on its own. It must be longer than the worst outage you intend to
/// survive: a five-minute blackout against a five-minute idle timeout is a dead
/// connection, not a surviving one (see `blackout_longer_than_idle_timeout`).
///
/// Note that keep-alives do not help here. During a real blackout the
/// keep-alive packets are dropped along with everything else.
const IDLE_TIMEOUT: Duration = Duration::from_secs(600);

// ===== harness =====

#[derive(Clone)]
struct TokioExecutor;

impl<F> hyper::rt::Executor<F> for TokioExecutor
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    fn execute(&self, fut: F) {
        tokio::spawn(fut);
    }
}

struct Tls {
    server: ServerConfig,
    client: ClientConfig,
}

fn tls() -> Tls {
    tls_with_idle_timeout(IDLE_TIMEOUT)
}

fn tls_with_idle_timeout(idle: Duration) -> Tls {
    static INSTALL: Once = Once::new();
    INSTALL.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });

    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let cert_der = cert.cert.der().clone();
    let key_der = rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());

    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key_der.into())
        .unwrap();
    server_crypto.alpn_protocols = vec![ALPN.to_vec()];
    let mut server = ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto).unwrap(),
    ));
    server.transport_config(Arc::new(transport(idle)));
    // Explicit, because the whole point of several tests below is that the
    // client may change address without the connection noticing.
    server.migration(true);

    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert_der).unwrap();
    let mut client_crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_crypto.alpn_protocols = vec![ALPN.to_vec()];
    let mut client = ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto).unwrap(),
    ));
    client.transport_config(Arc::new(transport(idle)));

    Tls { server, client }
}

fn transport(idle: Duration) -> TransportConfig {
    let mut transport = TransportConfig::default();
    transport.max_idle_timeout(Some(IdleTimeout::try_from(idle).unwrap()));
    // Keep-alives are what stop an idle-but-alive connection from being
    // reaped, and they resume on their own once packets flow again.
    transport.keep_alive_interval(Some(Duration::from_secs(2)));
    transport
}

/// Spawn an HTTP/3 server, returning the address it is listening on.
fn spawn_server<S, B>(tls: &Tls, service: S) -> SocketAddr
where
    S: hyper::service::HttpService<Incoming, ResBody = B> + Clone + Send + 'static,
    S::Future: Send,
    S::Error: Into<BoxError>,
    B: Body<Data = Bytes> + Send + 'static,
    B::Error: Into<BoxError>,
{
    let endpoint =
        Endpoint::server(tls.server.clone(), (Ipv4Addr::LOCALHOST, 0).into()).expect("endpoint");
    let addr = endpoint.local_addr().expect("local_addr");

    tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            let service = service.clone();
            tokio::spawn(async move {
                let conn = match incoming.await {
                    Ok(conn) => conn,
                    Err(_) => return,
                };
                let _ = server_http3::Builder::new(TokioExecutor)
                    .serve_connection(quic::Connection::new(conn), service)
                    .await;
            });
        }
    });

    addr
}

/// Connect a client, returning its endpoint (so tests can rebind it) and the
/// request sender.
async fn connect(tls: &Tls, addr: SocketAddr) -> (Endpoint, client_http3::SendRequest<TestBody>) {
    let mut endpoint = Endpoint::client((Ipv4Addr::LOCALHOST, 0).into()).expect("client endpoint");
    endpoint.set_default_client_config(tls.client.clone());

    let conn = endpoint
        .connect(addr, "localhost")
        .expect("connect")
        .await
        .expect("quic handshake");

    let (send_request, connection) =
        client_http3::handshake(TokioExecutor, quic::Connection::new(conn))
            .await
            .expect("http3 handshake");

    tokio::spawn(async move {
        let _ = connection.await;
    });

    (endpoint, send_request)
}

fn full(body: &'static str) -> TestBody {
    Full::new(Bytes::from_static(body.as_bytes())).boxed()
}

fn empty() -> TestBody {
    Empty::<Bytes>::new().boxed()
}

fn get(path: &str) -> Request<TestBody> {
    Request::builder()
        .uri(format!("https://localhost{path}"))
        .body(empty())
        .unwrap()
}

// ===== the basics =====

#[tokio::test]
async fn hello_world() {
    let tls = tls();
    let addr = spawn_server(
        &tls,
        service_fn(|req: Request<Incoming>| async move {
            assert_eq!(req.version(), Version::HTTP_3);
            assert_eq!(req.uri().path(), "/hello");
            Ok::<_, Infallible>(Response::new(full("Hello, HTTP/3!")))
        }),
    );

    let (_endpoint, mut send_request) = connect(&tls, addr).await;

    let res = send_request.send_request(get("/hello")).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(res.version(), Version::HTTP_3);
    // Set by the server by default, like HTTP/1 and HTTP/2.
    assert!(res.headers().contains_key("date"));

    let body = res.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(body, "Hello, HTTP/3!");
}

#[tokio::test]
async fn echoes_request_body_and_trailers() {
    let tls = tls();
    let addr = spawn_server(
        &tls,
        service_fn(|req: Request<Incoming>| async move {
            let collected = req.into_body().collect().await.unwrap();
            let trailers = collected.trailers().cloned();
            let data = collected.to_bytes();

            let mut echoed = HeaderMap::new();
            echoed.insert(
                "x-echoed-trailer",
                trailers
                    .and_then(|t| t.get("x-checksum").cloned())
                    .unwrap_or_else(|| "missing".parse().unwrap()),
            );

            let frames = futures_util::stream::iter(vec![
                Ok::<_, Infallible>(Frame::data(data)),
                Ok(Frame::trailers(echoed)),
            ]);
            Ok::<_, Infallible>(Response::new(StreamBody::new(frames).boxed()))
        }),
    );

    let (_endpoint, mut send_request) = connect(&tls, addr).await;

    let mut trailers = HeaderMap::new();
    trailers.insert("x-checksum", "abc123".parse().unwrap());
    let body = StreamBody::new(futures_util::stream::iter(vec![
        Ok::<_, Infallible>(Frame::data(Bytes::from_static(b"one "))),
        Ok(Frame::data(Bytes::from_static(b"two "))),
        Ok(Frame::data(Bytes::from_static(b"three"))),
        Ok(Frame::trailers(trailers)),
    ]))
    .boxed();

    let req = Request::builder()
        .method("POST")
        .uri("https://localhost/echo")
        .body(body)
        .unwrap();

    let res = send_request.send_request(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let collected = res.into_body().collect().await.unwrap();
    let echoed_trailer = collected
        .trailers()
        .and_then(|t| t.get("x-echoed-trailer"))
        .cloned();
    assert_eq!(collected.to_bytes(), "one two three");
    assert_eq!(echoed_trailer.unwrap(), "abc123");
}

/// The whole reason HTTP/3 exists: one slow request must not hold up another on
/// the same connection. The first request cannot finish until the second one
/// has, so this deadlocks if the two share a queue.
#[tokio::test]
async fn requests_do_not_block_each_other() {
    let tls = tls();
    let (release_tx, release_rx) = oneshot::channel::<()>();
    let release = Arc::new(tokio::sync::Mutex::new(Some(release_tx)));
    let gate = Arc::new(tokio::sync::Mutex::new(Some(release_rx)));

    let addr = spawn_server(
        &tls,
        service_fn(move |req: Request<Incoming>| {
            let release = Arc::clone(&release);
            let gate = Arc::clone(&gate);
            async move {
                if req.uri().path() == "/slow" {
                    // Waits for /fast to complete.
                    let rx = gate.lock().await.take().expect("one /slow request");
                    let _ = rx.await;
                    Ok::<_, Infallible>(Response::new(full("slow")))
                } else {
                    if let Some(tx) = release.lock().await.take() {
                        let _ = tx.send(());
                    }
                    Ok(Response::new(full("fast")))
                }
            }
        }),
    );

    let (_endpoint, mut send_request) = connect(&tls, addr).await;
    let mut second = send_request.clone();

    let slow = tokio::spawn(async move { send_request.send_request(get("/slow")).await });
    // Give /slow a head start so it is definitely in flight first.
    tokio::time::sleep(Duration::from_millis(50)).await;
    let fast = second.send_request(get("/fast")).await.unwrap();

    assert_eq!(
        fast.into_body().collect().await.unwrap().to_bytes(),
        "fast",
        "the second request must complete while the first is still blocked"
    );

    let slow = slow.await.unwrap().unwrap();
    assert_eq!(slow.into_body().collect().await.unwrap().to_bytes(), "slow");
}

/// A server that rejects an upload without reading it should be heard
/// immediately, not after the client has finished uploading.
#[tokio::test]
async fn early_response_reaches_client_mid_upload() {
    let tls = tls();
    let addr = spawn_server(
        &tls,
        service_fn(|_req: Request<Incoming>| async move {
            // Note: the request body is dropped unread, which sends
            // STOP_SENDING to the peer.
            Ok::<_, Infallible>(
                Response::builder()
                    .status(StatusCode::PAYLOAD_TOO_LARGE)
                    .body(full("too big"))
                    .unwrap(),
            )
        }),
    );

    let (_endpoint, mut send_request) = connect(&tls, addr).await;

    // A body that would take ~10s to finish uploading if anyone waited for it.
    let chunks = futures_util::stream::unfold(0usize, |n| async move {
        if n >= 100 {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        Some((
            Ok::<_, Infallible>(Frame::data(Bytes::from(vec![b'x'; 1024]))),
            n + 1,
        ))
    });

    let req = Request::builder()
        .method("POST")
        .uri("https://localhost/upload")
        .body(StreamBody::new(chunks).boxed())
        .unwrap();

    let res = tokio::time::timeout(Duration::from_secs(5), send_request.send_request(req))
        .await
        .expect("response must arrive without waiting for the upload to finish")
        .unwrap();

    assert_eq!(res.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(
        res.into_body().collect().await.unwrap().to_bytes(),
        "too big"
    );
}

#[tokio::test]
async fn graceful_shutdown_finishes_inflight_request() {
    let tls = tls();
    let (started_tx, started_rx) = oneshot::channel::<()>();
    let (release_tx, release_rx) = oneshot::channel::<()>();
    let started = Arc::new(tokio::sync::Mutex::new(Some(started_tx)));
    let release = Arc::new(tokio::sync::Mutex::new(Some(release_rx)));

    let endpoint =
        Endpoint::server(tls.server.clone(), (Ipv4Addr::LOCALHOST, 0).into()).expect("endpoint");
    let addr = endpoint.local_addr().unwrap();

    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        let incoming = endpoint.accept().await.expect("a connection");
        let conn = incoming.await.expect("quic handshake");

        let service = service_fn(move |_req: Request<Incoming>| {
            let started = Arc::clone(&started);
            let release = Arc::clone(&release);
            async move {
                if let Some(tx) = started.lock().await.take() {
                    let _ = tx.send(());
                }
                if let Some(rx) = release.lock().await.take() {
                    let _ = rx.await;
                }
                Ok::<_, Infallible>(Response::new(full("finished anyway")))
            }
        });

        let conn = server_http3::Builder::new(TokioExecutor)
            .serve_connection(quic::Connection::new(conn), service);
        tokio::pin!(conn);

        tokio::select! {
            res = conn.as_mut() => return res,
            _ = shutdown_rx => {}
        }

        conn.as_mut().graceful_shutdown();
        conn.await
    });

    let (_endpoint, mut send_request) = connect(&tls, addr).await;
    let request = tokio::spawn(async move { send_request.send_request(get("/slow")).await });

    // Ask for shutdown only once the request is actually being handled.
    started_rx.await.unwrap();
    shutdown_tx.send(()).unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    release_tx.send(()).unwrap();

    let res = request.await.unwrap().unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        res.into_body().collect().await.unwrap().to_bytes(),
        "finished anyway",
        "a request accepted before GOAWAY must still be answered"
    );

    tokio::time::timeout(Duration::from_secs(10), server)
        .await
        .expect("the connection future must resolve after shutdown")
        .unwrap()
        .expect("graceful shutdown is not an error");
}

// ===== being mean to the connection =====

/// Wi-Fi to cellular, mid-request.
///
/// The client's UDP socket is replaced with a new one on a different port while
/// a request is in flight. Under TCP the 4-tuple would be gone and the request
/// lost. Under QUIC the Connection ID still identifies the session, so the same
/// request finishes on the new path.
#[tokio::test]
async fn survives_network_migration_mid_request() {
    let tls = tls();
    let (started_tx, started_rx) = oneshot::channel::<()>();
    let (release_tx, release_rx) = oneshot::channel::<()>();
    let started = Arc::new(tokio::sync::Mutex::new(Some(started_tx)));
    let release = Arc::new(tokio::sync::Mutex::new(Some(release_rx)));

    let addr = spawn_server(
        &tls,
        service_fn(move |_req: Request<Incoming>| {
            let started = Arc::clone(&started);
            let release = Arc::clone(&release);
            async move {
                if let Some(tx) = started.lock().await.take() {
                    let _ = tx.send(());
                }
                if let Some(rx) = release.lock().await.take() {
                    let _ = rx.await;
                }
                Ok::<_, Infallible>(Response::new(full("survived the handover")))
            }
        }),
    );

    let (endpoint, mut send_request) = connect(&tls, addr).await;
    let before = endpoint.local_addr().unwrap();

    let request = tokio::spawn(async move { send_request.send_request(get("/epro")).await });

    // The request is on the wire and the server is holding it open.
    started_rx.await.unwrap();

    // The device changes network.
    let new_socket = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    endpoint.rebind(new_socket).expect("rebind");
    let after = endpoint.local_addr().unwrap();
    assert_ne!(before, after, "the client must actually have moved");

    release_tx.send(()).unwrap();

    let res = tokio::time::timeout(Duration::from_secs(20), request)
        .await
        .expect("the response must survive the address change")
        .unwrap()
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        res.into_body().collect().await.unwrap().to_bytes(),
        "survived the handover"
    );

    // And the connection is still usable afterwards, from the new address.
    let (_endpoint2, mut again) = connect(&tls, addr).await;
    let res = again.send_request(get("/again")).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
}

/// Total loss of signal, mid-request.
///
/// Every packet in both directions is dropped for `blackout`, then the network
/// comes back. Because the idle timeout is five minutes and hyper adds no
/// timeout of its own, the in-flight request simply resumes.
async fn blackout_case(blackout: Duration, idle_timeout: Duration) -> crate::BlackoutOutcome {
    let tls = tls_with_idle_timeout(idle_timeout);
    let addr = spawn_server(
        &tls,
        service_fn(|_req: Request<Incoming>| async move {
            Ok::<_, Infallible>(Response::new(full("still here")))
        }),
    );

    let dropping = Arc::new(AtomicBool::new(false));
    let relay_addr = spawn_relay(addr, Arc::clone(&dropping)).await;

    let (_endpoint, mut send_request) = connect(&tls, relay_addr).await;

    // Warm the connection up so the handshake is definitely behind us.
    let res = send_request.send_request(get("/warmup")).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let _ = res.into_body().collect().await.unwrap();

    // Into the tunnel.
    dropping.store(true, Ordering::SeqCst);
    let request = tokio::spawn(async move { send_request.send_request(get("/in-the-dark")).await });
    tokio::time::sleep(blackout).await;

    // Out of the tunnel.
    dropping.store(false, Ordering::SeqCst);

    // Generous: after a long outage QUIC's probe timeout has backed off, so
    // recovery is not instant. What matters is that it happens at all.
    let settled = tokio::time::timeout(Duration::from_secs(120), request)
        .await
        .expect("the request must resolve one way or the other, not hang forever")
        .unwrap();

    match settled {
        Ok(res) => {
            assert_eq!(res.status(), StatusCode::OK);
            assert_eq!(
                res.into_body().collect().await.unwrap().to_bytes(),
                "still here"
            );
            BlackoutOutcome::Survived
        }
        Err(err) => BlackoutOutcome::Died(err),
    }
}

enum BlackoutOutcome {
    Survived,
    Died(hyper::Error),
}

#[tokio::test]
async fn survives_short_blackout_mid_request() {
    match blackout_case(Duration::from_secs(3), IDLE_TIMEOUT).await {
        BlackoutOutcome::Survived => {}
        BlackoutOutcome::Died(err) => panic!("connection died during a 3s blackout: {err}"),
    }
}

/// The real thing: five minutes with no signal at all, against an idle timeout
/// that is longer than the outage.
///
/// Ignored by default because it takes five minutes; run it with
/// `cargo test --test http3 -- --ignored --nocapture`.
#[tokio::test]
#[ignore = "takes over five minutes by design"]
async fn survives_five_minute_blackout_mid_request() {
    match blackout_case(Duration::from_secs(300), Duration::from_secs(600)).await {
        BlackoutOutcome::Survived => {}
        BlackoutOutcome::Died(err) => panic!("connection died during a 5m blackout: {err}"),
    }
}

/// The other side of the same coin, and the reason the idle timeout has to be
/// chosen deliberately: an outage *longer* than the idle timeout does end the
/// connection. What matters is that it ends — promptly, with an error the
/// caller can act on by reconnecting — rather than hanging forever.
#[tokio::test]
async fn blackout_longer_than_idle_timeout_fails_cleanly() {
    match blackout_case(Duration::from_secs(10), Duration::from_secs(2)).await {
        BlackoutOutcome::Survived => {
            panic!("a 10s blackout must not survive a 2s idle timeout")
        }
        BlackoutOutcome::Died(err) => {
            assert!(!err.is_parse(), "expected a transport failure, got {err:?}");
        }
    }
}

/// A UDP relay sitting between client and server that can be told to drop
/// everything, simulating a total loss of signal rather than a clean
/// disconnect. Returns the address clients should talk to.
async fn spawn_relay(server: SocketAddr, dropping: Arc<AtomicBool>) -> SocketAddr {
    let to_client = Arc::new(
        tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap(),
    );
    let to_server = Arc::new(
        tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap(),
    );
    let relay_addr = to_client.local_addr().unwrap();

    // Learned from the first packet the client sends.
    let client_addr = Arc::new(std::sync::Mutex::new(None::<SocketAddr>));

    {
        let (to_client, to_server) = (Arc::clone(&to_client), Arc::clone(&to_server));
        let dropping = Arc::clone(&dropping);
        let client_addr = Arc::clone(&client_addr);
        tokio::spawn(async move {
            let mut buf = vec![0u8; 64 * 1024];
            loop {
                let (n, from) = match to_client.recv_from(&mut buf).await {
                    Ok(v) => v,
                    Err(_) => return,
                };
                *client_addr.lock().unwrap() = Some(from);
                if dropping.load(Ordering::SeqCst) {
                    continue;
                }
                let _ = to_server.send_to(&buf[..n], server).await;
            }
        });
    }

    {
        let (to_client, to_server) = (Arc::clone(&to_client), Arc::clone(&to_server));
        tokio::spawn(async move {
            let mut buf = vec![0u8; 64 * 1024];
            loop {
                let (n, _from) = match to_server.recv_from(&mut buf).await {
                    Ok(v) => v,
                    Err(_) => return,
                };
                if dropping.load(Ordering::SeqCst) {
                    continue;
                }
                let dst = *client_addr.lock().unwrap();
                if let Some(dst) = dst {
                    let _ = to_client.send_to(&buf[..n], dst).await;
                }
            }
        });
    }

    relay_addr
}

/// Many requests at once, so the per-stream tasks and the shared connection are
/// exercised together rather than one at a time.
#[tokio::test]
async fn many_concurrent_requests() {
    let tls = tls();
    let served = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&served);

    let addr = spawn_server(
        &tls,
        service_fn(move |req: Request<Incoming>| {
            let counter = Arc::clone(&counter);
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
                let path = req.uri().path().to_owned();
                Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(path)).boxed()))
            }
        }),
    );

    let (_endpoint, send_request) = connect(&tls, addr).await;

    let mut handles = Vec::new();
    for i in 0..50 {
        let mut sender = send_request.clone();
        handles.push(tokio::spawn(async move {
            let res = sender
                .send_request(get(&format!("/req/{i}")))
                .await
                .unwrap();
            assert_eq!(res.status(), StatusCode::OK);
            let body = res.into_body().collect().await.unwrap().to_bytes();
            assert_eq!(body, format!("/req/{i}"));
        }));
    }

    for handle in handles {
        handle.await.unwrap();
    }
    assert_eq!(served.load(Ordering::SeqCst), 50);
}
