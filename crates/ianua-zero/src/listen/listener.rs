//! The accept loop every HTTP and HTTPS port runs.
//!
//! Each accepted connection takes a permit or is closed at once. Its
//! opening is read within a timeout (the PROXY header from a trusted
//! ingress, or a check that no one else sent one), TLS is ended when the
//! port is HTTPS, and the connection is handed to the [`Handler`] with the
//! facts learned on the way. At a stop the loop takes no new connections
//! and waits for those it holds to finish their requests; the process's
//! grace period bounds that wait.

use std::io;
use std::net::SocketAddr;
use std::pin::pin;
use std::sync::Arc;
use std::time::Duration;

use ianua_boot::shutdown::Shutdown;
use ianua_domain::domains::proxy::request::forwarded::ClientScheme;
use ianua_domain::types::Fact;
use tokio::net::{TcpListener, TcpStream};
use tokio_util::task::TaskTracker;

use super::connection::{ConnectionFacts, ConnectionParts};
use super::handler::{ConnectionLifetime, Handler, HttpLimits, serve};
use super::internal_tls::InternalTls;
use super::permits::{ConnectionPermit, ConnectionPermits};
use super::proxy_header::{self, Opened, ProxyProtocol};
use super::tls::{Terminated, TlsTerminator};

/// How long to wait before accepting again after accepting failed, as when
/// the process is out of file descriptors.
const ACCEPT_PAUSE: Duration = Duration::from_millis(50);

/// Whether a port ends TLS.
pub(crate) enum Transport {
    /// Plain HTTP.
    Plain,
    /// HTTPS, ended by this terminator.
    Tls(Arc<TlsTerminator>),
    /// TLS with the platform's own certificate, on a listener inside the
    /// deployment's network; a client certificate is required where its
    /// configuration asks one.
    Internal(Arc<InternalTls>),
}

/// The limits a port serves connections under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ListenLimits {
    /// How long the opening may take: the PROXY header from the ingress,
    /// or the first bytes from anyone else. The TLS handshake has its own
    /// timeout on the [`TlsTerminator`].
    pub opening: Duration,
    /// The limits of the HTTP served on each connection.
    pub http: HttpLimits,
}

/// One port, and everything its connections are served with.
pub(crate) struct Listener<H> {
    /// The bound socket.
    pub socket: TcpListener,
    /// Whether the port ends TLS.
    pub transport: Transport,
    /// Whether the port reads PROXY protocol headers, and from whom.
    pub proxy_protocol: ProxyProtocol,
    /// The permits its connections are served under.
    pub permits: ConnectionPermits,
    /// The limits its connections are served under.
    pub limits: ListenLimits,
    /// What answers each request.
    pub handler: H,
}

/// What every connection on a port is served with.
struct Port<H> {
    transport: Transport,
    proxy_protocol: ProxyProtocol,
    limits: ListenLimits,
    handler: H,
    shutdown: Shutdown,
}

/// The bound listener and permit pool used by its accept loop.
struct Acceptor<H> {
    socket: TcpListener,
    permits: ConnectionPermits,
    port: Arc<Port<H>>,
}

impl<H: Handler> Listener<H> {
    /// Accepts connections until `shutdown` is stopping, then waits for
    /// those it holds to finish. Run it under [`Shutdown::spawn`], whose
    /// grace period bounds the wait.
    pub(crate) async fn run(self, shutdown: Shutdown) {
        if let Ok(address) = self.socket.local_addr() {
            tracing::info!(%address, "listening");
        }
        Acceptor {
            socket: self.socket,
            permits: self.permits,
            port: Arc::new(Port {
                transport: self.transport,
                proxy_protocol: self.proxy_protocol,
                limits: self.limits,
                handler: self.handler,
                shutdown,
            }),
        }
        .run()
        .await;
    }
}

impl<H: Handler> Acceptor<H> {
    /// Stops accepting before draining all admitted connections.
    async fn run(self) {
        let connections = TaskTracker::new();
        let mut stopping = pin!(self.port.shutdown.stopping());
        loop {
            let accepted = tokio::select! {
                biased;
                () = &mut stopping => break,
                accepted = self.socket.accept() => accepted,
            };
            let Some((stream, peer, permit)) = admitted(accepted, &self.permits).await else {
                continue;
            };
            let port = Arc::clone(&self.port);
            connections.spawn(async move {
                port.connection(stream, peer).await;
                drop(permit);
            });
        }
        drop(self.socket);
        connections.close();
        connections.wait().await;
    }
}

/// The accepted connection and its permit, or `None` when accepting failed
/// or every permit is taken; the connection is then closed.
async fn admitted(
    accepted: io::Result<(TcpStream, SocketAddr)>,
    permits: &ConnectionPermits,
) -> Option<(TcpStream, SocketAddr, ConnectionPermit)> {
    let (stream, peer) = match accepted {
        Ok(accepted) => accepted,
        Err(error) => {
            tracing::warn!(%error, "accepting a connection failed");
            tokio::time::sleep(ACCEPT_PAUSE).await;
            return None;
        }
    };
    let Some(permit) = permits.try_take() else {
        tracing::debug!(%peer, "connection closed: every permit is taken");
        return None;
    };
    Some((stream, peer, permit))
}

impl<H: Handler> Port<H> {
    async fn connection(&self, stream: TcpStream, peer: SocketAddr) {
        if let Err(error) = stream.set_nodelay(true) {
            tracing::debug!(%peer, %error, "TCP_NODELAY could not be set");
        }
        let opened = proxy_header::open(stream, peer, &self.proxy_protocol, self.limits.opening);
        let opened = match opened.await {
            Ok(opened) => opened,
            Err(error) => {
                tracing::debug!(%peer, %error, "connection refused as it opened");
                return;
            }
        };
        match &self.transport {
            Transport::Plain => self.plain(opened, peer).await,
            Transport::Tls(terminator) => self.tls(terminator, opened, peer).await,
            Transport::Internal(tls) => self.internal(tls, opened, peer).await,
        }
    }

    async fn internal(&self, tls: &InternalTls, opened: Opened<TcpStream>, peer: SocketAddr) {
        let Opened { client, stream } = opened;
        let stream = match tls.accept(stream).await {
            Ok(stream) => stream,
            Err(error) => {
                tracing::debug!(%client, %error, "TLS handshake refused");
                return;
            }
        };
        self.hand_over(stream, ConnectionFacts::internal(client, peer))
            .await;
    }

    async fn plain(&self, opened: Opened<TcpStream>, peer: SocketAddr) {
        let facts = ConnectionFacts::plain(opened.client, peer);
        self.hand_over(opened.stream, facts).await;
    }

    async fn tls(&self, terminator: &TlsTerminator, opened: Opened<TcpStream>, peer: SocketAddr) {
        let Opened { client, stream } = opened;
        let terminated = match terminator.terminate(stream).await {
            Ok(terminated) => terminated,
            Err(error) => {
                tracing::debug!(%client, %error, "TLS handshake refused");
                return;
            }
        };
        let Terminated {
            stream,
            server_name,
            client_certificate,
            ja4,
        } = terminated;
        let facts = ConnectionFacts::new(ConnectionParts {
            client,
            peer,
            scheme: ClientScheme::Https,
            server_name: Fact::Known(server_name),
            client_certificate,
            ja4: Fact::Known(ja4),
        });
        self.hand_over(stream, facts).await;
    }

    async fn hand_over<I>(&self, io: I, facts: ConnectionFacts)
    where
        I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        serve(
            io,
            self.handler.clone(),
            facts,
            ConnectionLifetime {
                limits: &self.limits.http,
                stopping: self.shutdown.stopping(),
            },
        )
        .await;
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::future::Future;
    use std::num::NonZeroUsize;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use http_body_util::{Empty, Full};
    use hyper::body::{Bytes, Incoming};
    use hyper::client::conn::http1::SendRequest;
    use hyper::{Request, Response, StatusCode};
    use hyper_util::rt::TokioIo;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;
    use crate::listen::tls::fixtures::{Names, terminator};

    const PATIENT: Duration = Duration::from_secs(5);
    const SOON: Duration = Duration::from_secs(2);

    /// Answers `ok` after `delay`, counting the requests it answered.
    #[derive(Clone, Default)]
    struct Answering {
        calls: Arc<AtomicUsize>,
        delay: Duration,
    }

    impl Handler for Answering {
        type Body = Full<Bytes>;

        fn handle(
            &self,
            _request: Request<Incoming>,
            _connection: Arc<ConnectionFacts>,
        ) -> impl Future<Output = Response<Self::Body>> + Send {
            let calls = Arc::clone(&self.calls);
            let delay = self.delay;
            async move {
                calls.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(delay).await;
                Response::new(Full::new(Bytes::from_static(b"ok")))
            }
        }
    }

    fn limits() -> ListenLimits {
        ListenLimits {
            opening: PATIENT,
            http: HttpLimits {
                idle: PATIENT,
                header_read: PATIENT,
                max_headers: 64,
                max_streams: 16,
            },
        }
    }

    fn permits(limit: usize) -> ConnectionPermits {
        ConnectionPermits::new(NonZeroUsize::new(limit).unwrap())
    }

    struct Running {
        address: SocketAddr,
        shutdown: Shutdown,
        finished: tokio::task::JoinHandle<()>,
    }

    async fn start(
        transport: Transport,
        permits: ConnectionPermits,
        handler: Answering,
    ) -> Running {
        let socket = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        let shutdown = Shutdown::new(SOON);
        let listener = Listener {
            socket,
            transport,
            proxy_protocol: ProxyProtocol::Off,
            permits,
            limits: limits(),
            handler,
        };
        let finished = tokio::spawn(listener.run(shutdown.clone()));
        Running {
            address,
            shutdown,
            finished,
        }
    }

    async fn client(address: SocketAddr) -> SendRequest<Empty<Bytes>> {
        let stream = TcpStream::connect(address).await.unwrap();
        let (sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .unwrap();
        tokio::spawn(connection);
        sender
    }

    async fn status_of(sender: &mut SendRequest<Empty<Bytes>>) -> StatusCode {
        let request = Request::builder()
            .uri("/")
            .header(hyper::header::HOST, "app.acme.test")
            .body(Empty::new())
            .unwrap();
        sender.send_request(request).await.unwrap().status()
    }

    /// Whether the server closes `stream` within `SOON`.
    async fn closed_by_server(mut stream: TcpStream) -> bool {
        let mut buffer = [0_u8; 16];
        matches!(
            tokio::time::timeout(SOON, stream.read(&mut buffer)).await,
            Ok(Ok(0) | Err(_))
        )
    }

    /// A request on a plain port reaches the handler.
    #[tokio::test]
    async fn a_request_reaches_the_handler() {
        let handler = Answering::default();
        let running = start(Transport::Plain, permits(4), handler.clone()).await;

        let status = status_of(&mut client(running.address).await).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(handler.calls.load(Ordering::SeqCst), 1);
    }

    /// With every permit held, the next connection is closed at once; once
    /// a permit is given back, a connection is served again.
    #[tokio::test]
    async fn permits_bound_the_connections_served() {
        let permits = permits(1);
        let running = start(Transport::Plain, permits.clone(), Answering::default()).await;
        let mut first = client(running.address).await;
        assert_eq!(status_of(&mut first).await, StatusCode::OK);

        let second = TcpStream::connect(running.address).await.unwrap();
        let refused = closed_by_server(second).await;
        drop(first);
        let given_back = tokio::time::timeout(SOON, async {
            while permits.available() == 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await;
        let third = status_of(&mut client(running.address).await).await;

        assert!(refused);
        assert!(given_back.is_ok());
        assert_eq!(third, StatusCode::OK);
    }

    /// A client that starts a ClientHello and stops is closed at the
    /// handshake timeout, and nothing reaches the handler.
    #[tokio::test]
    async fn a_stalled_handshake_closes_the_connection() {
        let (_, _, terminator) = terminator(Names(HashMap::new()), Duration::from_millis(100));
        let handler = Answering::default();
        let running = start(
            Transport::Tls(Arc::new(terminator)),
            permits(4),
            handler.clone(),
        )
        .await;

        let mut stream = TcpStream::connect(running.address).await.unwrap();
        stream.write_all(b"\x16\x03\x01").await.unwrap();

        assert!(closed_by_server(stream).await);
        assert_eq!(handler.calls.load(Ordering::SeqCst), 0);
    }

    /// At a stop, a request in flight is answered, new connections are not
    /// taken, and the loop ends once its connections have.
    #[tokio::test]
    async fn a_stop_lets_requests_in_flight_finish() {
        let handler = Answering {
            delay: Duration::from_millis(200),
            ..Answering::default()
        };
        let running = start(Transport::Plain, permits(4), handler).await;
        let mut sender = client(running.address).await;

        let in_flight = tokio::spawn(async move { status_of(&mut sender).await });
        tokio::time::sleep(Duration::from_millis(50)).await;
        running.shutdown.stop();
        let answered = in_flight.await.unwrap();
        let ended = tokio::time::timeout(SOON, running.finished).await;
        let after_the_stop = TcpStream::connect(running.address).await;

        assert_eq!(answered, StatusCode::OK);
        assert!(ended.is_ok());
        assert!(after_the_stop.is_err());
    }
}
