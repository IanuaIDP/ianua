//! A TCP route's port: accept, decide, splice. Raw TCP and TLS passed
//! through are carried here; a port that ends TLS, and the signed-in
//! tunnel, hand each connection to their own carrier.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use ianua_app::use_cases::routing::stream_routes::StreamConnectionCaller;
use ianua_domain::types::DomainName;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, oneshot};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use super::admission::Gate;
use super::route::ServedRoute;
use super::splice::{splice, unheld};
use super::{sni, terminated, tunnel};
use crate::listen::StreamHandshake;

/// How long to wait for a passthrough client's first bytes before reading
/// its server name as none.
///
/// A client that connects and says nothing is broken or probing, and must
/// not hold a permit while the gateway waits.
const CLIENT_HELLO_TIMEOUT: Duration = Duration::from_secs(5);

/// How long to pause after a failed accept, so a process out of file
/// descriptors does not spin on the error.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(50);

/// How a port's connections are carried.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Carry {
    /// Raw TCP, or TLS passed through: spliced as they arrive.
    Raw,
    /// TLS ended at the gateway, as this handshake asks.
    Terminated(StreamHandshake),
    /// The signed-in tunnel: TLS ended, then a `CONNECT` with a token.
    Tunnel,
}

/// A bound port and the route it serves.
pub(super) struct TcpPort {
    listener: TcpListener,
    route: Arc<ServedRoute>,
    carry: Carry,
    permits: Arc<Semaphore>,
}

impl TcpPort {
    /// Serves `route` on `listener` as `carry` says, carrying at most
    /// `capacity` connections at once.
    pub(super) fn new(
        listener: TcpListener,
        route: Arc<ServedRoute>,
        carry: Carry,
        capacity: usize,
    ) -> Self {
        Self {
            listener,
            route,
            carry,
            permits: Arc::new(Semaphore::new(capacity.max(1))),
        }
    }

    /// Accepts until `stop`, then frees the port, says so on `released`,
    /// and waits for the connections in flight to end.
    pub(super) async fn serve(self, stop: CancellationToken, released: oneshot::Sender<()>) {
        let mut connections = self.accept_until(&stop).await;
        let _ = released.send(());
        while connections.join_next().await.is_some() {}
    }

    /// Accepts connections until `stop`, and hands back those still in
    /// flight. The listener is dropped on return, which frees the port.
    async fn accept_until(self, stop: &CancellationToken) -> JoinSet<()> {
        let mut connections = JoinSet::new();
        loop {
            let accepted = tokio::select! {
                () = stop.cancelled() => return connections,
                accepted = self.listener.accept() => accepted,
            };
            while connections.try_join_next().is_some() {}
            let Ok((client, peer)) = accepted else {
                tokio::time::sleep(ACCEPT_BACKOFF).await;
                continue;
            };
            let Some(permit) = self.permit_for(peer) else {
                continue;
            };
            let route = Arc::clone(&self.route);
            let carrying = self.carry;
            connections.spawn(async move {
                let _permit = permit;
                match carrying {
                    Carry::Raw => carry(&route, client, peer).await,
                    Carry::Terminated(asked) => {
                        terminated::carry(&route, client, peer, asked).await
                    }
                    Carry::Tunnel => tunnel::carry(&route, client, peer).await,
                }
            });
        }
    }

    /// A permit for one more connection from `peer`, or `None` when the
    /// route carries all it may, which closes the connection.
    fn permit_for(&self, peer: SocketAddr) -> Option<OwnedSemaphorePermit> {
        let permit = Arc::clone(&self.permits).try_acquire_owned().ok();
        if permit.is_none() {
            self.route.record_at_capacity(peer);
        }
        permit
    }
}

/// Decides one connection, then splices it to a backend or closes it.
///
/// A raw or passed-through stream names no one, so the caller is nobody,
/// which only a public port lets in.
async fn carry(route: &ServedRoute, mut client: TcpStream, peer: SocketAddr) {
    let mut record = route.record(peer);
    record.record_server_name(server_name_of(route, &client).await);
    record.record_caller(StreamConnectionCaller::Nobody);
    if let Gate::Closed(shut) = route
        .gate(record.server_name(), StreamConnectionCaller::Nobody)
        .await
    {
        record.report_refusal(shut);
        return;
    }
    let mut backend = match route.dial().await {
        Ok(dialled) => dialled,
        Err(failure) => {
            record.unreachable(&failure);
            return;
        }
    };
    let (outcome, counts) = splice(
        &mut client,
        &mut backend.stream,
        route.idle_limit(),
        unheld(),
    )
    .await;
    record.report_close(&backend.authority, outcome, counts);
}

/// The server name a passthrough client's handshake asks for, peeked so
/// the bytes still reach the backend as sent. `None` on a protocol that
/// carries none, a handshake that did not arrive whole in time, or a name
/// that is no domain name.
async fn server_name_of(route: &ServedRoute, client: &TcpStream) -> Option<DomainName> {
    if !route.protocol().carries_sni() {
        return None;
    }
    let mut buffer = vec![0u8; sni::MAX_CLIENT_HELLO];
    let peeked = tokio::time::timeout(CLIENT_HELLO_TIMEOUT, client.peek(&mut buffer)).await;
    let Ok(Ok(len)) = peeked else {
        return None;
    };
    let hello = buffer
        .get(..len)
        .filter(|b| b.len() >= sni::MIN_CLIENT_HELLO)?;
    sni::server_name(hello).and_then(|name| DomainName::new(name).ok())
}
