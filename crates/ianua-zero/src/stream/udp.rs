//! A UDP route's port: datagrams, relayed per client.
//!
//! UDP has no connection to accept. One socket receives from every client,
//! so the gateway itself tells conversations apart by remembering, per
//! client address, the backend socket its datagrams go out on. That table
//! is bounded and expiring, because a source address is free to invent: an
//! unbounded map keyed by one hands memory to anyone who can send a packet.
//!
//! A UDP route is always a public port, since the domain lets nothing else
//! be one: no handshake, no identity, so a flow carries nothing that could
//! change the application's answer. The listener therefore asks once, when
//! it opens, and relays only once admitted; a route that changes is bound
//! again and asked again, and one that is disabled is closed.

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use ianua_app::use_cases::routing::stream_routes::StreamConnectionCaller;
use tokio::net::UdpSocket;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use super::admission::Gate;
use super::backend::{self, DialFailure};
use super::route::ServedRoute;

/// The largest datagram relayed. Reading into anything smaller would
/// truncate silently rather than fail.
const MAX_DATAGRAM: usize = 65_535;

/// How often conversations gone quiet are dropped.
const SWEEP_EVERY: Duration = Duration::from_secs(30);

/// How long a refused or undecided listener waits before asking again.
const ADMISSION_RETRY: Duration = Duration::from_secs(10);

/// A bound datagram port and the route it serves.
pub(super) struct UdpPort {
    socket: UdpSocket,
    route: Arc<ServedRoute>,
    flows: usize,
}

impl UdpPort {
    /// Serves `route` on `socket`, tracking at most `flows` clients at once.
    pub(super) fn new(socket: UdpSocket, route: Arc<ServedRoute>, flows: usize) -> Self {
        Self {
            socket,
            route,
            flows: flows.max(1),
        }
    }

    /// Relays until `stop`, then frees the port and says so on `released`.
    pub(super) async fn serve(self, stop: CancellationToken, released: oneshot::Sender<()>) {
        self.relay_until(&stop).await;
        let _ = released.send(());
    }

    /// Relays once admitted, until `stop`. Every conversation, and the
    /// socket, is dropped on return.
    async fn relay_until(self, stop: &CancellationToken) {
        if !admitted(&self.route, stop).await {
            return;
        }
        let mut relay = Relay {
            socket: Arc::new(self.socket),
            flows: Flows::new(self.route.idle_limit(), self.flows),
            route: self.route,
        };
        let mut buffer = vec![0u8; MAX_DATAGRAM];
        let mut sweep = tokio::time::interval(SWEEP_EVERY);
        loop {
            tokio::select! {
                () = stop.cancelled() => return,
                _ = sweep.tick() => relay.flows.expire(Instant::now()),
                received = relay.socket.recv_from(&mut buffer) => {
                    let Ok((len, peer)) = received else { continue };
                    let Some(datagram) = buffer.get(..len) else { continue };
                    relay.forward(peer, datagram).await;
                }
            }
        }
    }
}

/// Whether the application admits the route, asked again every
/// [`ADMISSION_RETRY`] until it does or `stop`.
async fn admitted(route: &ServedRoute, stop: &CancellationToken) -> bool {
    loop {
        let Gate::Closed(shut) = route.gate(None, StreamConnectionCaller::Nobody).await else {
            return true;
        };
        route.record_listener_shut(shut);
        tokio::select! {
            () = stop.cancelled() => return false,
            () = tokio::time::sleep(ADMISSION_RETRY) => {}
        }
    }
}

/// The port's socket, its route and its conversations.
struct Relay {
    socket: Arc<UdpSocket>,
    route: Arc<ServedRoute>,
    flows: Flows,
}

impl Relay {
    /// Sends `datagram` from `peer` on to its backend.
    async fn forward(&mut self, peer: SocketAddr, datagram: &[u8]) {
        let Some(upstream) = self.upstream_for(peer).await else {
            return;
        };
        if let Err(error) = upstream.send(datagram).await {
            tracing::debug!(%error, "a datagram was not relayed");
        }
    }

    /// The backend socket of `peer`'s conversation, opened when it is new
    /// and the route has room.
    async fn upstream_for(&mut self, peer: SocketAddr) -> Option<Arc<UdpSocket>> {
        if let Some(upstream) = self.flows.seen(peer) {
            return Some(upstream);
        }
        self.flows.expire(Instant::now());
        if !self.flows.has_room() {
            self.route.record_at_capacity(peer);
            return None;
        }
        let flow = self.start_flow(peer).await?;
        Some(self.flows.insert(peer, flow))
    }

    /// Opens `peer`'s conversation with the next backend, within the
    /// route's connect limit, and records why when it cannot.
    async fn start_flow(&self, peer: SocketAddr) -> Option<Flow> {
        let opening = open_flow(&self.socket, peer, &self.route);
        let opened = tokio::time::timeout(self.route.connect_limit(), opening)
            .await
            .unwrap_or(Err(DialFailure::TimedOut));
        match opened {
            Ok(flow) => Some(flow),
            Err(failure) => {
                let mut record = self.route.record(peer);
                record.record_caller(StreamConnectionCaller::Nobody);
                record.unreachable(&failure);
                None
            }
        }
    }
}

/// Opens the backend side of `peer`'s conversation and starts relaying its
/// replies back to `peer` through `client_socket`.
///
/// The backend socket is connected, so the kernel drops datagrams from
/// anywhere but the backend: anything else on the network could otherwise
/// answer for it by being quicker.
async fn open_flow(
    client_socket: &Arc<UdpSocket>,
    peer: SocketAddr,
    route: &ServedRoute,
) -> Result<Flow, DialFailure> {
    let authority = route.next_authority().ok_or(DialFailure::NoBackend)?;
    let addresses = backend::permitted_addresses(&authority, route.networks()).await?;
    let local = unspecified_like(addresses.first().ok_or(DialFailure::Forbidden)?);
    let upstream = UdpSocket::bind(local)
        .await
        .map_err(DialFailure::Unreachable)?;
    upstream
        .connect(addresses.as_slice())
        .await
        .map_err(DialFailure::Unreachable)?;
    let upstream = Arc::new(upstream);
    let replies = tokio::spawn(relay_replies(
        Arc::clone(&upstream),
        Arc::clone(client_socket),
        peer,
    ));
    Ok(Flow {
        upstream,
        last_seen: Instant::now(),
        replies,
    })
}

/// Any local address of the same family as `remote`, on any port.
fn unspecified_like(remote: &SocketAddr) -> SocketAddr {
    match remote {
        SocketAddr::V4(_) => SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
        SocketAddr::V6(_) => SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
    }
}

/// Sends every datagram `upstream` receives back to `peer`, until either
/// socket fails or the flow is dropped.
async fn relay_replies(upstream: Arc<UdpSocket>, client_socket: Arc<UdpSocket>, peer: SocketAddr) {
    let mut buffer = vec![0u8; MAX_DATAGRAM];
    while let Ok(len) = upstream.recv(&mut buffer).await {
        let Some(reply) = buffer.get(..len) else {
            return;
        };
        if client_socket.send_to(reply, peer).await.is_err() {
            return;
        }
    }
}

/// One client's conversation.
struct Flow {
    upstream: Arc<UdpSocket>,
    last_seen: Instant,
    replies: JoinHandle<()>,
}

impl Drop for Flow {
    fn drop(&mut self) {
        self.replies.abort();
    }
}

/// A bounded, expiring table of conversations.
struct Flows {
    entries: HashMap<SocketAddr, Flow>,
    idle: Duration,
    bound: usize,
}

impl Flows {
    fn new(idle: Duration, bound: usize) -> Self {
        Self {
            entries: HashMap::new(),
            idle,
            bound,
        }
    }

    /// The backend socket of a conversation already open with `peer`,
    /// noting that it was heard from now.
    fn seen(&mut self, peer: SocketAddr) -> Option<Arc<UdpSocket>> {
        let flow = self.entries.get_mut(&peer)?;
        flow.last_seen = Instant::now();
        Some(Arc::clone(&flow.upstream))
    }

    /// Keeps `flow` as `peer`'s conversation, and hands back its socket.
    fn insert(&mut self, peer: SocketAddr, flow: Flow) -> Arc<UdpSocket> {
        let upstream = Arc::clone(&flow.upstream);
        self.entries.insert(peer, flow);
        upstream
    }

    /// Drops the conversations nothing was heard from within the idle
    /// window.
    fn expire(&mut self, now: Instant) {
        let idle = self.idle;
        self.entries
            .retain(|_, flow| now.duration_since(flow.last_seen) < idle);
    }

    /// Whether one more client can be tracked. Past the bound a new client
    /// is dropped rather than an old one evicted: that loses a packet from
    /// someone who has not spoken yet, not the reply path of someone
    /// mid-conversation.
    fn has_room(&self) -> bool {
        self.entries.len() < self.bound
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flow_at(last_seen: Instant) -> Flow {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("a socket");
        socket.set_nonblocking(true).expect("nonblocking");
        Flow {
            upstream: Arc::new(UdpSocket::from_std(socket).expect("a tokio socket")),
            last_seen,
            replies: tokio::spawn(async {}),
        }
    }

    fn peer(port: u16) -> SocketAddr {
        SocketAddr::from((Ipv4Addr::LOCALHOST, port))
    }

    #[tokio::test]
    async fn a_conversation_gone_quiet_is_dropped() {
        let mut flows = Flows::new(Duration::from_secs(60), 8);
        flows.insert(peer(5000), flow_at(Instant::now()));

        flows.expire(Instant::now() + Duration::from_secs(61));

        assert!(flows.seen(peer(5000)).is_none());
    }

    #[tokio::test]
    async fn a_live_conversation_survives_a_sweep() {
        let mut flows = Flows::new(Duration::from_secs(60), 8);
        flows.insert(peer(5000), flow_at(Instant::now()));

        flows.expire(Instant::now());

        assert!(flows.seen(peer(5000)).is_some());
    }

    #[tokio::test]
    async fn the_table_has_no_room_at_its_bound() {
        let mut flows = Flows::new(Duration::from_secs(60), 2);
        flows.insert(peer(5000), flow_at(Instant::now()));
        flows.insert(peer(5001), flow_at(Instant::now()));

        assert!(!flows.has_room());
    }
}
