//! Where an admitted stream goes: picking a backend, and reaching it.

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use ianua_domain::domains::routing::stream::StreamBackend;
use ianua_domain::shared::security::ssrf::UpstreamNetworks;
use tokio::net::TcpStream;

/// A route's backends, taken in turn by weight.
///
/// Weighted round-robin over a counter rather than a random draw, so a
/// route weighted 1 and 3 sends exactly one stream in four to the first.
pub(super) struct Backends {
    list: Vec<StreamBackend>,
    cursor: AtomicUsize,
}

impl Backends {
    /// Takes `list` in turn, from its first backend.
    pub(super) fn new(list: Vec<StreamBackend>) -> Self {
        Self {
            list,
            cursor: AtomicUsize::new(0),
        }
    }

    /// The next backend, or `None` for a route with none, which the
    /// domain refuses to build.
    pub(super) fn pick(&self) -> Option<&StreamBackend> {
        let total: u64 = self.list.iter().map(|b| u64::from(b.weight())).sum();
        if total == 0 {
            return self.list.first();
        }
        let step = u64::try_from(self.cursor.fetch_add(1, Ordering::Relaxed)).unwrap_or(0);
        let mut point = step % total;
        for backend in &self.list {
            let weight = u64::from(backend.weight());
            if point < weight {
                return Some(backend);
            }
            point -= weight;
        }
        self.list.first()
    }
}

/// Why a backend could not be reached.
#[derive(Debug, thiserror::Error)]
pub(super) enum DialFailure {
    /// The name did not resolve, or the connection was refused.
    #[error("the backend could not be reached")]
    Unreachable(#[source] io::Error),
    /// Everything the name resolves to is an address no stream may reach.
    #[error("the backend resolves only to addresses a stream may not reach")]
    Forbidden,
    /// Resolving and connecting took longer than the route allows.
    #[error("the backend did not answer in time")]
    TimedOut,
    /// The route has no backend, which the domain never builds.
    #[error("the route has no backend")]
    NoBackend,
}

impl DialFailure {
    /// A short, stable reason for the record.
    pub(super) fn as_str(&self) -> &'static str {
        match self {
            Self::Unreachable(_) => "backend_unreachable",
            Self::Forbidden => "backend_forbidden",
            Self::TimedOut => "backend_timed_out",
            Self::NoBackend => "no_backend",
        }
    }
}

/// The addresses `authority` resolves to that `networks` permits.
///
/// Checked on every connection rather than only when the route is saved: a
/// name can start pointing somewhere internal at any time.
///
/// # Errors
///
/// - [`DialFailure::Unreachable`] when the name does not resolve.
/// - [`DialFailure::Forbidden`] when nothing it resolves to may be reached.
pub(super) async fn permitted_addresses(
    authority: &str,
    networks: &UpstreamNetworks,
) -> Result<Vec<SocketAddr>, DialFailure> {
    let resolved = tokio::net::lookup_host(authority)
        .await
        .map_err(DialFailure::Unreachable)?;
    let permitted: Vec<SocketAddr> = resolved.filter(|a| networks.permits(a.ip())).collect();
    if permitted.is_empty() {
        return Err(DialFailure::Forbidden);
    }
    Ok(permitted)
}

/// A connection to `authority` at an address `networks` permits, opened
/// within `limit`, resolving included.
///
/// # Errors
///
/// - [`DialFailure::TimedOut`] past `limit`.
/// - [`DialFailure::Unreachable`] or [`DialFailure::Forbidden`] as
///   [`permitted_addresses`] says, or when every address refuses.
pub(super) async fn dial(
    authority: &str,
    networks: &UpstreamNetworks,
    limit: Duration,
) -> Result<TcpStream, DialFailure> {
    let connecting = async {
        let addresses = permitted_addresses(authority, networks).await?;
        TcpStream::connect(addresses.as_slice())
            .await
            .map_err(DialFailure::Unreachable)
    };
    tokio::time::timeout(limit, connecting)
        .await
        .map_err(|_| DialFailure::TimedOut)?
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use tokio::net::TcpSocket;

    use super::*;

    fn backend(host: &str, weight: u32) -> StreamBackend {
        StreamBackend::new(host, 5432, weight).expect("a valid backend")
    }

    fn loopback() -> UpstreamNetworks {
        UpstreamNetworks::parse_list("127.0.0.0/8").expect("a valid range")
    }

    #[test]
    fn a_single_backend_is_always_picked() {
        let backends = Backends::new(vec![backend("a.example.com", 1)]);

        for _ in 0..5 {
            let picked = backends.pick().expect("a backend");
            assert_eq!(picked.host().as_str(), "a.example.com");
        }
    }

    #[test]
    fn weights_decide_the_proportions_exactly() {
        let backends = Backends::new(vec![
            backend("a.example.com", 1),
            backend("b.example.com", 3),
        ]);

        let to_a = (0..400)
            .filter_map(|_| backends.pick())
            .filter(|b| b.host().as_str() == "a.example.com")
            .count();

        assert_eq!(to_a, 100);
    }

    #[tokio::test]
    async fn a_backend_outside_the_networks_is_never_dialled() {
        let listening = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let authority = listening.local_addr().expect("address").to_string();

        let dialled = dial(
            &authority,
            &UpstreamNetworks::public_only(),
            Duration::from_secs(1),
        )
        .await;

        assert!(matches!(dialled, Err(DialFailure::Forbidden)));
    }

    /// A backend whose accept queue is full drops new handshakes, so a
    /// connect to it hangs. The dial gives up at its limit rather than
    /// holding the client's connection.
    #[tokio::test]
    async fn a_backend_that_never_answers_is_given_up_on_at_the_limit() {
        let socket = TcpSocket::new_v4().expect("socket");
        socket
            .bind("127.0.0.1:0".parse().expect("address"))
            .expect("bind");
        let full = socket.listen(1).expect("listen");
        let address = full.local_addr().expect("address");
        let fillers: Vec<_> = (0..8)
            .map(|_| {
                tokio::spawn(tokio::time::timeout(
                    Duration::from_secs(5),
                    TcpStream::connect(address),
                ))
            })
            .collect();
        tokio::time::sleep(Duration::from_millis(100)).await;

        let started = Instant::now();
        let dialled = dial(
            &address.to_string(),
            &loopback(),
            Duration::from_millis(300),
        )
        .await;

        assert!(matches!(dialled, Err(DialFailure::TimedOut)));
        assert!(started.elapsed() < Duration::from_secs(2));
        fillers.iter().for_each(tokio::task::JoinHandle::abort);
    }
}
