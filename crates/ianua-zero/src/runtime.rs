//! The internal listener: whether the process lives, whether it may take
//! traffic, and its metrics.
//!
//! Its own port, never the public one: what it serves maps a deployment,
//! and the public port is reachable by anyone. Bind it where only the
//! orchestrator and the scraper reach.
//!
//! - `/health/live` answers `200` for as long as the process runs.
//! - `/health/ready` answers `200` only once the follower loaded the
//!   tables and while the database, the bus and the cache each answer;
//!   `503` otherwise, and from the moment the stop is asked for.
//! - `/metrics` writes out the process's metrics registry.
//!
//! It holds a bounded number of connections, each bounded in time, and
//! stops taking new ones at the stop.

mod answers;
mod listener;
mod tables;

use std::net::SocketAddr;
use std::sync::Arc;

use ianua_app::ports::runtime::MetricsExporter;
use ianua_app::use_cases::runtime::CheckReadinessPorts;
use ianua_boot::shutdown::Shutdown;
use tokio::net::TcpListener;

use self::answers::Runtime;
use self::listener::accept_until_stopped;
pub(crate) use self::tables::TablesLoaded;

/// Why the internal listener could not be opened.
#[derive(Debug, thiserror::Error)]
pub enum RuntimeError {
    /// The address cannot be listened on.
    #[error("the internal listener cannot listen on {address}")]
    Listen {
        /// The address asked for.
        address: SocketAddr,
        /// Why not.
        #[source]
        cause: std::io::Error,
    },
}

/// What the internal listener reads.
pub(crate) struct RuntimePorts {
    /// The database, bus and cache probes.
    pub readiness: CheckReadinessPorts,
    /// Writes out the process's metrics registry.
    pub exporter: Arc<dyn MetricsExporter>,
    /// Whether the follower loaded the tables.
    pub tables: TablesLoaded,
}

/// Opens the internal listener on `address` and serves it until `shutdown`
/// stops; returns the address it listens on, which names the port given
/// when `address` asked for any.
///
/// # Errors
///
/// [`RuntimeError::Listen`] when `address` cannot be listened on.
pub(crate) async fn serve(
    ports: RuntimePorts,
    address: SocketAddr,
    shutdown: &Shutdown,
) -> Result<SocketAddr, RuntimeError> {
    let refused = |cause| RuntimeError::Listen { address, cause };
    let socket = TcpListener::bind(address).await.map_err(refused)?;
    let bound = socket.local_addr().map_err(refused)?;
    let runtime = Arc::new(Runtime::new(ports, shutdown.clone()));
    shutdown.spawn(
        "internal listener",
        accept_until_stopped(socket, runtime, shutdown.clone()),
    );
    tracing::info!(address = %bound, "internal listener open");
    Ok(bound)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use ianua_app::test_support::FakeMetricsExporter;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::TcpStream;

    use super::*;

    async fn asked(bound: SocketAddr, path: &str) -> String {
        let mut stream = TcpStream::connect(bound).await.unwrap();
        let request = format!("GET {path} HTTP/1.1\r\nHost: internal\r\n\r\n");
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut answer = String::new();
        stream.read_to_string(&mut answer).await.unwrap();
        answer
    }

    fn ports(tables: &TablesLoaded) -> RuntimePorts {
        RuntimePorts {
            readiness: CheckReadinessPorts::fakes(),
            exporter: Arc::new(FakeMetricsExporter::writing("")),
            tables: tables.clone(),
        }
    }

    /// An orchestrator asks over the wire: the fresh gateway is alive and
    /// not ready, then ready once its tables are loaded.
    #[tokio::test]
    async fn the_listener_answers_over_the_wire() {
        let shutdown = Shutdown::new(Duration::from_secs(1));
        let tables = TablesLoaded::not_yet();
        let bound = serve(ports(&tables), "127.0.0.1:0".parse().unwrap(), &shutdown)
            .await
            .unwrap();

        let live = asked(bound, "/health/live").await;
        let unready = asked(bound, "/health/ready").await;
        tables.mark_loaded();
        let ready = asked(bound, "/health/ready").await;

        assert!(live.starts_with("HTTP/1.1 200"), "{live}");
        assert!(unready.starts_with("HTTP/1.1 503"), "{unready}");
        assert!(ready.starts_with("HTTP/1.1 200"), "{ready}");
        shutdown.stop();
        assert!(shutdown.join().await.is_ok());
    }

    /// At the stop the listener takes no new connection.
    #[tokio::test]
    async fn the_listener_stops_at_the_stop() {
        let shutdown = Shutdown::new(Duration::from_secs(1));
        let bound = serve(
            ports(&TablesLoaded::not_yet()),
            "127.0.0.1:0".parse().unwrap(),
            &shutdown,
        )
        .await
        .unwrap();

        shutdown.stop();
        assert!(shutdown.join().await.is_ok());

        assert!(TcpStream::connect(bound).await.is_err());
    }
}
