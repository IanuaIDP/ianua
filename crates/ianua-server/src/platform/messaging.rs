//! The message bus, the agent message plane on it, and the state the
//! cache-shaped ports keep: shared across nodes, and this node's own.

use std::sync::Arc;

use ianua_boot::foundation::{BusConfig, BusPlace, CacheConfig, CachePlace};
use ianua_infra::bus::{Bus, MemoryBus, MessagePlane, ServerBus};
use ianua_infra::cache::{MemoryState, ServerState, SharedState};
use ianua_infra::crypto::ReceiptSeal;
use ianua_infra::namespace::Namespace;

use crate::error::PlatformError;

/// The entries this node's own state holds for the ports that count per
/// node, when the shared state lives elsewhere.
const NODE_ENTRIES: usize = 100_000;

/// The bus, and the message plane when the bus is a server.
pub(super) struct BusParts {
    /// The bus every event, broadcast and follower goes through.
    pub(super) bus: Arc<dyn Bus>,
    /// The agent message plane, which keeps durable consumers and dead
    /// letters and so runs on a bus server alone; none on a bus in this
    /// process.
    pub(super) message_plane: Option<Arc<MessagePlane>>,
}

/// The bus the configuration names: in this process, or on a server with
/// every name under `namespace`, the message plane opened on it.
///
/// # Errors
///
/// [`PlatformError`] when the bus server cannot be reached or its streams
/// cannot be made.
pub(super) async fn bus(
    config: &BusConfig,
    namespace: &Namespace,
    receipts: &ReceiptSeal,
) -> Result<BusParts, PlatformError> {
    let (url, sign_in) = match &config.place {
        BusPlace::Memory { events } => {
            return Ok(BusParts {
                bus: Arc::new(MemoryBus::new(*events)),
                message_plane: None,
            });
        }
        BusPlace::Server { url, sign_in } => (url, sign_in),
    };
    let server = ServerBus::connect_as(url, sign_in, namespace, config.timeout)
        .await
        .map_err(PlatformError::of("the bus"))?;
    let plane = MessagePlane::open(server.clone(), receipts.clone())
        .await
        .map_err(PlatformError::of("the agent message plane"))?;
    Ok(BusParts {
        bus: Arc::new(server),
        message_plane: Some(Arc::new(plane)),
    })
}

/// The state cache-shaped ports keep.
pub(super) struct StateParts {
    /// Shared by every node: the cache server, or this process's memory on
    /// a deployment of one node. Counters, ledgers, budgets, alert
    /// throttles and the store caches' versions live here.
    pub(super) shared: Arc<dyn SharedState>,
    /// This node's own, for the ports that count per node: rate limits and
    /// the bind, mail, webhook and verification throttles.
    pub(super) node: Arc<dyn SharedState>,
}

/// The shared state the configuration names, every key on a cache server
/// under `namespace`, and this node's own.
///
/// # Errors
///
/// [`PlatformError`] when the cache server cannot be reached in time.
pub(super) async fn state(
    config: &CacheConfig,
    namespace: &Namespace,
) -> Result<StateParts, PlatformError> {
    match &config.place {
        CachePlace::Memory { entries } => {
            let memory: Arc<dyn SharedState> = Arc::new(MemoryState::new(*entries));
            Ok(StateParts {
                shared: Arc::clone(&memory),
                node: memory,
            })
        }
        CachePlace::Server { url } => {
            let server = ServerState::connect(url.expose(), namespace, config.timeout)
                .await
                .map_err(PlatformError::of("the cache"))?;
            Ok(StateParts {
                shared: Arc::new(server),
                node: Arc::new(MemoryState::new(NODE_ENTRIES)),
            })
        }
    }
}
