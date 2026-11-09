//! What everything else in the gateway is built on: its database pools
//! under its own role, the keys it may hold, the bus, the state every
//! gateway shares, the store caches over it, and the sealer of secrets at
//! rest.

use std::sync::Arc;
use std::time::Duration;

use ianua_app::ports::authentication::{Geolocator, SecretEncryptor};
use ianua_boot::foundation::{BusConfig, BusPlace, CacheConfig, CachePlace, DatabaseConfig};
use ianua_boot::shutdown::Shutdown;
use ianua_infra::bus::{Bus, MemoryBus, ServerBus};
use ianua_infra::cache::{MemoryState, ServerState, SharedState, StoreCaches};
use ianua_infra::crypto::{
    AesGcmSecretEncryptor, BroadcastSeal, EventSeal, FleetVerdictSeal, RootSecret,
};
use ianua_infra::geo::{MmdbGeolocator, NoGeolocator};
use ianua_infra::namespace::Namespace;
use ianua_infra::postgres::Databases;
use ianua_infra::postgres::tenant::load_tenant_databases;

use crate::config::Config;
use crate::error::PlatformError;

/// How long a store cache's version is kept past its last raise, as the
/// control plane keeps it.
const VERSIONS_KEPT: Duration = Duration::from_secs(86_400);

/// The keys the gateway holds, all made from the shared root: never the
/// control plane's root, which it is never given.
#[derive(Debug, Clone)]
pub(crate) struct Keys {
    /// The shared root itself, for the adapters that derive their own key
    /// from it: the digests of consumers' keys and the sealed channel to
    /// the API.
    pub shared_root: RootSecret,
    /// The seal on every event the gateway keeps in its inbox, which the
    /// worker checks before the event reaches the trail.
    pub data_plane_seal: EventSeal,
    /// The seal on the live dashboard updates the gateway broadcasts.
    pub broadcast_seal: BroadcastSeal,
    /// The seal on the threat verdicts gateways share.
    pub fleet_seal: Arc<FleetVerdictSeal>,
}

/// The foundation, built once.
pub(crate) struct Foundation {
    /// The gateway role's pools, every tenant's own database known.
    pub databases: Arc<Databases>,
    /// The keys the gateway holds.
    pub keys: Keys,
    /// The message bus.
    pub bus: Arc<dyn Bus>,
    /// The state every gateway shares: the cache server, or this process's
    /// memory in development.
    pub shared_state: Arc<dyn SharedState>,
    /// The store caches of this node, under versions every node shares.
    pub store_caches: Arc<StoreCaches>,
    /// Opens the secrets stored sealed: served certificates' keys, tenants'
    /// assertion keys, log shipping credentials.
    pub encryptor: Arc<dyn SecretEncryptor>,
    /// Where an address is: the country database the settings name, or
    /// none, with which every address stays unplaced.
    pub geolocator: Arc<dyn Geolocator>,
}

impl Foundation {
    /// The foundation `config` describes. The database is waited for until
    /// it answers, or until `shutdown` stops.
    ///
    /// # Errors
    ///
    /// [`PlatformError`] naming the part that could not be built.
    pub(crate) async fn build(config: &Config, shutdown: &Shutdown) -> Result<Self, PlatformError> {
        let databases = databases(&config.database, shutdown).await?;
        let bus = bus(&config.bus, &config.namespace).await?;
        let shared_state = state(&config.cache, &config.namespace).await?;
        let store_caches = Arc::new(StoreCaches::new(Arc::clone(&shared_state), VERSIONS_KEPT));
        let shared = &config.keys.shared_root;
        Ok(Self {
            databases,
            keys: Keys {
                data_plane_seal: EventSeal::data_plane(shared),
                broadcast_seal: BroadcastSeal::data_plane(shared),
                fleet_seal: Arc::new(FleetVerdictSeal::new(shared)),
                shared_root: shared.clone(),
            },
            bus,
            shared_state,
            store_caches,
            encryptor: Arc::new(AesGcmSecretEncryptor::new(
                config.keys.sealing_key.clone(),
                config.keys.retired_keys.clone(),
            )),
            geolocator: geolocator(config)?,
        })
    }
}

/// Where a client's address is looked up: the country database the
/// settings name, or none, in which every address stays unplaced and a
/// geo fence with an allow list refuses every caller.
fn geolocator(config: &Config) -> Result<Arc<dyn Geolocator>, PlatformError> {
    let Some(path) = &config.deployment.geoip_database else {
        return Ok(Arc::new(NoGeolocator));
    };
    let opened = MmdbGeolocator::open(path).map_err(PlatformError::of("the country database"))?;
    Ok(Arc::new(opened))
}

/// The gateway role's pools, with every tenant living apart routed to its
/// own database, waited for until the database answers.
///
/// The gateway never migrates: it starts beside a control plane that may
/// still be migrating, so it asks again every `ready_poll`.
async fn databases(
    database: &DatabaseConfig,
    shutdown: &Shutdown,
) -> Result<Arc<Databases>, PlatformError> {
    let databases = Arc::new(Databases::gateway(
        database.login.options.clone(),
        database.pools,
    ));
    loop {
        match load_tenant_databases(&databases).await {
            Ok(()) => return Ok(databases),
            Err(error) => tracing::info!(%error, "waiting for the database"),
        }
        tokio::select! {
            () = shutdown.stopping() => return Err(PlatformError::Stopped),
            () = tokio::time::sleep(database.ready_poll) => {}
        }
    }
}

/// The bus the configuration names: in this process, or on a server with
/// every name under `namespace`.
async fn bus(config: &BusConfig, namespace: &Namespace) -> Result<Arc<dyn Bus>, PlatformError> {
    let (url, sign_in) = match &config.place {
        BusPlace::Memory { events } => return Ok(Arc::new(MemoryBus::new(*events))),
        BusPlace::Server { url, sign_in } => (url, sign_in),
    };
    let server = ServerBus::connect_as(url, sign_in, namespace, config.timeout)
        .await
        .map_err(PlatformError::of("the bus"))?;
    Ok(Arc::new(server))
}

/// The state every gateway shares, every key on a cache server under
/// `namespace`.
async fn state(
    config: &CacheConfig,
    namespace: &Namespace,
) -> Result<Arc<dyn SharedState>, PlatformError> {
    match &config.place {
        CachePlace::Memory { entries } => Ok(Arc::new(MemoryState::new(*entries))),
        CachePlace::Server { url } => {
            let server = ServerState::connect(url.expose(), namespace, config.timeout)
                .await
                .map_err(PlatformError::of("the cache"))?;
            Ok(Arc::new(server))
        }
    }
}
