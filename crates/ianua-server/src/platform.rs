//! The shared core, built once per process from the configuration: the
//! databases, the keys, the bus and the shared state, the store caches with
//! the unit of work and the dispatcher they wrap, the sealer and the
//! hasher, the file store, the metrics, the readiness probes, and the
//! providers outside the deployment both halves call: mail, the clouds
//! and the workflows' integrations.
//!
//! The API and the worker take every adapter of this kind from here and
//! never build a copy of their own: two pools, two caches or two bus
//! connections in one process would each see half of what happens.

mod databases;
mod integrations;
mod keys;
mod memory;
mod messaging;
mod protected_data;
mod providers;
mod services;
mod stores;

use std::sync::Arc;

use ianua_app::ports::authorization::AccessRecordStore;
use ianua_app::ports::domain::DnsResolver;
use ianua_app::ports::federation::SamlMetadataReader;
use ianua_app::ports::runtime::UnitOfWork;
use ianua_app::ports::shared::{EventDispatcher, TokenLookup};
use ianua_boot::shutdown::Shutdown;
use ianua_infra::bus::{Bus, MessagePlane};
use ianua_infra::cache::{SharedState, StoreCacheFollower, StoreCaches};
use ianua_infra::cloud::ConfiguredCloudProviderRegistry;
use ianua_infra::crypto::HmacTokenResolver;
use ianua_infra::files::{FileLinks, FileStore};
use ianua_infra::integrations::Installed;
use ianua_infra::postgres::Databases;
use ianua_infra::postgres::tenant::{TenantDatabaseFollower, TenantSchemaAccess};

pub use self::keys::{Digests, Keys};
pub(crate) use self::memory::MemoryParts;
pub use self::providers::Mail;
pub use self::services::{Metrics, Outbound, Readiness, Secrets};
use crate::config::Config;
use crate::error::PlatformError;
use crate::platform::databases::DatabaseParts;
use crate::platform::messaging::{BusParts, StateParts};
use crate::platform::stores::StoreParts;

/// The shared core of one process.
pub struct Platform {
    /// The app's role's databases, every tenant's route loaded and kept to
    /// the registry by the follower.
    pub databases: Arc<Databases>,
    /// The audit purge's role's databases, for the retention store, the
    /// trail mover and the tenant database provisioner alone, and never
    /// handed to anything else. Held by a worker and the install command;
    /// the configuration keeps the login off every API node.
    pub audit_purge: Option<Arc<Databases>>,
    /// How tenants' schemas are made, as the owner, for the tenant database
    /// provisioner. Held where `audit_purge` is.
    pub schema_access: Option<TenantSchemaAccess>,
    /// The roots and the seals made from them.
    pub keys: Keys,
    /// The digests of every secret handed out.
    pub digests: Digests,
    /// The sealer of secrets at rest and the hashing of passwords.
    pub secrets: Secrets,
    /// The message bus.
    pub bus: Arc<dyn Bus>,
    /// The agent message plane, on a bus server only.
    pub message_plane: Option<Arc<MessagePlane>>,
    /// The state every node shares: the cache server, or this process's
    /// memory on a deployment of one node.
    pub shared_state: Arc<dyn SharedState>,
    /// This node's own state, for the ports that count per node.
    pub node_state: Arc<dyn SharedState>,
    /// The store caches of this node.
    pub store_caches: Arc<StoreCaches>,
    /// The unit of work every use case runs in.
    pub unit_of_work: Arc<dyn UnitOfWork>,
    /// The event dispatcher every use case records through.
    pub event_dispatcher: Arc<dyn EventDispatcher>,
    /// The bearer lookup every port that looks a bearer up takes.
    pub token_lookup: Arc<dyn TokenLookup>,
    /// The access record store every port that reads holdings takes.
    pub access_records: Arc<dyn AccessRecordStore>,
    /// The resolver of bearers.
    pub token_resolver: Arc<HmacTokenResolver>,
    /// The file store.
    pub files: Arc<dyn FileStore>,
    /// The shared instruments recording runtime activity and failures.
    pub metrics: Metrics,
    /// The networks outbound calls may reach.
    pub outbound: Outbound,
    /// The probes `/ready` asks.
    pub readiness: Readiness,
    /// The platform's own mail.
    pub mail: Mail,
    /// The integrations workflow steps call, which the API lists and the
    /// worker runs.
    pub integrations: Arc<Installed>,
    /// The clouds customers connect their accounts from.
    pub clouds: Arc<ConfiguredCloudProviderRegistry>,
    /// The links export files are downloaded through, under the control
    /// root.
    pub file_links: FileLinks,
    /// The DNS lookups that prove tenants' domains, through the resolvers
    /// `DNS_RESOLVERS` names or the host's, for the API's checks and the worker's sweeps and
    /// certificate orders alike.
    pub dns: Arc<dyn DnsResolver>,
    /// Fetches and reads SAML providers' metadata, for the API's imports
    /// and the worker's refresh alike: names looked up through the
    /// resolvers `DNS_RESOLVERS` names or the host's, addresses screened by
    /// `UPSTREAM_NETWORKS`, and `SAML_METADATA_CA_FILE` trusted instead of
    /// the public roots when it is set.
    pub saml_metadata: Arc<dyn SamlMetadataReader>,
    /// The memories: where they and their texts are kept, and the
    /// embeddings client filling them.
    pub(crate) memory: MemoryParts,
}

impl Platform {
    /// The shared core `config` describes. A process holding the owner's
    /// login brings the schema up to date first; an API node waits until
    /// it is, or until `shutdown` stops it.
    ///
    /// # Errors
    ///
    /// [`PlatformError`] naming the part that could not be built.
    pub async fn build(config: &Config, shutdown: &Shutdown) -> Result<Self, PlatformError> {
        SharedParts::build(config, shutdown).await?.finish(config)
    }

    /// Starts what every node runs whatever its mode: the store caches'
    /// follower, dropping what other nodes' events changed, and the
    /// tenant database follower, keeping this node's routes to the
    /// registry. The worker does not start them again.
    pub fn follow(&self, config: &Config, shutdown: &Shutdown) {
        let caches = StoreCacheFollower::new(
            Arc::clone(&self.bus),
            self.keys.event_check.clone(),
            Arc::clone(&self.store_caches),
        );
        shutdown.spawn_until_stopped(caches.run());
        let routes = TenantDatabaseFollower::new(
            Arc::clone(&self.databases),
            Arc::clone(&self.bus),
            config.app_database.routes_reload,
        );
        let stopping = shutdown.stopping();
        shutdown.spawn("the tenant database follower", async move {
            tokio::select! {
                () = stopping => {}
                followed = routes.follow() => {
                    if let Err(error) = followed {
                        tracing::error!(%error, "the tenants' routes are no longer followed");
                    }
                }
            }
        });
    }
}

/// The resources opened once before constructing providers that share them.
struct SharedParts {
    databases: DatabaseParts,
    keys: Keys,
    bus: BusParts,
    state: StateParts,
    stores: StoreParts,
    outbound: Outbound,
}

impl SharedParts {
    /// Opens databases, messaging and caches in startup order before building providers.
    async fn build(config: &Config, shutdown: &Shutdown) -> Result<Self, PlatformError> {
        let databases = databases::databases(
            &config.database,
            &config.app_database,
            &config.logins,
            shutdown,
        )
        .await?;
        let keys = keys::keys(&config.crypto);
        let bus = messaging::bus(&config.bus, &config.namespace, &keys.receipt_seal).await?;
        let state = messaging::state(&config.cache, &config.namespace).await?;
        let stores = stores::stores(
            &databases.app,
            Arc::clone(&state.shared),
            &config.cache,
            &keys,
        );
        let outbound = services::outbound(config)?;
        Ok(Self {
            databases,
            keys,
            bus,
            state,
            stores,
            outbound,
        })
    }

    /// Builds providers over shared resources in their original validation order.
    /// The exhaustive initializer keeps the public platform's ownership transfers together.
    #[allow(clippy::too_many_lines)]
    fn finish(self, config: &Config) -> Result<Platform, PlatformError> {
        Ok(Platform {
            memory: memory::memory(config, &self.databases.app, &self.outbound)?,
            mail: providers::mail(config, &self.databases.app)?,
            integrations: providers::integrations(config, &self.outbound)?,
            clouds: providers::clouds(config)?,
            file_links: providers::file_links(config, &self.keys)?,
            dns: providers::dns(&config.domains.resolvers)?,
            saml_metadata: providers::saml_metadata(config)?,
            readiness: services::readiness(&self.databases.app, &self.bus.bus, &self.state.shared),
            secrets: services::secrets(&config.crypto)?,
            files: services::files(&config.files)?,
            metrics: services::metrics()?,
            outbound: self.outbound,
            digests: keys::digests(&self.keys),
            keys: self.keys,
            databases: self.databases.app,
            audit_purge: self.databases.audit_purge,
            schema_access: self.databases.schema_access,
            bus: self.bus.bus,
            message_plane: self.bus.message_plane,
            shared_state: self.state.shared,
            node_state: self.state.node,
            store_caches: self.stores.caches,
            unit_of_work: self.stores.unit_of_work,
            event_dispatcher: self.stores.event_dispatcher,
            token_lookup: self.stores.token_lookup,
            access_records: self.stores.access_records,
            token_resolver: self.stores.token_resolver,
        })
    }
}
