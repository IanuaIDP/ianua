//! What the platform runs in the process or reaches out to beside the
//! stores: the sealer and the password hasher, the file store, the
//! metrics, the networks outbound calls may reach, and the readiness
//! probes.

use std::sync::Arc;

use ianua_app::ports::runtime::ReadinessProbe;
use ianua_boot::foundation::{CryptoConfig, FilesConfig};
use ianua_domain::shared::security::ssrf::UpstreamNetworks;
use ianua_domain::types::CertificatePem;
use ianua_infra::bus::{Bus, BusReadinessProbe};
use ianua_infra::cache::{CacheReadinessProbe, SharedState};
use ianua_infra::crypto::{AesGcmSecretEncryptor, Argon2PasswordHashFormat, Argon2PasswordHasher};
use ianua_infra::files::{DiskFileStore, FileStore, ObjectFileStore};
use ianua_infra::http::client::{DeliveryReach, NameLookup};
use ianua_infra::postgres::Databases;
use ianua_infra::postgres::runtime::PgReadinessProbe;
use ianua_infra::runtime::{
    LocalMetricsExporter, LocalPasswordHashPermits, LocalServedRequestObserver,
};
use prometheus::Registry;

use crate::config::Config;
use crate::error::PlatformError;

/// The sealer of secrets at rest and the hashing of passwords.
pub struct Secrets {
    /// Seals under the current key and opens under the retired ones too.
    pub encryptor: Arc<AesGcmSecretEncryptor>,
    /// Hashes passwords with Argon2id and checks imported formats.
    pub password_hasher: Arc<Argon2PasswordHasher>,
    /// Says whether a stored hash needs making again under the current
    /// settings.
    pub password_format: Arc<Argon2PasswordHashFormat>,
    /// The bounded places hashes run in, so a flood of sign-ins cannot
    /// take every CPU.
    pub hash_permits: Arc<LocalPasswordHashPermits>,
}

/// The metrics this process exposes.
pub struct Metrics {
    /// The one registry every metric is in.
    pub registry: Registry,
    /// Writes the registry out for the scrape.
    pub exporter: Arc<LocalMetricsExporter>,
    /// Counts the API's requests into the registry.
    pub served_requests: Arc<LocalServedRequestObserver>,
}

/// The networks calls out of the deployment may reach, beside public
/// addresses. Every outbound adapter builds its own client from these,
/// screened for an address a tenant chose and fixed for one the platform
/// chose, so no client is shared.
#[derive(Debug, Clone)]
pub struct Outbound {
    /// For routes, identity providers, webhooks and every other address a
    /// tenant chose: `UPSTREAM_NETWORKS`.
    pub upstream_networks: UpstreamNetworks,
    /// For tenants' model endpoints: `ALLOW_PRIVATE_MODEL_ENDPOINTS`.
    pub model_networks: UpstreamNetworks,
    /// How webhooks, signal pushes, audit streams, message pushes,
    /// notification destinations and integrations reach their addresses:
    /// `OUTBOUND_DELIVERY_CA_FILE` and `DNS_RESOLVERS` when the file is
    /// set, the host's lookup and public roots otherwise.
    pub deliveries: DeliveryReach,
}

/// The probes `/ready` asks: the database, the bus and the cache.
pub struct Readiness {
    /// Pings the platform's database.
    pub database: Arc<dyn ReadinessProbe>,
    /// Pings the bus.
    pub bus: Arc<dyn ReadinessProbe>,
    /// Pings the shared state.
    pub cache: Arc<dyn ReadinessProbe>,
}

/// The sealer, the hasher and its permits.
///
/// # Errors
///
/// [`PlatformError`] when Argon2 refuses the settings, which a checked
/// configuration never holds.
pub(super) fn secrets(crypto: &CryptoConfig) -> Result<Secrets, PlatformError> {
    let hashing = crypto.hashing;
    Ok(Secrets {
        encryptor: Arc::new(AesGcmSecretEncryptor::new(
            crypto.shared.sealing_key.clone(),
            crypto.shared.retired_keys.clone(),
        )),
        password_hasher: Arc::new(
            Argon2PasswordHasher::new(hashing.argon2)
                .map_err(PlatformError::of("the password hasher"))?,
        ),
        password_format: Arc::new(Argon2PasswordHashFormat::new(hashing.argon2)),
        hash_permits: Arc::new(LocalPasswordHashPermits::new(
            hashing.concurrency,
            hashing.wait,
        )),
    })
}

/// The file store the configuration names.
///
/// # Errors
///
/// [`PlatformError`] when the object store refuses its settings.
pub(super) fn files(config: &FilesConfig) -> Result<Arc<dyn FileStore>, PlatformError> {
    match config {
        FilesConfig::Disk { dir } => Ok(Arc::new(DiskFileStore::new(dir.clone()))),
        FilesConfig::Objects(settings) => Ok(Arc::new(
            ObjectFileStore::new(settings.clone())
                .map_err(PlatformError::of("the object store"))?,
        )),
    }
}

/// The registry, its exporter and the API's request counts.
///
/// # Errors
///
/// [`PlatformError`] when the request counts cannot be registered.
pub(super) fn metrics() -> Result<Metrics, PlatformError> {
    let registry = Registry::new();
    let served_requests = LocalServedRequestObserver::register(&registry)
        .map_err(PlatformError::of("the request metrics"))?;
    Ok(Metrics {
        exporter: Arc::new(LocalMetricsExporter::new(registry.clone())),
        served_requests: Arc::new(served_requests),
        registry,
    })
}

/// The networks outbound calls may reach, and how deliveries reach them.
///
/// # Errors
///
/// [`PlatformError`] when `OUTBOUND_DELIVERY_CA_FILE` is set but cannot
/// be read or holds no certificate, or the resolvers cannot be built.
pub(super) fn outbound(config: &Config) -> Result<Outbound, PlatformError> {
    Ok(Outbound {
        upstream_networks: config.http.upstream_networks.clone(),
        model_networks: config.agents.model_networks.clone(),
        deliveries: delivery_reach(config)?,
    })
}

/// How deliveries reach their addresses: with `OUTBOUND_DELIVERY_CA_FILE`
/// set, through the resolvers `DNS_RESOLVERS` names or the host's, that
/// authority trusted beside the public roots; with it unset, exactly as
/// before, through the host's lookup and the public roots.
fn delivery_reach(config: &Config) -> Result<DeliveryReach, PlatformError> {
    let Some(path) = &config.http.delivery_authority else {
        return Ok(DeliveryReach::default());
    };
    let lookup = NameLookup::asking(&config.domains.resolvers)
        .map_err(PlatformError::of("the delivery name lookup"))?;
    let pem =
        std::fs::read_to_string(path).map_err(PlatformError::of("OUTBOUND_DELIVERY_CA_FILE"))?;
    let authority =
        CertificatePem::new(pem).map_err(PlatformError::of("OUTBOUND_DELIVERY_CA_FILE"))?;
    DeliveryReach::also_trusting(lookup, &authority)
        .map_err(PlatformError::of("OUTBOUND_DELIVERY_CA_FILE"))
}

/// The probes of the database, the bus and the shared state.
#[must_use]
pub(super) fn readiness(
    databases: &Arc<Databases>,
    bus: &Arc<dyn Bus>,
    state: &Arc<dyn SharedState>,
) -> Readiness {
    Readiness {
        database: Arc::new(PgReadinessProbe::new(Arc::clone(databases))),
        bus: Arc::new(BusReadinessProbe::new(Arc::clone(bus))),
        cache: Arc::new(CacheReadinessProbe::new(Arc::clone(state))),
    }
}
