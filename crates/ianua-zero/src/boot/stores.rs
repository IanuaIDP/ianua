//! The stores the gateway reads and the few it writes, every one under the
//! gateway's own database role, each built once and handed to whatever
//! reads it.
//!
//! The role reads what the gateway serves and checks callers against, and
//! writes only its request and stream records, its event inbox, what the
//! session and agent checks touch, and when each connector's link was
//! last seen. A store the role was not granted
//! fails at its first read, never silently.

use std::sync::Arc;

use ianua_app::ports::agents::{
    AgentExposureGate, AgentStandingCheck, AgentStore, DelegationRevocationCheck,
};
use ianua_app::ports::authentication::{
    AppSessionCheck, FactorStanding, Geolocator, SecretEncryptor,
};
use ianua_app::ports::authorization::{AccessRecordStore, PolicyStore};
use ianua_app::ports::branding::BrandingStore;
use ianua_app::ports::consumers::ConsumerStore;
use ianua_app::ports::crypto::{AssertionKeyStore, AssertionSigningKeys, VerifyingKeyStore};
use ianua_app::ports::data_classification::ClassificationStore;
use ianua_app::ports::domain::AcmeChallengeStore;
use ianua_app::ports::identity::UserStore;
use ianua_app::ports::oauth::{AccessTokenStore, OAuthClientStore};
use ianua_app::ports::organization::{MemberStandings, OrganizationStore};
use ianua_app::ports::proxy::{
    CrossTenantHosts, CrossTenantServedCertificates, LogShippingStore, PipelineStore,
    ProxyAccessLogSink, WasmModuleStore,
};
use ianua_app::ports::routing::{
    ConnectorSightings, ConnectorTunnelStore, PolicyDecisionPoint, RouteStore, ServiceStore,
    StreamRecordWriter, StreamRouteDirectory, StreamRouteStore,
};
use ianua_app::ports::shared::SessionStore;
use ianua_app::ports::tenant::TenantStore;
use ianua_domain::shared::config::DomainLimits;
use ianua_infra::cache::{
    CacheAccessRecordStore, CacheAppSessionCheck, CacheAssertionSigningKeys,
    CacheClassificationStore, CacheVerifyingKeyStore, EntryKeeping,
};
use ianua_infra::postgres::agents::{
    PgAgentExposureGate, PgAgentStandingCheck, PgAgentStore, PgDelegationRevocationCheck,
};
use ianua_infra::postgres::authentication::PgFactorStanding;
use ianua_infra::postgres::authorization::{PgAccessRecordStore, PgPolicyStore};
use ianua_infra::postgres::branding::PgBrandingStore;
use ianua_infra::postgres::consumers::PgConsumerStore;
use ianua_infra::postgres::crypto::{
    PgAssertionKeyStore, PgAssertionSigningKeys, PgVerifyingKeyStore,
};
use ianua_infra::postgres::data_classification::PgClassificationStore;
use ianua_infra::postgres::domain::PgAcmeChallengeStore;
use ianua_infra::postgres::identity::PgUserStore;
use ianua_infra::postgres::oauth::{PgAccessTokenStore, PgOAuthClientStore};
use ianua_infra::postgres::organization::{PgMemberStandings, PgOrganizationStore};
use ianua_infra::postgres::proxy::{
    PgCrossTenantHosts, PgCrossTenantServedCertificates, PgLogShippingStore, PgPipelineStore,
    PgProxyAccessLogSink, PgWasmModuleStore,
};
use ianua_infra::postgres::routing::{
    PgConnectorSightings, PgConnectorTunnelStore, PgPolicyDecisionPoint, PgRouteStore,
    PgServiceStore, PgStreamRecordWriter, PgStreamRouteDirectory, PgStreamRouteStore,
};
use ianua_infra::postgres::shared::{PgAppSessionCheck, PgSessionStore};
use ianua_infra::postgres::tenant::PgTenantStore;

use crate::boot::foundation::Foundation;
use crate::config::Config;

/// The largest WASM module read for a `Custom` stage, as the API takes
/// them.
const LARGEST_MODULE: usize = 16 * 1024 * 1024;

/// How many live app sessions this node keeps.
const KEPT_ENTRIES: usize = 50_000;

/// How many tenants' keys and classification rules this node keeps.
const KEPT_TENANTS: usize = 10_000;

/// Every store the gateway reaches, under its own role.
pub(crate) struct Stores {
    /// Every tenant served and the names it is served on.
    pub hosts: Arc<dyn CrossTenantHosts>,
    /// The current certificate of every name served, keys opened.
    pub served_certificates: Arc<dyn CrossTenantServedCertificates>,
    /// Loads tenant identity and standing before constructing its serving state.
    pub tenants: Arc<dyn TenantStore>,
    /// The organizations, for the issuer of a tenant's tokens.
    pub organizations: Arc<dyn OrganizationStore>,
    /// Each tenant's routes.
    pub routes: Arc<dyn RouteStore>,
    /// Each tenant's services.
    pub services: Arc<dyn ServiceStore>,
    /// Each tenant's pipelines.
    pub pipelines: Arc<dyn PipelineStore>,
    /// Each tenant's stream routes.
    pub stream_routes: Arc<dyn StreamRouteStore>,
    /// Every active stream route with its port.
    pub stream_directory: Arc<dyn StreamRouteDirectory>,
    /// Each tenant's look.
    pub branding: Arc<dyn BrandingStore>,
    /// Each tenant's consumers.
    pub consumers: Arc<dyn ConsumerStore>,
    /// Each tenant's sessions, for holding their uses against where each
    /// was last used.
    pub sessions: Arc<dyn SessionStore>,
    /// Whether a person holds a factor that could lift a frozen session.
    pub factor_standing: Arc<dyn FactorStanding>,
    /// Where an address is: the country database the settings name, or
    /// none.
    pub geolocator: Arc<dyn Geolocator>,
    /// What decides each holder's holdings, kept a short while.
    pub access_records: Arc<dyn AccessRecordStore>,
    /// The tenants' people.
    pub users: Arc<dyn UserStore>,
    /// Whether an app session is live, kept as long as the settings say.
    pub app_sessions: Arc<dyn AppSessionCheck>,
    /// Each route's policy.
    pub policy_decisions: Arc<dyn PolicyDecisionPoint>,
    /// Organization members an agent acts for, as a tenant reads them.
    pub member_standings: Arc<dyn MemberStandings>,
    /// Each tenant's authorization policy.
    pub policies: Arc<dyn PolicyStore>,
    /// Each tenant's classification rules.
    pub classifications: Arc<dyn ClassificationStore>,
    /// The modules `Custom` stages run.
    pub wasm_modules: Arc<dyn WasmModuleStore>,
    /// Where request records are written.
    pub access_log: Arc<dyn ProxyAccessLogSink>,
    /// Where stream records are written.
    pub stream_records: Arc<dyn StreamRecordWriter>,
    /// The ACME answers port 80 serves.
    pub acme_challenges: Arc<dyn AcmeChallengeStore>,
    /// Where each tenant ships its request records.
    pub log_shipping: Arc<dyn LogShippingStore>,
    /// The tenants' agents, for the name a stolen token's record carries.
    pub agents: Arc<dyn AgentStore>,
    /// Whether an agent may still act.
    pub agent_standings: Arc<dyn AgentStandingCheck>,
    /// Whether a delegation was revoked.
    pub delegation_revocations: Arc<dyn DelegationRevocationCheck>,
    /// How far each agent was exposed.
    pub agent_exposure: Arc<dyn AgentExposureGate>,
    /// The public halves of tenants' signing keys.
    pub verifying_keys: Arc<dyn VerifyingKeyStore>,
    /// The key that signs each tenant's assertions now, opened.
    pub assertion_signing_keys: Arc<dyn AssertionSigningKeys>,
    /// Each tenant's assertion keys, for the key set published on its
    /// hosts.
    pub assertion_keys: Arc<dyn AssertionKeyStore>,
    /// The tenants' OAuth clients.
    pub oauth_clients: Arc<dyn OAuthClientStore>,
    /// The opaque access tokens issued.
    pub access_tokens: Arc<dyn AccessTokenStore>,
    /// Each tenant's enrolled connectors, the parts a link is judged by.
    pub connector_tunnels: Arc<dyn ConnectorTunnelStore>,
    /// When each connector's link was last seen.
    pub connector_sightings: Arc<dyn ConnectorSightings>,
}

impl Stores {
    /// Every store, on `foundation`'s pools and caches, as `config` keeps
    /// them.
    #[must_use]
    // Every field wires one store adapter; keeping the complete inventory together exposes omissions.
    #[allow(clippy::too_many_lines)]
    pub(crate) fn new(foundation: &Foundation, config: &Config) -> Self {
        let db = || Arc::clone(&foundation.databases);
        let caches = || Arc::clone(&foundation.store_caches);
        let sealer = || -> Arc<dyn SecretEncryptor> { Arc::clone(&foundation.encryptor) };
        let limits = DomainLimits::default;
        Self {
            hosts: Arc::new(PgCrossTenantHosts::new(db(), limits())),
            served_certificates: Arc::new(PgCrossTenantServedCertificates::new(db(), sealer())),
            tenants: Arc::new(PgTenantStore::new(db(), limits())),
            organizations: Arc::new(PgOrganizationStore::new(db(), limits())),
            routes: Arc::new(PgRouteStore::new(db())),
            services: Arc::new(PgServiceStore::new(db())),
            pipelines: Arc::new(PgPipelineStore::new(db())),
            stream_routes: Arc::new(PgStreamRouteStore::new(db())),
            stream_directory: Arc::new(PgStreamRouteDirectory::new(db())),
            branding: Arc::new(PgBrandingStore::new(db())),
            consumers: Arc::new(PgConsumerStore::new(db())),
            access_records: Arc::new(CacheAccessRecordStore::new(
                Arc::new(PgAccessRecordStore::new(db())),
                caches(),
                config.cache.holdings,
            )),
            sessions: Arc::new(PgSessionStore::new(db())),
            factor_standing: Arc::new(PgFactorStanding::new(db())),
            geolocator: Arc::clone(&foundation.geolocator),
            users: Arc::new(PgUserStore::new(db(), limits())),
            app_sessions: app_sessions(foundation, config),
            policy_decisions: Arc::new(PgPolicyDecisionPoint::new(db(), limits())),
            member_standings: Arc::new(PgMemberStandings::new(db(), limits())),
            policies: Arc::new(PgPolicyStore::new(db())),
            classifications: Arc::new(CacheClassificationStore::new(
                Arc::new(PgClassificationStore::new(db())),
                caches(),
                KEPT_TENANTS,
            )),
            wasm_modules: Arc::new(PgWasmModuleStore::new(db(), LARGEST_MODULE)),
            access_log: Arc::new(PgProxyAccessLogSink::new(db())),
            stream_records: Arc::new(PgStreamRecordWriter::new(db())),
            acme_challenges: Arc::new(PgAcmeChallengeStore::new(db())),
            log_shipping: Arc::new(PgLogShippingStore::new(db())),
            agents: Arc::new(PgAgentStore::new(db())),
            agent_standings: Arc::new(PgAgentStandingCheck::new(db())),
            delegation_revocations: Arc::new(PgDelegationRevocationCheck::new(db())),
            agent_exposure: Arc::new(PgAgentExposureGate::new(db())),
            verifying_keys: Arc::new(CacheVerifyingKeyStore::new(
                Arc::new(PgVerifyingKeyStore::new(db())),
                caches(),
                KEPT_TENANTS,
            )),
            assertion_signing_keys: Arc::new(CacheAssertionSigningKeys::new(
                Arc::new(PgAssertionSigningKeys::new(db(), sealer())),
                caches(),
                KEPT_TENANTS,
            )),
            assertion_keys: Arc::new(PgAssertionKeyStore::new(db(), sealer())),
            oauth_clients: Arc::new(PgOAuthClientStore::new(db())),
            access_tokens: Arc::new(PgAccessTokenStore::new(db())),
            connector_tunnels: Arc::new(PgConnectorTunnelStore::new(db())),
            connector_sightings: Arc::new(PgConnectorSightings::new(db())),
        }
    }
}

/// The check of live app sessions: kept for as long as
/// `GATEWAY_APP_SESSION_CACHE_SECONDS` says, or asked of the store on every
/// request when it says nothing is kept.
fn app_sessions(foundation: &Foundation, config: &Config) -> Arc<dyn AppSessionCheck> {
    let store: Arc<dyn AppSessionCheck> =
        Arc::new(PgAppSessionCheck::new(Arc::clone(&foundation.databases)));
    let lifetime = config.app_sign_in.session_cache;
    if lifetime.is_zero() {
        return store;
    }
    Arc::new(CacheAppSessionCheck::keeping(
        store,
        Arc::clone(&foundation.store_caches),
        EntryKeeping {
            lifetime,
            capacity: KEPT_ENTRIES,
        },
    ))
}
