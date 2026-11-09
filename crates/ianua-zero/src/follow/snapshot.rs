//! What the follower hands the gateway's tables, and what it asks of them.

use ianua_app::ports::pages::ErrorBranding;
use ianua_app::ports::proxy::{HostedTenant, ServedCertificate};
use ianua_domain::domains::proxy::pipeline::Pipeline;
use ianua_domain::domains::routing::connector::tunnel::ConnectorTunnel;
use ianua_domain::domains::routing::route::Route;
use ianua_domain::domains::routing::service::Service;
use ianua_domain::domains::tenant::access::network_security::MtlsConfig;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{Issuer, OrganizationId, ServiceId, TenantId};

/// Everything the gateway serves one tenant by, read in one reload.
///
/// Whole, never partial: a snapshot is built only once every part of it
/// was read, so the tables never hold a tenant's new routes beside its old
/// pipelines. Routes are listed whatever their status; which of them serve
/// is the domain's answer, asked by the tables.
#[derive(Debug)]
pub(crate) struct TenantSnapshot {
    /// The tenant and every name it is served on. Only a tenant open to
    /// requests has one.
    pub hosted: HostedTenant,
    /// The organization that owns the tenant.
    pub organization: OrganizationId,
    /// The issuer the tenant's tokens name, which every token presented on
    /// its routes is held to and every assertion it hands upstreams names.
    pub issuer: Issuer,
    /// The tenant's look, which its error pages wear.
    pub branding: ErrorBranding,
    /// Whom the tenant trusts to sign client certificates, and whether it
    /// asks for them.
    pub mtls: MtlsConfig,
    /// Its HTTP routes, in priority order.
    pub routes: Vec<Route<ResolvedTenant>>,
    /// Its services, with the hosts their app sign-in answers on.
    pub services: Vec<Service<ResolvedTenant>>,
    /// The ordered stage definitions available to this tenant's HTTP routes.
    pub pipelines: Vec<Pipeline<ResolvedTenant>>,
    /// The opened private keys of the services that present a client
    /// certificate to their backends. A service whose key did not open is
    /// missing here, so it gets no pool and its routes are refused.
    pub client_keys: Vec<OpenedClientKey>,
    /// Its enrolled connectors, revoked ones too, which its connectors'
    /// links are judged against: a link whose connector is not among them
    /// admitting its key is closed.
    pub connectors: Vec<ConnectorTunnel>,
}

/// The private key one service presents with its client certificate,
/// opened from its seal. It never prints.
pub(crate) struct OpenedClientKey {
    /// The service presenting it.
    pub service_id: ServiceId,
    /// The key, as PEM.
    pub pem: Secret,
}

impl std::fmt::Debug for OpenedClientKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenedClientKey")
            .field("service_id", &self.service_id)
            .finish_non_exhaustive()
    }
}

/// The gateway's tables, as the follower keeps them current.
///
/// Every call replaces what it names whole and at once, so a request reads
/// either the tables before it or the tables after it, never a mix.
pub(crate) trait Tables: Send + Sync {
    /// Serves the tenant `snapshot` is of by it from now on, in place of
    /// whatever was held for that tenant.
    fn install(&self, snapshot: TenantSnapshot);

    /// Stops serving `tenant`: its names resolve to no tenant, and its
    /// routes, stream routes and trusted authorities are dropped. Nothing
    /// held for a tenant that was never installed is no error.
    fn withdraw(&self, tenant: &TenantId);

    /// Serves `certificates` from now on, in place of every certificate
    /// held: a certificate missing from them is no longer served.
    fn install_certificates(&self, certificates: Vec<ServedCertificate>);
}
