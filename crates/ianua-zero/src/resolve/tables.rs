//! The tables the request path reads, kept current by the follower.
//!
//! [`Tables`] is the follower's [`follow::Tables`]: each install, withdrawal
//! or certificate handover builds what it changes and swaps it in whole, so
//! a request reads the tables before a change or after it, never a mix.
//! The routing side (hosts, routes, pipelines, sign-in hosts) is held here;
//! client-certificate verification and served certificates live in the
//! listener's tables, and the stream listeners read their own directory,
//! so a change to a tenant asks them to look again.

use std::collections::HashMap;
use std::sync::{Arc, OnceLock};

use arc_swap::ArcSwap;
use ianua_app::ports::pages::ErrorBranding;
use ianua_app::ports::proxy::{HostedTenant, ServedCertificate};
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::proxy::pipeline::Pipeline;
use ianua_domain::domains::proxy::stages::stage::{DecoyLifetime, ReconWindow};
use ianua_domain::domains::tenant::hosts::PlatformAddressing;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::{CanonicalPath, DomainName, Issuer, TenantId};

use crate::follow::{self, TenantSnapshot};
use crate::listen::{CertificateTable, ClientAuthTable, ServedNames, TenantMtls};
use crate::request::RequestHost;
use crate::resolve::hosts::{HostResolution, HostTable};
use crate::resolve::routes::{ClientCertificates, RouteSetting, RouteTable};
use crate::resolve::sign_in::AppSignInIndex;
use crate::stream::StreamReload;

/// One tenant's routes, app sign-in, issuer, look and pipelines, as one
/// install made them.
#[derive(Debug)]
pub(crate) struct TenantTable {
    routes: RouteTable,
    sign_in: AppSignInIndex,
    issuer: Issuer,
    branding: ErrorBranding,
    pipelines: Vec<Arc<Pipeline<ResolvedTenant>>>,
}

impl TenantTable {
    /// The tenant's routes.
    #[must_use]
    pub(crate) fn routes(&self) -> &RouteTable {
        &self.routes
    }

    /// The tenant's app sign-in, by host.
    #[must_use]
    pub(crate) fn sign_in(&self) -> &AppSignInIndex {
        &self.sign_in
    }

    /// The issuer the tenant's tokens name.
    #[must_use]
    pub(crate) fn issuer(&self) -> &Issuer {
        &self.issuer
    }

    /// The tenant's look, which its error pages wear.
    #[must_use]
    pub(crate) fn branding(&self) -> &ErrorBranding {
        &self.branding
    }

    /// How long a client asking for `path` is blocked, as the tenant's
    /// running pipelines say; `None` when no pipeline calls it a decoy.
    #[must_use]
    pub(crate) fn decoy_lifetime(&self, path: &CanonicalPath) -> Option<DecoyLifetime> {
        Pipeline::decoy_lifetime_across(self.pipelines.iter().map(Arc::as_ref), path)
    }

    /// The window the tenant's running pipelines score recon over; `None`
    /// when none scores it.
    #[must_use]
    pub(crate) fn recon_window(&self) -> Option<ReconWindow> {
        Pipeline::recon_window_across(self.pipelines.iter().map(Arc::as_ref))
    }

    /// The table `snapshot`'s routes, services and pipelines make, with
    /// client certificates verifiable or not.
    fn build(snapshot: TenantSnapshot, certificates: ClientCertificates) -> Self {
        let sign_in = AppSignInIndex::build(&snapshot.services);
        let services = snapshot
            .services
            .into_iter()
            .map(|service| (*service.id(), Arc::new(service)))
            .collect();
        let pipelines: Vec<Arc<Pipeline<ResolvedTenant>>> =
            snapshot.pipelines.into_iter().map(Arc::new).collect();
        let by_id = pipelines
            .iter()
            .map(|pipeline| (*pipeline.id(), Arc::clone(pipeline)))
            .collect();
        let setting = RouteSetting {
            services: &services,
            pipelines: &by_id,
            certificates,
        };
        Self {
            routes: RouteTable::build(snapshot.routes, setting),
            sign_in,
            issuer: snapshot.issuer,
            branding: snapshot.branding,
            pipelines,
        }
    }
}

/// Every served tenant's names and tables, one consistent version.
#[derive(Debug, Default, Clone)]
pub(crate) struct Routing {
    addressing: PlatformAddressing,
    hosted: HashMap<TenantId, HostedTenant>,
    hosts: Arc<HostTable>,
    tenants: HashMap<TenantId, Arc<TenantTable>>,
}

impl Routing {
    /// The tenant `host` belongs to: one tenant's, no tenant's, or more
    /// than one's and so refused.
    #[must_use]
    pub(crate) fn tenant_for(&self, host: &RequestHost) -> HostResolution {
        self.hosts.resolve(host)
    }

    /// `tenant`'s table, when it is served.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn tenant(&self, tenant: &ScopedTenant) -> Option<&TenantTable> {
        self.tenants.get(&**tenant).map(Arc::as_ref)
    }

    /// The table of `tenant`, shared, for a request that holds it from
    /// start to end; `None` when the tenant is not served.
    #[must_use]
    pub(crate) fn shared_tenant(&self, tenant: &ScopedTenant) -> Option<Arc<TenantTable>> {
        self.tenants.get(&**tenant).map(Arc::clone)
    }

    /// This version with `hosted` served by `table`, in place of whatever
    /// was held for it.
    fn with_tenant(
        &self,
        hosted: &HostedTenant,
        table: &Arc<TenantTable>,
        base: &DomainName,
    ) -> Self {
        let mut next = self.clone();
        next.hosted.insert(hosted.tenant_id, hosted.clone());
        next.tenants.insert(hosted.tenant_id, Arc::clone(table));
        next.rebuild_hosts(base);
        next
    }

    /// This version without `tenant`.
    fn without_tenant(&self, tenant: &TenantId, base: &DomainName) -> Self {
        let mut next = self.clone();
        next.hosted.remove(tenant);
        next.tenants.remove(tenant);
        next.rebuild_hosts(base);
        next
    }

    fn rebuild_hosts(&mut self, base: &DomainName) {
        self.hosts = Arc::new(HostTable::build(
            self.hosted.values(),
            base,
            self.addressing,
        ));
    }
}

/// What the tables are made of besides their own routing.
pub(crate) struct TablesParts {
    /// The deployment's enabled platform address shape.
    pub addressing: PlatformAddressing,
    /// The base domain tenants' platform subdomains sit under.
    pub base_domain: DomainName,
    /// The listener's client-certificate verification, per tenant.
    pub client_auth: Arc<ClientAuthTable>,
    /// The listener's served certificates.
    pub certificates: Arc<CertificateTable>,
}

/// The gateway's tables: routing for the request path, swapped whole, and
/// the listener's certificate tables, kept current beside it.
pub(crate) struct Tables {
    base_domain: DomainName,
    routing: ArcSwap<Routing>,
    client_auth: Arc<ClientAuthTable>,
    certificates: Arc<CertificateTable>,
    streams: OnceLock<StreamReload>,
}

impl Tables {
    /// Tables serving no tenant until the follower installs one: every host
    /// is unknown until then.
    #[must_use]
    pub(crate) fn new(parts: TablesParts) -> Self {
        Self {
            base_domain: parts.base_domain,
            routing: ArcSwap::from_pointee(Routing {
                addressing: parts.addressing,
                ..Routing::default()
            }),
            client_auth: parts.client_auth,
            certificates: parts.certificates,
            streams: OnceLock::new(),
        }
    }

    /// Asks `streams` to read the stream routes again whenever a tenant is
    /// installed or withdrawn from now on. The stream listeners end TLS for
    /// the names these tables serve, so they start after the tables and
    /// read every route as they start; only the first call counts.
    pub(crate) fn tell_streams(&self, streams: StreamReload) {
        if self.streams.set(streams).is_err() {
            tracing::warn!("the stream listeners were already told of; a second set is ignored");
        }
    }

    /// Asks the stream listeners, once started, to read their routes again.
    fn streams_changed(&self) {
        if let Some(streams) = self.streams.get() {
            streams.request();
        }
    }

    /// The routing as it is now. A request holds this one version from
    /// start to end.
    #[must_use]
    pub(crate) fn current(&self) -> Arc<Routing> {
        self.routing.load_full()
    }

    /// Verifies `snapshot`'s client certificates from the next handshake
    /// on, and says whether that can be done.
    fn install_client_auth(&self, snapshot: &TenantSnapshot) -> ClientCertificates {
        let tenant = TenantMtls {
            tenant_id: snapshot.hosted.tenant_id,
            config: snapshot.mtls.clone(),
        };
        let Err(error) = self.client_auth.set(&tenant) else {
            return ClientCertificates::Verifiable;
        };
        tracing::error!(
            tenant_id = %tenant.tenant_id,
            error = %error,
            "the tenant's client certificate authorities cannot be used; its client-certificate routes refuse"
        );
        ClientCertificates::Unverifiable
    }
}

impl follow::Tables for Tables {
    fn install(&self, snapshot: TenantSnapshot) {
        let certificates = self.install_client_auth(&snapshot);
        let hosted = snapshot.hosted.clone();
        let table = Arc::new(TenantTable::build(snapshot, certificates));
        self.routing
            .rcu(|current| current.with_tenant(&hosted, &table, &self.base_domain));
        self.streams_changed();
    }

    fn withdraw(&self, tenant: &TenantId) {
        self.routing
            .rcu(|current| current.without_tenant(tenant, &self.base_domain));
        self.client_auth.remove(tenant);
        self.streams_changed();
    }

    fn install_certificates(&self, certificates: Vec<ServedCertificate>) {
        let loaded = self.certificates.replace(&certificates);
        if loaded.refused.is_empty() {
            return;
        }
        let refused: Vec<&str> = loaded.refused.iter().map(DomainName::as_str).collect();
        tracing::warn!(
            refused = ?refused,
            "some served certificates cannot be used; their names are refused at the handshake"
        );
    }
}

/// The tenant behind the name a TLS client asked for, so its handshake is
/// verified by that tenant's authorities alone. A name no tenant or more
/// than one tenant answers on has none: its handshake asks for no client
/// certificate, and its requests resolve to no tenant and are refused.
impl ServedNames for Tables {
    fn tenant_of(&self, name: &DomainName) -> Option<TenantId> {
        let host = RequestHost::new(name.clone()).ok()?;
        match self.current().tenant_for(&host) {
            HostResolution::Tenant(tenant) => Some(*tenant),
            HostResolution::Unknown | HostResolution::Ambiguous => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::proxy::pipeline_status::PipelineStatus;
    use ianua_domain::domains::tenant::hosts::{PlatformLabel, ReadableAddress};
    use ianua_domain::shared::config::SlugLimits;
    use ianua_domain::types::{CanonicalPath, DisplayName, HttpMethod, TenantSlug};

    use super::*;
    use crate::request::RequestHeaders;
    use crate::resolve::routes::tests::{RouteSpec, active_service, pipelines_in};
    use crate::resolve::routes::{RouteLookup, RouteQuery};

    fn base() -> DomainName {
        DomainName::new("zero.test").unwrap()
    }

    fn hosted(org: &str, domains: &[&str]) -> HostedTenant {
        HostedTenant {
            platform_label: PlatformLabel::new("k7f3q9").unwrap(),
            readable_address: ReadableAddress::Off,
            tenant_id: TenantId::new(),
            organization_slug: TenantSlug::new(org, &SlugLimits::default()).unwrap(),
            slug: TenantSlug::new("prod", &SlugLimits::default()).unwrap(),
            domains: domains
                .iter()
                .map(|d| DomainName::new(*d).unwrap())
                .collect(),
        }
    }

    fn table_on(pattern: &'static str) -> Arc<TenantTable> {
        let service = Arc::new(active_service());
        let routes = vec![RouteSpec::on(pattern).stored(service.id())];
        let services = HashMap::from([(*service.id(), service)]);
        let pipelines = pipelines_in(PipelineStatus::Active);
        let setting = RouteSetting {
            services: &services,
            pipelines: &pipelines,
            certificates: ClientCertificates::Verifiable,
        };
        Arc::new(TenantTable {
            routes: RouteTable::build(routes, setting),
            sign_in: AppSignInIndex::default(),
            issuer: Issuer::new("https://app.example.com/t/acme-org/acme").unwrap(),
            branding: ErrorBranding {
                name: DisplayName::try_from("Acme".to_owned()).unwrap(),
                logo_url: None,
                primary_color: None,
                background_color: None,
            },
            pipelines: pipelines.values().cloned().collect(),
        })
    }

    fn host(name: &str) -> RequestHost {
        RequestHost::new(DomainName::new(name).unwrap()).unwrap()
    }

    fn routes_on(routing: &Routing, on: &str, path: &str) -> RouteLookup {
        let HostResolution::Tenant(tenant) = routing.tenant_for(&host(on)) else {
            return RouteLookup::NotFound;
        };
        let Some(table) = routing.tenant(&tenant) else {
            return RouteLookup::NotFound;
        };
        let headers = http::HeaderMap::new();
        let path = CanonicalPath::new(path).unwrap();
        let on = host(on);
        table.routes().find(&RouteQuery {
            host: &on,
            method: HttpMethod::Get,
            path: &path,
            values: &RequestHeaders::new(&headers),
        })
    }

    #[test]
    fn nothing_is_served_before_the_first_install() {
        assert_eq!(
            Routing::default().tenant_for(&host("shop.acme.com")),
            HostResolution::Unknown
        );
    }

    #[test]
    fn an_installed_tenant_is_found_by_host_and_route() {
        let acme = hosted("acme", &["shop.acme.com"]);

        let routing = Routing::default().with_tenant(&acme, &table_on("/api/*"), &base());

        assert!(matches!(
            routes_on(&routing, "shop.acme.com", "/api/orders"),
            RouteLookup::Found(_)
        ));
        assert!(matches!(
            routes_on(&routing, "acme-prod.zero.test", "/api/orders"),
            RouteLookup::NotFound
        ));
    }

    /// Withdrawing an installed tenant removes both its host resolution and
    /// its stored routing table.
    #[test]
    fn a_withdrawn_tenant_resolves_to_nobody_and_its_routes_are_gone() {
        let acme = hosted("acme", &["shop.acme.com"]);
        let routing = Routing::default().with_tenant(&acme, &table_on("/api/*"), &base());

        let after = routing.without_tenant(&acme.tenant_id, &base());

        assert_eq!(
            after.tenant_for(&host("shop.acme.com")),
            HostResolution::Unknown
        );
        let scoped = ScopedTenant::from_request_host(acme.tenant_id);
        assert!(after.tenant(&scoped).is_none());
    }

    /// A reinstall replaces the tenant whole: a domain it no longer lists
    /// stops resolving, and its old routes go.
    #[test]
    fn a_reinstall_replaces_the_tenant_whole() {
        let acme = hosted("acme", &["old.acme.com"]);
        let routing = Routing::default().with_tenant(&acme, &table_on("/old/*"), &base());
        let moved = HostedTenant {
            domains: vec![DomainName::new("new.acme.com").unwrap()],
            ..acme.clone()
        };

        let after = routing.with_tenant(&moved, &table_on("/new/*"), &base());

        assert_eq!(
            after.tenant_for(&host("old.acme.com")),
            HostResolution::Unknown
        );
        assert!(matches!(
            routes_on(&after, "new.acme.com", "/old/x"),
            RouteLookup::NotFound
        ));
        assert!(matches!(
            routes_on(&after, "new.acme.com", "/new/x"),
            RouteLookup::Found(_)
        ));
    }

    /// Withdrawing one tenant leaves a name another tenant now holds alone
    /// to that tenant, and installing a second claimant makes it ambiguous.
    #[test]
    fn a_name_is_ambiguous_only_while_two_tenants_claim_it() {
        let first = hosted("first", &["shop.acme.com"]);
        let second = hosted("second", &["shop.acme.com"]);
        let both = Routing::default()
            .with_tenant(&first, &table_on("/*"), &base())
            .with_tenant(&second, &table_on("/*"), &base());

        let one_left = both.without_tenant(&first.tenant_id, &base());

        assert_eq!(
            both.tenant_for(&host("shop.acme.com")),
            HostResolution::Ambiguous
        );
        assert_eq!(
            one_left.tenant_for(&host("shop.acme.com")),
            HostResolution::Tenant(ScopedTenant::from_request_host(second.tenant_id))
        );
    }
}
