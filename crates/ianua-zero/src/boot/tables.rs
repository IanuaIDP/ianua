//! What the follower fills: the request path's tables and, beside them,
//! one pool of backends per service and the enrolled connectors every
//! connector link is judged against.
//!
//! A tenant's pools are reconciled before its tables are swapped in, so a
//! request that finds a route finds its service's pool too. A tenant
//! withdrawn loses its tables first and its pools after, so no request
//! starts on a route whose pool is gone. Its connectors are handed over
//! first of all, so a revoked connector's links close before anything
//! else of the tenant is rebuilt; a tenant withdrawn loses every link.

use std::sync::Arc;

use ianua_app::ports::proxy::ServedCertificate;
use ianua_domain::types::TenantId;

use crate::connectors::ConnectorLinks;
use crate::follow::{self, OpenedClientKey, TenantSnapshot};
use crate::forward::{ClientKey, ClientKeys, ServicePools};
use crate::resolve::Tables;

/// The request path's tables, the services' pools and the connectors'
/// links, filled together.
pub(crate) struct ServedTables {
    tables: Arc<Tables>,
    pools: Arc<ServicePools>,
    links: Arc<ConnectorLinks>,
}

impl ServedTables {
    /// `tables`, `pools` and `links`, filled together.
    #[must_use]
    pub(crate) fn new(
        tables: Arc<Tables>,
        pools: Arc<ServicePools>,
        links: Arc<ConnectorLinks>,
    ) -> Self {
        Self {
            tables,
            pools,
            links,
        }
    }
}

impl follow::Tables for ServedTables {
    /// Builds the tenant's pools, then serves its tables. A service that
    /// presents a client certificate to its backends gets a pool only with
    /// its key; without one its routes are refused.
    fn install(&self, mut snapshot: TenantSnapshot) {
        let tenant = snapshot.hosted.tenant_id;
        self.links
            .install(tenant, std::mem::take(&mut snapshot.connectors));
        let keys = client_keys(std::mem::take(&mut snapshot.client_keys));
        self.pools
            .reconcile_tenant(tenant, &snapshot.services, &keys);
        self.tables.install(snapshot);
    }

    fn withdraw(&self, tenant: &TenantId) {
        self.links.withdraw(tenant);
        self.tables.withdraw(tenant);
        self.pools.drop_tenant(*tenant);
    }

    fn install_certificates(&self, certificates: Vec<ServedCertificate>) {
        self.tables.install_certificates(certificates);
    }
}

/// The keys `opened` holds, as the pools present them. A key that is no
/// private key leaves its service without one, named in the log.
fn client_keys(opened: Vec<OpenedClientKey>) -> ClientKeys {
    let mut keys = ClientKeys::none();
    for OpenedClientKey { service_id, pem } in opened {
        match ClientKey::from_pem(pem.expose().as_bytes()) {
            Ok(key) => keys.insert(service_id, key),
            Err(error) => tracing::warn!(
                %service_id,
                %error,
                "a service's client key is no private key; its routes are refused"
            ),
        }
    }
    keys
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use ianua_app::ports::pages::ErrorBranding;
    use ianua_app::ports::proxy::HostedTenant;
    use ianua_app::test_support::routing::{pinned_upstream, service_named};
    use ianua_domain::domains::routing::backend::tls::{
        UpstreamClientCertificate, UpstreamTls, UpstreamTlsParams, UpstreamTrust,
    };
    use ianua_domain::domains::routing::connector::ConnectorStatus;
    use ianua_domain::domains::routing::connector::scope::ConnectorScope;
    use ianua_domain::domains::routing::connector::tunnel::{ConnectorTunnel, ConnectorTunnelRow};
    use ianua_domain::domains::routing::service::Service;
    use ianua_domain::domains::tenant::access::network_security::MtlsConfig;
    use ianua_domain::domains::tenant::hosts::{
        PlatformAddressing, PlatformLabel, ReadableAddress,
    };
    use ianua_domain::isolation::scope::ResolvedTenant;
    use ianua_domain::shared::security::secret::Secret;
    use ianua_domain::shared::security::ssrf::UpstreamNetworks;
    use ianua_domain::types::{
        CertificatePem, ConnectorId, DisplayName, DomainName, Issuer, OrganizationId, PublicKeyPin,
        SealedSecret, ServiceId, Setting, TenantSlug,
    };
    use ianua_infra::cache::{CacheBackendHealthReports, MemoryState};
    use ianua_infra::crypto::ConnectorIdentity;
    use ianua_infra::dns::DnsBackendDiscovery;
    use tokio_rustls::rustls::crypto::ring;
    use tokio_util::sync::CancellationToken;

    use super::*;
    use crate::connectors::LinkLimits;
    use crate::follow::Tables as _;
    use crate::forward::{
        Clients, DiscoverySettings, DiscoveryWatch, ForwardError, ForwardSettings, HealthChecks,
        ProbeSettings, TunnelLimits,
    };
    use crate::listen::{CertificateTable, ClientAuthTable};
    use crate::resolve::TablesParts;

    fn links() -> Arc<ConnectorLinks> {
        Arc::new(ConnectorLinks::new(LinkLimits {
            max_links: 4,
            links_per_connector: 2,
            streams_per_link: 4,
            handshake: Duration::from_secs(1),
            open: Duration::from_secs(1),
            keepalive: Duration::from_secs(5),
            sighting: Duration::from_secs(60),
        }))
    }

    fn pools() -> Arc<ServicePools> {
        let settings = forward_settings();
        let reports = Arc::new(CacheBackendHealthReports::new(Arc::new(MemoryState::new(
            100,
        ))));
        Arc::new(ServicePools::new(
            Clients::new(&settings, links()).unwrap(),
            HealthChecks::new(
                CancellationToken::new(),
                ProbeSettings {
                    max_in_flight: std::num::NonZeroUsize::MIN,
                },
                reports,
            ),
            Arc::new(DiscoveryWatch::new(
                Arc::new(DnsBackendDiscovery::new(Duration::from_secs(1))),
                DiscoverySettings {
                    tick: Duration::from_secs(1),
                    lookup_timeout: Duration::from_secs(1),
                    max_in_flight: std::num::NonZeroUsize::MIN,
                },
            )),
        ))
    }

    /// Public backends and short bounded connections keep the pool fixtures isolated.
    fn forward_settings() -> ForwardSettings {
        ForwardSettings {
            networks: UpstreamNetworks::public_only(),
            connect_timeout: Duration::from_secs(1),
            response_deadline: Duration::from_secs(1),
            long_lived_idle: Duration::from_secs(1),
            pool_idle_timeout: Duration::from_secs(1),
            pool_max_idle_per_backend: 1,
            tunnels: TunnelLimits {
                max_open: std::num::NonZeroUsize::MIN,
                lifetime: Duration::from_secs(1),
                idle: Duration::from_secs(1),
                recheck_every: Duration::from_secs(1),
                recheck_timeout: Duration::from_secs(1),
            },
        }
    }

    fn served(pools: &Arc<ServicePools>) -> ServedTables {
        served_with(pools, links())
    }

    fn served_with(pools: &Arc<ServicePools>, links: Arc<ConnectorLinks>) -> ServedTables {
        let provider = Arc::new(ring::default_provider());
        let tables = Tables::new(TablesParts {
            addressing: PlatformAddressing::Nested,
            base_domain: DomainName::new("apps.example.com").unwrap(),
            client_auth: Arc::new(ClientAuthTable::new(Arc::clone(&provider))),
            certificates: Arc::new(CertificateTable::new(provider, &[]).unwrap()),
        });
        ServedTables::new(Arc::new(tables), Arc::clone(pools), links)
    }

    /// A certificate the payroll service presents, and its key as PEM.
    fn client_certificate() -> (CertificatePem, String) {
        let key = rcgen::KeyPair::generate().unwrap();
        let params = rcgen::CertificateParams::new(vec!["gateway.internal".to_owned()]).unwrap();
        let certificate = params.self_signed(&key).unwrap();
        (
            CertificatePem::new(certificate.pem()).unwrap(),
            key.serialize_pem(),
        )
    }

    /// Payroll, presenting `certificate` to its backend, its key sealed.
    fn payroll(certificate: CertificatePem) -> Service<ResolvedTenant> {
        let tls = UpstreamTls::new(UpstreamTlsParams {
            trust: UpstreamTrust::PublicRoots,
            client_certificate: Setting::Set(UpstreamClientCertificate::new(
                certificate,
                SealedSecret::new("v1.sealed-client-key").unwrap(),
            )),
            server_name: Setting::Unset,
        })
        .unwrap();
        let upstream = pinned_upstream("https://payroll.example.com", "payroll").with_tls(tls);
        service_named("payroll", upstream)
    }

    /// Payroll needs its key for a pool: without it payroll's routes are
    /// refused, never called without the certificate; with it payroll is
    /// served.
    #[tokio::test]
    async fn a_service_presenting_a_certificate_is_pooled_only_with_its_key() {
        let pools = pools();
        let served = served(&pools);
        let tenant = TenantId::new();
        let (certificate, key) = client_certificate();
        let service = payroll(certificate);
        let id: ServiceId = *service.id();

        served.install(snapshot(tenant, &service));
        let without_key = pools.pool(tenant, &id);
        let mut keyed = snapshot(tenant, &service);
        keyed.client_keys = vec![OpenedClientKey {
            service_id: id,
            pem: Secret::new(key),
        }];
        served.install(keyed);
        let with_key = pools.pool(tenant, &id);

        assert!(matches!(without_key, Err(ForwardError::NoPool)));
        assert!(with_key.is_ok());
    }

    fn snapshot(tenant: TenantId, service: &Service<ResolvedTenant>) -> TenantSnapshot {
        TenantSnapshot {
            hosted: HostedTenant {
                platform_label: PlatformLabel::new(
                    tenant.as_uuid().simple().to_string()[16..].to_owned(),
                )
                .unwrap(),
                readable_address: ReadableAddress::Off,
                tenant_id: tenant,
                organization_slug: TenantSlug::try_from("acme-org".to_owned()).unwrap(),
                slug: TenantSlug::try_from("acme".to_owned()).unwrap(),
                domains: Vec::new(),
            },
            organization: OrganizationId::new(),
            issuer: Issuer::new("https://app.example.com/t/acme-org/acme").unwrap(),
            branding: ErrorBranding {
                name: DisplayName::try_from("Acme".to_owned()).unwrap(),
                logo_url: None,
                primary_color: None,
                background_color: None,
            },
            mtls: MtlsConfig::disabled(),
            routes: Vec::new(),
            services: vec![service.clone()],
            pipelines: Vec::new(),
            client_keys: Vec::new(),
            connectors: Vec::new(),
        }
    }

    /// A tenant installed has a pool for each of its services, and loses
    /// them once withdrawn, so no request reaches a backend of a tenant no
    /// longer served.
    #[tokio::test]
    async fn a_tenants_pools_follow_its_tables() {
        let pools = pools();
        let served = served(&pools);
        let tenant = TenantId::new();
        let service = service_named("app", pinned_upstream("https://backend.example.com", "app"));
        let id: ServiceId = *service.id();

        served.install(snapshot(tenant, &service));
        let while_served = pools.pool(tenant, &id).is_ok();
        served.withdraw(&tenant);
        let after = pools.pool(tenant, &id);

        assert!(while_served);
        assert!(matches!(after, Err(ForwardError::NoPool)));
    }

    /// Acme's connector is handed over with its tenant, so its link is let
    /// in, and taken away when the tenant is withdrawn, so it no longer is.
    #[tokio::test]
    async fn a_tenants_connectors_follow_its_tables() {
        let links = links();
        let served = served_with(&pools(), Arc::clone(&links));
        let tenant = TenantId::new();
        let key = PublicKeyPin::from_digest([4; 32]);
        let connector = ConnectorTunnel::reconstitute(ConnectorTunnelRow {
            id: ConnectorId::new(),
            scope: ConnectorScope::new(
                Vec::new(),
                vec![DomainName::new("wiki.corp.internal").unwrap()],
            )
            .unwrap(),
            key,
            status: ConnectorStatus::Active,
        })
        .unwrap();
        let identity = ConnectorIdentity {
            tenant,
            connector: *connector.id(),
            key,
        };
        let service = service_named("app", pinned_upstream("https://backend.example.com", "app"));
        let mut installed = snapshot(tenant, &service);
        installed.connectors = vec![connector];

        served.install(installed);
        let while_served = links.admits(&identity);
        served.withdraw(&tenant);

        assert!(while_served.is_ok());
        assert!(links.admits(&identity).is_err());
    }
}
