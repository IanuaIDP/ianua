//! Change service TLS: set how the gateway opens TLS to a service's
//! upstream on a private PKI, or go back to the public roots.

use std::sync::Arc;

use ianua_domain::domains::routing::backend::upstream::Upstream;
use ianua_domain::domains::routing::control::{RoutingControl, RoutingRight};
use ianua_domain::domains::routing::service::Service;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{ServiceId, Setting};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::authentication::SecretEncryptor;
use crate::ports::routing::{RouteStore, ServiceStore};
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::routing::lookup::{existing_service, routes_to};
use crate::use_cases::routing::services::upstream_tls::{
    UpstreamTlsRequest, client_key_place, sealed_tls,
};

/// A service's new upstream TLS.
pub struct ChangeTlsRequest {
    /// The service to change.
    pub service_id: ServiceId,
    /// The TLS to open to its upstream, or unset to trust the public roots
    /// with no client certificate and no server name of its own.
    pub tls: Setting<UpstreamTlsRequest>,
}

/// The ports [`ChangeTlsUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ChangeTlsPorts {
    /// Keeps the tenant's services.
    pub service_store: Arc<dyn ServiceStore>,
    /// The tenant's routes, each of which must still work with the
    /// service's changed upstream.
    pub route_store: Arc<dyn RouteStore>,
    /// Seals the client certificate's private key.
    pub encryptor: Arc<dyn SecretEncryptor>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Changes how the gateway opens TLS to a service's upstream.
pub struct ChangeTlsUseCase {
    ports: ChangeTlsPorts,
}

impl ChangeTlsUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: ChangeTlsPorts) -> Self {
        Self { ports }
    }

    /// The upstream of `tenant`'s `service` with `tls` in place of the TLS
    /// it has.
    ///
    /// # Errors
    ///
    /// - `AppError::Domain` when the server name is a wildcard.
    /// - `AppError::Internal` when the key cannot be sealed.
    async fn upstream_with(
        &self,
        tenant: &ScopedTenant,
        service: &Service<ResolvedTenant>,
        tls: Setting<UpstreamTlsRequest>,
    ) -> Result<Upstream, AppError> {
        let Setting::Set(tls) = tls else {
            return Ok(service.upstream().without_tls());
        };
        let place = client_key_place(tenant, service.id());
        let sealed = sealed_tls(self.ports.encryptor.as_ref(), tls, &place).await?;
        Ok(service.upstream().clone().with_tls(sealed))
    }
}

impl Command for ChangeTlsUseCase {
    type Caller = CallerContext;
    type Input = ChangeTlsRequest;
    type Output = Result<(), AppError>;

    /// Replaces the service's upstream TLS and records
    /// `routing.service_updated`. A client key given is stored sealed, and
    /// is in no event.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not update routing.
    /// - `AppError::NotFound` if the service doesn't exist.
    /// - `AppError::Domain` if the server name is a wildcard, or TLS is set
    ///   while a backend is reached over plain `http://`.
    /// - `AppError::Internal` on storage, sealing or audit failure.
    async fn execute(
        &self,
        caller: &CallerContext,
        auditor: &RequestAuditor,
        request: ChangeTlsRequest,
    ) -> Result<(), AppError> {
        let authority = self.ports.tenant_authorities.authority(caller).await?;
        let by = RoutingControl::new(&authority);
        by.ensure_may(RoutingRight::Update)
            .map_err(AppError::from_domain)?;
        let tenant = caller.tenant();
        let store = self.ports.service_store.as_ref();
        let mut service = existing_service(store, &tenant, &request.service_id).await?;
        let upstream = self.upstream_with(&tenant, &service, request.tls).await?;
        let routes = routes_to(self.ports.route_store.as_ref(), &tenant, service.id()).await?;
        service
            .replace_upstream(upstream, &routes, &by)
            .map_err(AppError::from_domain)?;
        store
            .save(&tenant, &service)
            .await
            .map_err(AppError::from_domain)?;
        auditor
            .dispatch_by(&caller.actor(), service.take_events(&tenant))
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{RoutingAction, SystemPermission};
    use ianua_domain::domains::routing::backend::tls::{
        UpstreamTls, UpstreamTlsParams, UpstreamTrust,
    };
    use ianua_domain::shared::security::secret::Secret;
    use ianua_domain::types::{CertificatePem, DomainName};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authentication::FakeEncryptor;
    use crate::test_support::domain::{TEST_CERTIFICATE_PEM, TEST_PRIVATE_KEY_PEM};
    use crate::test_support::routing::{FakeServiceStore, pinned_upstream, service_named};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};
    use crate::use_cases::routing::services::upstream_tls::ClientCertificateRequest;

    /// The store, the audit record, the use case a test runs, and the
    /// service it holds.
    struct Fixture {
        services: Arc<FakeServiceStore>,
        audit: Arc<FakeEventDispatcher>,
        use_case: ChangeTlsUseCase,
        service: ServiceId,
    }

    /// A fixture holding the `api` service at `upstream`, the caller
    /// holding what `authorities` says.
    fn fixture_over(upstream: Upstream, authorities: FakeTenantAuthorities) -> Fixture {
        let service = service_named("api", upstream);
        let services = Arc::new(FakeServiceStore::empty());
        block_on(services.save(&test_ctx().tenant(), &service)).unwrap();
        Fixture {
            use_case: ChangeTlsUseCase::new(ChangeTlsPorts {
                service_store: services.clone(),
                tenant_authorities: Arc::new(authorities),
                ..ChangeTlsPorts::fakes()
            }),
            services,
            audit: Arc::new(FakeEventDispatcher::new()),
            service: *service.id(),
        }
    }

    /// The `api` service over HTTPS, pinned to `client`.
    fn api() -> Upstream {
        pinned_upstream("https://api.corp.example.com", "client")
    }

    /// A fixture holding the `api` service, run by a routing admin.
    fn fixture() -> Fixture {
        fixture_over(api(), FakeTenantAuthorities::holding_everything())
    }

    /// TLS to a private CA under `server_name`, presenting the test client
    /// certificate.
    fn private_tls(server_name: &str) -> UpstreamTlsRequest {
        UpstreamTlsRequest {
            trust: UpstreamTrust::PrivateCa(CertificatePem::new(TEST_CERTIFICATE_PEM).unwrap()),
            client_certificate: Setting::Set(ClientCertificateRequest {
                certificate: CertificatePem::new(TEST_CERTIFICATE_PEM).unwrap(),
                private_key: Secret::new(TEST_PRIVATE_KEY_PEM),
            }),
            server_name: Setting::Set(DomainName::new(server_name).unwrap()),
        }
    }

    /// Changes the service `id` to `tls`.
    fn change(
        f: &Fixture,
        id: ServiceId,
        tls: Setting<UpstreamTlsRequest>,
    ) -> Result<(), AppError> {
        block_on(f.use_case.execute(
            &test_ctx(),
            &test_auditor(f.audit.clone()),
            ChangeTlsRequest {
                service_id: id,
                tls,
            },
        ))
    }

    /// The fixture's service as stored.
    fn saved(f: &Fixture) -> Service<ResolvedTenant> {
        block_on(f.services.find_by_id(&test_ctx().tenant(), &f.service))
            .unwrap()
            .unwrap()
    }

    /// Ann's backend moves to the company PKI and asks for a client
    /// certificate. The service trusts the CA, sends the internal name, and
    /// keeps the key only sealed. The change is recorded.
    #[test]
    fn private_tls_is_saved_with_the_key_sealed() {
        let f = fixture();

        change(
            &f,
            f.service,
            Setting::Set(private_tls("api.corp.internal")),
        )
        .unwrap();

        let service = saved(&f);
        let tls = service.upstream().tls().unwrap();
        assert!(matches!(tls.trust(), UpstreamTrust::PrivateCa(_)));
        assert_eq!(
            *tls.client_certificate().unwrap().private_key(),
            FakeEncryptor::sealed_for(
                TEST_PRIVATE_KEY_PEM,
                &client_key_place(&test_ctx().tenant(), &f.service)
            )
        );
        assert_eq!(
            *f.audit.records.lock().unwrap(),
            ["routing.service_updated"]
        );
    }

    /// Ann goes back to the public roots. The TLS settings are gone and
    /// the rest of the upstream, its audience among them, stays.
    #[test]
    fn unsetting_tls_keeps_the_rest_of_the_upstream() {
        let named = UpstreamTls::new(UpstreamTlsParams {
            trust: UpstreamTrust::PublicRoots,
            client_certificate: Setting::Unset,
            server_name: Setting::Set(DomainName::new("api.corp.internal").unwrap()),
        })
        .unwrap();
        let f = fixture_over(
            api().with_tls(named),
            FakeTenantAuthorities::holding_everything(),
        );

        change(&f, f.service, Setting::Unset).unwrap();

        assert_eq!(*saved(&f).upstream(), api());
    }

    /// A wildcard TLS server name is refused, leaving TLS settings absent
    /// and recording no service update.
    #[test]
    fn a_wildcard_server_name_is_refused() {
        let f = fixture();

        let result = change(&f, f.service, Setting::Set(private_tls("*.corp.internal")));

        assert!(matches!(result, Err(AppError::Domain(_))), "{result:?}");
        assert!(saved(&f).upstream().tls().is_none());
        assert!(f.audit.records.lock().unwrap().is_empty());
    }

    /// Setting private TLS on a plain HTTP backend is refused and leaves its
    /// saved TLS settings absent.
    #[test]
    fn tls_on_a_plain_http_backend_is_refused() {
        let f = fixture_over(
            pinned_upstream("http://api.corp.example.com", "client"),
            FakeTenantAuthorities::holding_everything(),
        );

        let result = change(
            &f,
            f.service,
            Setting::Set(private_tls("api.corp.internal")),
        );

        assert!(matches!(result, Err(AppError::Domain(_))), "{result:?}");
        assert!(saved(&f).upstream().tls().is_none());
    }

    /// Ann names a service the tenant does not have. It is not found.
    #[test]
    fn an_unknown_service_is_not_found() {
        let f = fixture();

        let result = change(&f, ServiceId::new(), Setting::Unset);

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A routing viewer cannot configure private TLS for a service. The
    /// refusal leaves TLS settings absent and records no update event.
    #[test]
    fn a_caller_without_the_update_right_is_refused() {
        let f = fixture_over(
            api(),
            FakeTenantAuthorities::holding(&[SystemPermission::Routing(RoutingAction::View)]),
        );

        let result = change(
            &f,
            f.service,
            Setting::Set(private_tls("api.corp.internal")),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(saved(&f).upstream().tls().is_none());
        assert!(f.audit.records.lock().unwrap().is_empty());
    }

    /// A signed-out session cannot change service TLS settings.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let f = fixture_over(api(), FakeTenantAuthorities::refusing(Refusal::SignedOut));

        let result = change(&f, f.service, Setting::Unset);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
