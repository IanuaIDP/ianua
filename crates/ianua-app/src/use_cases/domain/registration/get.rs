//! Get domain: one of the tenant's registered domains, with the certificate
//! it serves.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::{DomainAction, SystemPermission};
use ianua_domain::domains::tenant::custom_domains::registered_domain::RegisteredDomain;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::DomainId;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::domain::{CertificateStore, RegisteredDomainStore};
use crate::use_case::Query;
use crate::use_cases::domain::certificates::detail::CertificateDetail;
use crate::use_cases::domain::lookup::existing_domain;

/// A registered domain and the certificate it serves, if any.
pub struct DomainDetail {
    /// The registration.
    pub domain: RegisteredDomain<ResolvedTenant>,
    /// The certificate it serves: where it came from, who renews it and
    /// when it runs out. `None` when it was never given one.
    pub certificate: Option<CertificateDetail>,
}

/// The ports [`GetDomainUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct GetDomainPorts {
    /// Loads the registration.
    pub domain_store: Arc<dyn RegisteredDomainStore>,
    /// Loads the certificate it serves.
    pub certificate_store: Arc<dyn CertificateStore>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Reads one of a tenant's domains with its certificate.
pub struct GetDomainUseCase {
    ports: GetDomainPorts,
}

impl GetDomainUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: GetDomainPorts) -> Self {
        Self { ports }
    }
}

impl Query for GetDomainUseCase {
    type Caller = CallerContext;
    type Input = DomainId;
    type Output = Result<DomainDetail, AppError>;

    /// The caller's tenant's domain `domain_id` and the detail of the
    /// certificate it serves, once they may view its domains. The
    /// certificate's key never leaves the store.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not view domains.
    /// - `AppError::NotFound` if the tenant has no such domain.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        caller: &CallerContext,
        domain_id: DomainId,
    ) -> Result<DomainDetail, AppError> {
        self.ports
            .tenant_authorities
            .authority(caller)
            .await?
            .ensure_holds(SystemPermission::Domains(DomainAction::View))
            .map_err(AppError::from_domain)?;
        let tenant = caller.tenant();
        let domain = existing_domain(self.ports.domain_store.as_ref(), &tenant, &domain_id).await?;
        let certificate = self
            .ports
            .certificate_store
            .find_current(&tenant, &domain_id)
            .await
            .or_internal()?;
        Ok(DomainDetail {
            domain,
            certificate: certificate.as_ref().map(CertificateDetail::from),
        })
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::tenant::custom_domains::certificate::Renewal;
    use ianua_domain::domains::tenant::custom_domains::verification_status::TlsStatus;
    use ianua_domain::shared::clock;
    use time::Duration;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::domain::{
        DomainSeed, FakeCertificateStore, FakeDomainStore, test_uploaded_certificate,
    };
    use crate::test_support::{block_on, test_ctx};

    const HOST: &str = "auth.acme.test";

    struct Fixture {
        use_case: GetDomainUseCase,
        certificates: Arc<FakeCertificateStore>,
        id: DomainId,
    }

    fn fixture_with(authorities: FakeTenantAuthorities) -> Fixture {
        let domain = DomainSeed::verified(HOST).tls(TlsStatus::Active).build();
        let id = *domain.id();
        let certificates = Arc::new(FakeCertificateStore::empty());
        let use_case = GetDomainUseCase::new(GetDomainPorts {
            domain_store: Arc::new(FakeDomainStore::holding(test_ctx().tenant_id(), [domain])),
            certificate_store: certificates.clone(),
            tenant_authorities: Arc::new(authorities),
        });
        Fixture {
            use_case,
            certificates,
            id,
        }
    }

    fn fixture() -> Fixture {
        fixture_with(FakeTenantAuthorities::holding_everything())
    }

    fn get(f: &Fixture, id: DomainId) -> Result<DomainDetail, AppError> {
        block_on(f.use_case.execute(&test_ctx(), id))
    }

    /// Ann reads Acme's domain, which serves the certificate Acme uploaded,
    /// running out in twenty days. She sees the tenant renews it and how
    /// long it has left.
    #[test]
    fn a_domain_is_read_with_the_certificate_it_serves() {
        let f = fixture();
        let cert = test_uploaded_certificate(f.id, HOST, clock::now() + Duration::days(20));
        block_on(f.certificates.save(&test_ctx().tenant(), &cert)).unwrap();

        let detail = get(&f, f.id).unwrap();

        let certificate = detail.certificate.unwrap();
        assert_eq!(certificate.renewal, Renewal::ByTenant);
        assert!((19..=20).contains(&certificate.days_until_expiry));
        assert_eq!(detail.domain.domain().as_str(), HOST);
    }

    /// Acme's domain was never given a certificate. It is read with none.
    #[test]
    fn a_domain_without_a_certificate_is_read_with_none() {
        let f = fixture();

        let detail = get(&f, f.id).unwrap();

        assert!(detail.certificate.is_none());
    }

    /// Ann names a domain Acme does not have. It is not found.
    #[test]
    fn an_unknown_domain_is_not_found() {
        let f = fixture();

        let result = get(&f, DomainId::new());

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A caller without domain-viewing rights cannot read a registered
    /// hostname's details.
    #[test]
    fn a_caller_who_may_not_view_domains_is_refused() {
        let f = fixture_with(FakeTenantAuthorities::holding(&[]));

        let result = get(&f, f.id);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out session cannot read the tenant's domain details.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let f = fixture_with(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        let result = get(&f, f.id);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
