//! Remove certificate: stop serving the certificate a tenant uploaded for
//! one of its domains.
//!
//! The name then serves no certificate until the tenant uploads another or
//! asks for one through ACME, which
//! [`RequestTlsUseCase`](crate::use_cases::domain::certificates::RequestTlsUseCase)
//! does.

use std::sync::Arc;

use ianua_domain::domains::tenant::control::{TenantArea, TenantControl};
use ianua_domain::domains::tenant::custom_domains::certificate::CertificateBundle;
use ianua_domain::domains::tenant::custom_domains::registered_domain::RegisteredDomain;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::DomainId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::domain::{CertificateStore, RegisteredDomainStore};
use crate::ports::tenant::TenantStore;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::domain::lookup::{acting_tenant, existing_certificate, existing_domain};

/// The ports [`RemoveUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RemovePorts {
    /// Loads the domain, and saves it serving none.
    pub domain_store: Arc<dyn RegisteredDomainStore>,
    /// Loads the certificate the domain serves, and deletes it.
    pub certificate_store: Arc<dyn CertificateStore>,
    /// Loads the tenant the domain is registered in.
    pub tenants: Arc<dyn TenantStore>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Stops serving a certificate the tenant uploaded.
pub struct RemoveUseCase {
    ports: RemovePorts,
}

impl RemoveUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: RemovePorts) -> Self {
        Self { ports }
    }

    /// Deletes `current` and saves `domain` serving none.
    ///
    /// # Errors
    ///
    /// - `AppError::NotFound` when the certificate was deleted meanwhile.
    /// - `AppError::Internal` on persistence failure.
    async fn remove(
        &self,
        tenant: &ScopedTenant,
        domain: &RegisteredDomain<ResolvedTenant>,
        current: &CertificateBundle,
    ) -> Result<(), AppError> {
        let deleted = self
            .ports
            .certificate_store
            .delete(tenant, current.id())
            .await
            .or_internal()?;
        if !deleted {
            return Err(AppError::NotFound(message!(
                "directory-certificate-not-found",
                "certificate not found"
            )));
        }
        self.ports
            .domain_store
            .save(tenant, domain)
            .await
            .or_internal()
    }
}

impl Command for RemoveUseCase {
    type Caller = CallerContext;
    type Input = DomainId;
    type Output = Result<(), AppError>;

    /// Deletes the certificate the tenant uploaded for the caller's domain,
    /// leaves the domain serving none, and records
    /// `tenant.domain_certificate_removed`.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `Forbidden` without domain-change rights.
    /// - `AppError::NotFound` for a missing tenant domain or certificate; `Conflict` for an ACME certificate.
    /// - `AppError::Domain` when no certificate is serving; `Internal` on persistence or audit failure.
    async fn execute(
        &self,
        caller: &CallerContext,
        auditor: &RequestAuditor,
        domain_id: DomainId,
    ) -> Result<(), AppError> {
        let authority = self.ports.tenant_authorities.authority(caller).await?;
        let control = TenantControl::new(&authority);
        control
            .ensure_may(&caller.tenant_id(), TenantArea::Domains)
            .map_err(AppError::from_domain)?;
        let tenant = caller.tenant();
        let scope = acting_tenant(self.ports.tenants.as_ref(), caller).await?;
        let store = self.ports.domain_store.as_ref();
        let mut domain = existing_domain(store, &tenant, &domain_id).await?;
        let current =
            existing_certificate(self.ports.certificate_store.as_ref(), &tenant, &domain_id)
                .await?;
        domain
            .remove_uploaded(&current, &scope, control)
            .map_err(AppError::from_domain)?;

        self.remove(&tenant, &domain, &current).await?;
        auditor
            .dispatch_by(&caller.actor(), domain.take_events(&tenant))
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{DomainAction, SystemPermission};
    use ianua_domain::domains::tenant::custom_domains::verification_status::TlsStatus;
    use ianua_domain::shared::clock;
    use time::Duration;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::domain::{
        DomainSeed, FakeCertificateStore, FakeDomainStore, test_certificate,
        test_uploaded_certificate,
    };
    use crate::test_support::tenant::{FakeTenantStore, test_tenant_for_ctx};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    const HOST: &str = "auth.acme.test";

    /// What Acme's domain serves in a test.
    #[derive(Clone, Copy)]
    enum Serving {
        Uploaded,
        Issued,
        Nothing,
    }

    struct Fixture {
        use_case: RemoveUseCase,
        domains: Arc<FakeDomainStore>,
        certificates: Arc<FakeCertificateStore>,
        audit: Arc<FakeEventDispatcher>,
        id: DomainId,
    }

    fn fixture_with(serving: Serving, authorities: FakeTenantAuthorities) -> Fixture {
        let domain = DomainSeed::verified(HOST).tls(TlsStatus::Active).build();
        let id = *domain.id();
        let domains = Arc::new(FakeDomainStore::holding(test_ctx().tenant_id(), [domain]));
        let certificates = Arc::new(FakeCertificateStore::empty());
        seed_certificate(&certificates, serving, id);
        let use_case = RemoveUseCase::new(RemovePorts {
            domain_store: domains.clone(),
            certificate_store: certificates.clone(),
            tenants: Arc::new(FakeTenantStore::holding(test_tenant_for_ctx())),
            tenant_authorities: Arc::new(authorities),
        });
        Fixture {
            use_case,
            domains,
            certificates,
            audit: Arc::new(FakeEventDispatcher::new()),
            id,
        }
    }

    /// Stores what `serving` says the domain `id` serves.
    fn seed_certificate(store: &FakeCertificateStore, serving: Serving, id: DomainId) {
        let expires_at = clock::now() + Duration::days(60);
        let cert = match serving {
            Serving::Uploaded => test_uploaded_certificate(id, HOST, expires_at),
            Serving::Issued => test_certificate(id, expires_at),
            Serving::Nothing => return,
        };
        block_on(store.save(&test_ctx().tenant(), &cert)).unwrap();
    }

    fn fixture(serving: Serving) -> Fixture {
        fixture_with(serving, FakeTenantAuthorities::holding_everything())
    }

    fn remove(f: &Fixture, id: DomainId) -> Result<(), AppError> {
        block_on(
            f.use_case
                .execute(&test_ctx(), &test_auditor(f.audit.clone()), id),
        )
    }

    fn nothing_changed(f: &Fixture) -> bool {
        f.certificates.count() == 1 && f.audit.records.lock().unwrap().is_empty()
    }

    /// Ann removes the certificate Acme uploaded. It is deleted, the domain
    /// has no certificate, rather than one that reads as lapsed, and the
    /// removal is recorded.
    #[test]
    fn an_uploaded_certificate_is_deleted_and_recorded() {
        let f = fixture(Serving::Uploaded);

        remove(&f, f.id).unwrap();

        assert_eq!(f.certificates.count(), 0);
        let domain = f.domains.domain_of(test_ctx().tenant_id(), &f.id).unwrap();
        assert_eq!(domain.tls_status(), TlsStatus::NoCertificate);
        assert_eq!(
            *f.audit.records.lock().unwrap(),
            vec!["tenant.domain_certificate_removed"]
        );
    }

    /// Acme's uploaded certificate lapsed yesterday, and Ann removes it. It
    /// is deleted, and the domain has no certificate.
    #[test]
    fn a_lapsed_uploaded_certificate_is_removed() {
        let domain = DomainSeed::verified(HOST).tls(TlsStatus::Expired).build();
        let id = *domain.id();
        let domains = Arc::new(FakeDomainStore::holding(test_ctx().tenant_id(), [domain]));
        let certificates = Arc::new(FakeCertificateStore::empty());
        let lapsed = test_uploaded_certificate(id, HOST, clock::now() - Duration::days(1));
        block_on(certificates.save(&test_ctx().tenant(), &lapsed)).unwrap();
        let f = Fixture {
            use_case: RemoveUseCase::new(RemovePorts {
                domain_store: domains.clone(),
                certificate_store: certificates.clone(),
                tenants: Arc::new(FakeTenantStore::holding(test_tenant_for_ctx())),
                tenant_authorities: Arc::new(FakeTenantAuthorities::holding_everything()),
            }),
            domains,
            certificates,
            audit: Arc::new(FakeEventDispatcher::new()),
            id,
        };

        remove(&f, f.id).unwrap();

        assert_eq!(f.certificates.count(), 0);
        let domain = f.domains.domain_of(test_ctx().tenant_id(), &f.id).unwrap();
        assert_eq!(domain.tls_status(), TlsStatus::NoCertificate);
    }

    /// Removing a platform-issued certificate conflicts with upload-only
    /// removal; the certificate remains and no removal is audited.
    #[test]
    fn an_issued_certificate_is_not_removed() {
        let f = fixture(Serving::Issued);

        let result = remove(&f, f.id);

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert!(nothing_changed(&f));
    }

    /// Acme's domain serves no certificate. There is none to remove.
    #[test]
    fn a_domain_serving_none_has_none_to_remove() {
        let f = fixture(Serving::Nothing);

        let result = remove(&f, f.id);

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(f.audit.records.lock().unwrap().is_empty());
    }

    /// Ann names a domain Acme does not have. It is not found.
    #[test]
    fn an_unknown_domain_is_not_found() {
        let f = fixture(Serving::Uploaded);

        let result = remove(&f, DomainId::new());

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(nothing_changed(&f));
    }

    /// Domain-viewing rights cannot remove an uploaded certificate; the
    /// forbidden attempt leaves it stored without an audit event.
    #[test]
    fn a_caller_who_may_only_view_domains_is_refused() {
        let f = fixture_with(
            Serving::Uploaded,
            FakeTenantAuthorities::holding(&[SystemPermission::Domains(DomainAction::View)]),
        );

        let result = remove(&f, f.id);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(nothing_changed(&f));
    }

    /// A signed-out session cannot remove the upload; its certificate
    /// remains stored and no removal is audited.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let f = fixture_with(
            Serving::Uploaded,
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
        );

        let result = remove(&f, f.id);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert!(nothing_changed(&f));
    }
}
