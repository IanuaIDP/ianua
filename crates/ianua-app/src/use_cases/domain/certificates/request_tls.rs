//! Request TLS: ask for a verified domain's certificate.
//!
//! Issuance talks to a certificate authority and waits for a proof to become
//! visible, which takes longer than a request should, so the request only
//! queues it. The worker issues the certificate through
//! [`ProvisionTlsUseCase`](crate::use_cases::domain::certificates::ProvisionTlsUseCase)
//! and retries an authority that cannot see the proof yet.

use std::sync::Arc;

use ianua_domain::domains::tenant::control::{TenantArea, TenantControl};
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::DomainId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::domain::RegisteredDomainStore;
use crate::use_case::Command;
use crate::use_cases::domain::certificates::provision_tls::ensure_awaiting_certificate;
use crate::use_cases::domain::lookup::existing_domain;
use crate::use_cases::domain::verification::verified::{CertificateQueue, queue_certificate};

/// The ports [`RequestTlsUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RequestTlsPorts {
    /// Loads the domain the certificate is for.
    pub domain_store: Arc<dyn RegisteredDomainStore>,
    /// Queues the job that issues the certificate.
    pub certificates: CertificateQueue,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Asks for a verified domain's TLS certificate.
pub struct RequestTlsUseCase {
    ports: RequestTlsPorts,
}

impl RequestTlsUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: RequestTlsPorts) -> Self {
        Self { ports }
    }
}

impl Command for RequestTlsUseCase {
    type Caller = CallerContext;
    type Input = DomainId;
    type Output = Result<(), AppError>;

    /// Queues the certificate for the caller's verified domain and records
    /// `tenant.domain_tls_requested`. The domain itself is not changed here;
    /// it serves the certificate once the worker has issued it.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not change the tenant's
    ///   domains.
    /// - `AppError::NotFound` if the tenant has no such domain.
    /// - `AppError::Conflict` if the domain is not verified, or its
    ///   certificate is already active.
    /// - `AppError::Internal` if the job cannot be queued or the request
    ///   cannot be recorded.
    async fn execute(
        &self,
        caller: &CallerContext,
        auditor: &RequestAuditor,
        domain_id: DomainId,
    ) -> Result<(), AppError> {
        let authority = self.ports.tenant_authorities.authority(caller).await?;
        TenantControl::new(&authority)
            .ensure_may(&caller.tenant_id(), TenantArea::Domains)
            .map_err(AppError::from_domain)?;
        let mut domain = existing_domain(
            self.ports.domain_store.as_ref(),
            &caller.tenant(),
            &domain_id,
        )
        .await?;
        ensure_awaiting_certificate(&domain)?;
        domain
            .request_certificate()
            .map_err(AppError::from_domain)?;

        queue_certificate(&self.ports.certificates, &caller.tenant_id(), &domain).await?;
        auditor
            .dispatch_by(&caller.actor(), domain.take_events(&caller.tenant()))
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{DomainAction, SystemPermission};
    use ianua_domain::domains::tenant::custom_domains::registered_domain::RegisteredDomain;
    use ianua_domain::isolation::scope::ResolvedTenant;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::domain::{DomainSeed, FakeDomainStore, certificates};
    use crate::test_support::scheduling::FakeJobQueue;
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};
    use crate::use_cases::domain::verification::verified::PROVISION_TLS_JOB;

    struct Fixture {
        use_case: RequestTlsUseCase,
        queue: Arc<FakeJobQueue>,
        audit: Arc<FakeEventDispatcher>,
    }

    fn fixture_with(
        domain: RegisteredDomain<ResolvedTenant>,
        authorities: FakeTenantAuthorities,
    ) -> Fixture {
        let queue = Arc::new(FakeJobQueue::new());
        let use_case = RequestTlsUseCase::new(RequestTlsPorts {
            domain_store: Arc::new(FakeDomainStore::holding(test_ctx().tenant_id(), [domain])),
            certificates: certificates(queue.clone()),
            tenant_authorities: Arc::new(authorities),
        });
        Fixture {
            use_case,
            queue,
            audit: Arc::new(FakeEventDispatcher::new()),
        }
    }

    fn request(f: &Fixture, domain_id: DomainId) -> Result<(), AppError> {
        block_on(
            f.use_case
                .execute(&test_ctx(), &test_auditor(f.audit.clone()), domain_id),
        )
    }

    fn verified_with(authorities: FakeTenantAuthorities) -> (Fixture, DomainId) {
        let domain = DomainSeed::verified("auth.acme.test").build();
        let id = *domain.id();
        (fixture_with(domain, authorities), id)
    }

    /// Ann asks for the certificate of Acme's verified domain. The job is
    /// queued and the request recorded.
    #[test]
    fn a_verified_domain_has_its_certificate_queued_and_the_request_recorded() {
        let (f, id) = verified_with(FakeTenantAuthorities::holding_everything());

        request(&f, id).unwrap();

        assert!(f.queue.holds(PROVISION_TLS_JOB));
        assert_eq!(
            f.audit.records.lock().unwrap()[0],
            "tenant.domain_tls_requested"
        );
    }

    /// Acme's domain is not verified yet. The request is refused and nothing
    /// is queued.
    #[test]
    fn an_unverified_domain_is_refused_and_nothing_is_queued() {
        let domain = DomainSeed::pending("auth.acme.test").build();
        let id = *domain.id();
        let f = fixture_with(domain, FakeTenantAuthorities::holding_everything());

        let result = request(&f, id);

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert_eq!(f.queue.count(), 0);
    }

    /// Ann names a domain Acme does not have. It is not found.
    #[test]
    fn an_unknown_domain_is_not_found() {
        let (f, _) = verified_with(FakeTenantAuthorities::holding_everything());

        let result = request(&f, DomainId::new());

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Domain-viewing rights cannot request a certificate; the forbidden
    /// attempt leaves the job queue empty.
    #[test]
    fn a_caller_who_may_only_view_domains_is_refused() {
        let (f, id) = verified_with(FakeTenantAuthorities::holding(&[
            SystemPermission::Domains(DomainAction::View),
        ]));

        let result = request(&f, id);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(f.queue.count(), 0);
    }

    /// A signed-out session cannot request TLS for a verified domain.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let (f, id) = verified_with(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        let result = request(&f, id);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
