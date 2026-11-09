//! Verify domain: check the domain's DNS proof and, once it holds, mark the
//! domain verified.

use std::sync::Arc;

use ianua_domain::domains::tenant::control::{TenantArea, TenantControl};
use ianua_domain::domains::tenant::custom_domains::registered_domain::RegisteredDomain;
use ianua_domain::domains::tenant::custom_domains::verification_status::VerificationStatus;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::DomainId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::domain::{DnsResolver, RegisteredDomainStore};
use crate::ports::runtime::UnitOfWork;
use crate::services::kept_together::kept_together;
use crate::use_case::Command;
use crate::use_cases::domain::lookup::existing_domain;
use crate::use_cases::domain::verification::proof::{ProofRules, ProofSources, is_proven};
use crate::use_cases::domain::verification::recorded::save_and_record;
use crate::use_cases::domain::verification::verified::{CertificateQueue, request_certificate};

/// The ports [`VerifyDomainUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct VerifyDomainPorts {
    /// Loads and saves the registration.
    pub domain_store: Arc<dyn RegisteredDomainStore>,
    /// The DNS lookups that prove ownership (`TXT` or `NS`).
    pub dns_resolver: Arc<dyn DnsResolver>,
    /// Queues the certificate a newly verified domain is owed.
    pub certificates: CertificateQueue,
    /// Keeps the verified domain and the record of it together.
    pub unit_of_work: Arc<dyn UnitOfWork>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Checks a registered domain's DNS proof on the tenant's request.
pub struct VerifyDomainUseCase {
    ports: VerifyDomainPorts,
    rules: ProofRules,
}

impl VerifyDomainUseCase {
    /// A use case working through `ports`, accepting what `rules` say proves
    /// a domain.
    #[must_use]
    pub fn new(ports: VerifyDomainPorts, rules: ProofRules) -> Self {
        Self { ports, rules }
    }
}

impl Command for VerifyDomainUseCase {
    type Caller = CallerContext;
    type Input = DomainId;
    type Output = Result<VerificationStatus, AppError>;

    /// Checks the domain's proof and, once it holds, marks the domain
    /// verified, records `tenant.domain_verified` and asks for its
    /// certificate. Returns where the domain's proof stands.
    ///
    /// Only ever promotes. A check that does not find the proof leaves the
    /// domain where it was and records nothing, because "not there" and "not
    /// there yet" are the same answer: DNS caches the old answer for as long
    /// as its TTL says. Marking a lost proof belongs to the health check,
    /// which watches over time. A domain already verified is left as it is.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not change the tenant's
    ///   domains.
    /// - `AppError::NotFound` if the tenant has no such domain.
    /// - `AppError::Internal` on DNS, persistence or audit failure.
    async fn execute(
        &self,
        caller: &CallerContext,
        auditor: &RequestAuditor,
        domain_id: DomainId,
    ) -> Result<VerificationStatus, AppError> {
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
        if !newly_proven(&self.ports, caller, &domain, &self.rules).await? {
            return Ok(domain.verification_status());
        }

        domain.mark_verified().map_err(AppError::from_domain)?;
        let (store, tenant) = (self.ports.domain_store.as_ref(), caller.tenant());
        let saved = save_and_record(store, auditor, &tenant, &mut domain, Vec::new());
        kept_together(self.ports.unit_of_work.as_ref(), saved).await?;
        request_certificate(&self.ports.certificates, &caller.tenant_id(), &domain).await;
        Ok(domain.verification_status())
    }
}

/// Whether `domain` is not yet verified and its proof now holds.
async fn newly_proven(
    ports: &VerifyDomainPorts,
    caller: &CallerContext,
    domain: &RegisteredDomain<ResolvedTenant>,
    rules: &ProofRules,
) -> Result<bool, AppError> {
    if domain.verification_status() == VerificationStatus::Verified {
        return Ok(false);
    }
    let sources = ProofSources {
        resolver: ports.dns_resolver.as_ref(),
        domains: ports.domain_store.as_ref(),
        rules,
    };
    is_proven(sources, &caller.tenant(), domain)
        .await
        .or_internal()
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use ianua_domain::domains::authorization::permission::{DomainAction, SystemPermission};
    use ianua_domain::domains::tenant::custom_domains::dns_zone::{RecordName, TxtValue};
    use ianua_domain::shared::errors::DomainError;
    use ianua_domain::types::DomainName;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::domain::{
        AcceptingDnsResolver, DomainSeed, FakeDomainStore, RejectingDnsResolver, certificates,
    };
    use crate::test_support::scheduling::FakeJobQueue;
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};
    use crate::use_cases::domain::verification::verified::PROVISION_TLS_JOB;

    struct Fixture {
        use_case: VerifyDomainUseCase,
        domains: Arc<FakeDomainStore>,
        queue: Arc<FakeJobQueue>,
        audit: Arc<FakeEventDispatcher>,
    }

    struct Setup {
        domain: RegisteredDomain<ResolvedTenant>,
        resolver: Arc<dyn DnsResolver>,
        authorities: FakeTenantAuthorities,
    }

    fn fixture(setup: Setup) -> Fixture {
        let domains = Arc::new(FakeDomainStore::holding(
            test_ctx().tenant_id(),
            [setup.domain],
        ));
        let queue = Arc::new(FakeJobQueue::new());
        let use_case = VerifyDomainUseCase::new(
            VerifyDomainPorts {
                domain_store: domains.clone(),
                dns_resolver: setup.resolver,
                certificates: certificates(queue.clone()),
                tenant_authorities: Arc::new(setup.authorities),
                ..VerifyDomainPorts::fakes()
            },
            ProofRules::new(
                vec![DomainName::new("ns1.ianua.test").unwrap()],
                Default::default(),
            ),
        );
        Fixture {
            use_case,
            domains,
            queue,
            audit: Arc::new(FakeEventDispatcher::new()),
        }
    }

    fn checking(domain: RegisteredDomain<ResolvedTenant>, resolver: Arc<dyn DnsResolver>) -> Setup {
        Setup {
            domain,
            resolver,
            authorities: FakeTenantAuthorities::holding_everything(),
        }
    }

    fn verify(f: &Fixture, id: DomainId) -> Result<VerificationStatus, AppError> {
        block_on(
            f.use_case
                .execute(&test_ctx(), &test_auditor(f.audit.clone()), id),
        )
    }

    fn pending() -> RegisteredDomain<ResolvedTenant> {
        DomainSeed::pending("acme.test").build()
    }

    /// Ann published Acme's token and presses verify. The domain is
    /// verified, the verification recorded, and its certificate queued.
    #[test]
    fn a_published_proof_verifies_the_domain() {
        let domain = pending();
        let id = *domain.id();
        let f = fixture(checking(domain, Arc::new(AcceptingDnsResolver)));

        assert_eq!(verify(&f, id).unwrap(), VerificationStatus::Verified);
        assert_eq!(f.audit.records.lock().unwrap()[0], "tenant.domain_verified");
        assert!(f.queue.holds(PROVISION_TLS_JOB));
    }

    /// Ann presses verify minutes after publishing, before DNS has caught
    /// up. The domain stays pending and nothing is recorded; calling it
    /// failed would accuse her at the moment she most likely did nothing
    /// wrong.
    #[test]
    fn a_check_that_finds_no_proof_leaves_the_domain_pending() {
        let domain = pending();
        let id = *domain.id();
        let f = fixture(checking(domain, Arc::new(RejectingDnsResolver)));

        assert_eq!(verify(&f, id).unwrap(), VerificationStatus::Pending);
        assert!(f.audit.records.lock().unwrap().is_empty());
    }

    /// Acme's domain already serves traffic and one lookup misses. It stays
    /// verified; that judgement belongs to the health check.
    #[test]
    fn a_failed_check_never_downgrades_a_verified_domain() {
        let domain = DomainSeed::verified("acme.test").build();
        let id = *domain.id();
        let f = fixture(checking(domain, Arc::new(RejectingDnsResolver)));

        assert_eq!(verify(&f, id).unwrap(), VerificationStatus::Verified);
        assert_eq!(
            f.domains
                .domain_of(test_ctx().tenant_id(), &id)
                .unwrap()
                .verification_status(),
            VerificationStatus::Verified
        );
    }

    /// Acme's domain is already verified when Ann presses verify again.
    /// Nothing is recorded twice and no second certificate is asked for.
    #[test]
    fn a_verified_domain_is_not_verified_again() {
        let domain = DomainSeed::verified("acme.test").build();
        let id = *domain.id();
        let f = fixture(checking(domain, Arc::new(AcceptingDnsResolver)));

        verify(&f, id).unwrap();

        assert!(f.audit.records.lock().unwrap().is_empty());
        assert_eq!(f.queue.count(), 0);
    }

    /// Acme's domain lost its proof and Ann put the record back. Verify lifts
    /// it back to verified.
    #[test]
    fn a_lost_proof_put_back_verifies_again() {
        let domain = DomainSeed::verified("acme.test").lost().build();
        let id = *domain.id();
        let f = fixture(checking(domain, Arc::new(AcceptingDnsResolver)));

        assert_eq!(verify(&f, id).unwrap(), VerificationStatus::Verified);
    }

    /// Acme delegated its domain. The delegation proves it; no token was
    /// ever handed out to look for.
    #[test]
    fn a_delegated_domain_is_proved_by_its_delegation() {
        let domain = DomainSeed::pending("auth.acme.test").delegated().build();
        let id = *domain.id();
        let f = fixture(checking(domain, Arc::new(DelegationOnly)));

        assert_eq!(verify(&f, id).unwrap(), VerificationStatus::Verified);
    }

    /// Acme runs its own DNS and only a delegation answers yes. A tenant-
    /// managed domain is not waved through by a check it never made.
    #[test]
    fn a_self_managed_domain_is_not_proved_by_a_delegation() {
        let domain = pending();
        let id = *domain.id();
        let f = fixture(checking(domain, Arc::new(DelegationOnly)));

        assert_eq!(verify(&f, id).unwrap(), VerificationStatus::Pending);
    }

    /// Ann names a domain Acme does not have. It is not found.
    #[test]
    fn an_unknown_domain_is_not_found() {
        let f = fixture(checking(pending(), Arc::new(AcceptingDnsResolver)));

        let result = verify(&f, DomainId::new());

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Domain-viewing rights cannot trigger verification, even when DNS
    /// would prove ownership; the refusal records no verification event.
    #[test]
    fn a_caller_who_may_only_view_domains_is_refused() {
        let domain = pending();
        let id = *domain.id();
        let f = fixture(Setup {
            authorities: FakeTenantAuthorities::holding(&[SystemPermission::Domains(
                DomainAction::View,
            )]),
            ..checking(domain, Arc::new(AcceptingDnsResolver))
        });

        let result = verify(&f, id);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(f.audit.records.lock().unwrap().is_empty());
    }

    /// A signed-out session cannot verify a pending domain.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let domain = pending();
        let id = *domain.id();
        let f = fixture(Setup {
            authorities: FakeTenantAuthorities::refusing(Refusal::SignedOut),
            ..checking(domain, Arc::new(AcceptingDnsResolver))
        });

        let result = verify(&f, id);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// Answers yes to a delegation and no to everything else.
    struct DelegationOnly;

    #[async_trait]
    impl DnsResolver for DelegationOnly {
        async fn verify_txt_record(
            &self,
            _: &RecordName,
            _: &TxtValue,
        ) -> Result<bool, DomainError> {
            Ok(false)
        }

        async fn verify_cname(&self, _: &DomainName, _: &DomainName) -> Result<bool, DomainError> {
            Ok(false)
        }

        async fn verify_delegation(
            &self,
            _: &DomainName,
            _: &[DomainName],
        ) -> Result<bool, DomainError> {
            Ok(true)
        }
    }
}
