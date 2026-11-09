//! Retry verification: check DNS again for domains whose proof has not held
//! yet, or no longer held.

use std::sync::Arc;

use ianua_domain::domains::tenant::custom_domains::registered_domain::RegisteredDomain;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::TenantId;

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::domain::{CrossTenantDomainStore, DnsResolver, RegisteredDomainStore};
use crate::ports::runtime::UnitOfWork;
use crate::services::kept_together::kept_together;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::domain::verification::proof::{ProofRules, ProofSources, is_proven};
use crate::use_cases::domain::verification::recorded::save_and_record;
use crate::use_cases::domain::verification::verified::{CertificateQueue, request_certificate};

/// The ports [`RetryUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RetryPorts {
    /// Saves the domains that pass.
    pub domain_store: Arc<dyn RegisteredDomainStore>,
    /// Lists every tenant's domains due a check, and stamps each one checked.
    pub cross_tenant_domains: Arc<dyn CrossTenantDomainStore>,
    /// The DNS lookups that prove ownership (`TXT` or `NS`).
    pub dns_resolver: Arc<dyn DnsResolver>,
    /// Queues the certificate a newly verified domain is owed.
    ///
    /// This is where most domains are verified: a tenant sets their records
    /// and then waits, and whichever sweep runs next is what notices.
    pub certificates: CertificateQueue,
    /// Keeps each change and the record of it together.
    pub unit_of_work: Arc<dyn UnitOfWork>,
}

/// Checks DNS again for domains whose verification is pending or failed.
///
/// Runs as a periodic task over the domains the store considers due: a short
/// wait after registration, then often, then backing off.
pub struct RetryUseCase {
    ports: RetryPorts,
    rules: ProofRules,
}

impl RetryUseCase {
    /// A use case working through `ports`, accepting what `rules` say proves
    /// a domain.
    #[must_use]
    pub fn new(ports: RetryPorts, rules: ProofRules) -> Self {
        Self { ports, rules }
    }
}

/// What one retry did to a domain.
enum Retry {
    /// The proof held and the domain is now verified.
    Verified,
    /// The proof does not hold yet.
    StillPending,
}

impl Command for RetryUseCase {
    type Caller = ();
    type Input = ();
    type Output = Result<u32, AppError>;

    /// Checks every domain due a retry, and records `tenant.domain_verified`
    /// against its own tenant, and queues its certificate, for each one that
    /// comes through. Returns how many were newly verified.
    ///
    /// Asks [`is_proven`], the same question the first attempt asked, so a
    /// delegated domain that fell to failed can recover.
    ///
    /// # Errors
    ///
    /// Returns `AppError::Internal` if listing domains fails. A domain that
    /// cannot be checked or recorded is logged and left for the next sweep.
    async fn execute(&self, (): &(), auditor: &RequestAuditor, (): ()) -> Result<u32, AppError> {
        let due = self
            .ports
            .cross_tenant_domains
            .list_pending_verification()
            .await
            .or_internal()?;

        let mut verified = 0u32;
        for (tenant_id, mut domain) in due {
            match retried(&self.ports, &self.rules, auditor, tenant_id, &mut domain).await {
                Ok(Retry::Verified) => verified += 1,
                Ok(Retry::StillPending) => {}
                Err(error) => tracing::warn!(
                    domain = domain.domain().as_str(),
                    %error,
                    "domain retry failed; left pending for the next sweep"
                ),
            }
        }
        Ok(verified)
    }
}

/// Checks one domain again and, once its proof holds, saves and records it
/// as one unit and queues its certificate.
async fn retried(
    ports: &RetryPorts,
    rules: &ProofRules,
    auditor: &RequestAuditor,
    tenant_id: TenantId,
    domain: &mut RegisteredDomain<ResolvedTenant>,
) -> Result<Retry, AppError> {
    let tenant = ScopedTenant::for_background(tenant_id);
    let sources = ProofSources {
        resolver: ports.dns_resolver.as_ref(),
        domains: ports.domain_store.as_ref(),
        rules,
    };
    let proven = is_proven(sources, &tenant, domain).await;
    note_checked(ports, domain).await;
    if !proven.or_internal()? {
        return Ok(Retry::StillPending);
    }

    domain.mark_verified().map_err(AppError::from_domain)?;
    let auditor = auditor.with_tenant(tenant_id);
    let saved = save_and_record(
        ports.domain_store.as_ref(),
        &auditor,
        &tenant,
        domain,
        Vec::new(),
    );
    kept_together(ports.unit_of_work.as_ref(), saved).await?;
    tracing::info!(
        domain = domain.domain().as_str(),
        "domain verified by the retry sweep"
    );
    request_certificate(&ports.certificates, &tenant_id, domain).await;
    Ok(Retry::Verified)
}

/// Stamps the domain as checked, so the sweep backs off before asking
/// again. A stamp that cannot be written only means an early retry, so it is
/// logged rather than allowed to stop the check.
async fn note_checked(ports: &RetryPorts, domain: &RegisteredDomain<ResolvedTenant>) {
    let Err(error) = ports.cross_tenant_domains.mark_checked(domain.id()).await else {
        return;
    };
    tracing::warn!(
        domain = domain.domain().as_str(),
        %error,
        "could not record the check time; the domain may be retried early"
    );
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::tenant::custom_domains::verification_status::VerificationStatus;
    use ianua_domain::types::{DomainId, DomainName};

    use super::*;
    use crate::ports::runtime::Settlement;
    use crate::ports::shared::EventDispatcher;
    use crate::test_support::domain::{
        AcceptingDnsResolver, DomainSeed, FakeDomainStore, RejectingDnsResolver, certificates,
    };
    use crate::test_support::scheduling::FakeJobQueue;
    use crate::test_support::{
        FailingEventDispatcher, FakeEventDispatcher, RecordingUnitOfWork, block_on, test_auditor,
    };
    use crate::use_cases::domain::verification::verified::PROVISION_TLS_JOB;

    struct Fixture {
        use_case: RetryUseCase,
        domains: Arc<FakeDomainStore>,
        queue: Arc<FakeJobQueue>,
        unit: Arc<RecordingUnitOfWork>,
        owner: TenantId,
        id: DomainId,
    }

    fn fixture(
        domain: RegisteredDomain<ResolvedTenant>,
        resolver: Arc<dyn DnsResolver>,
    ) -> Fixture {
        let owner = TenantId::new();
        let id = *domain.id();
        let domains = Arc::new(FakeDomainStore::holding(owner, [domain]));
        let queue = Arc::new(FakeJobQueue::new());
        let unit = Arc::new(RecordingUnitOfWork::default());
        let use_case = RetryUseCase::new(
            RetryPorts {
                domain_store: domains.clone(),
                cross_tenant_domains: domains.clone(),
                dns_resolver: resolver,
                certificates: certificates(queue.clone()),
                unit_of_work: unit.clone(),
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
            unit,
            owner,
            id,
        }
    }

    fn pending(resolver: Arc<dyn DnsResolver>) -> Fixture {
        fixture(DomainSeed::pending("swept.acme.test").build(), resolver)
    }

    fn sweep(f: &Fixture, sink: Arc<dyn EventDispatcher>) -> u32 {
        block_on(f.use_case.execute(&(), &test_auditor(sink), ())).unwrap()
    }

    fn status(f: &Fixture) -> VerificationStatus {
        f.domains
            .domain_of(f.owner, &f.id)
            .unwrap()
            .verification_status()
    }

    /// Acme's records propagated while nobody was watching. The sweep
    /// verifies the domain, records it against Acme and asks for its
    /// certificate.
    #[test]
    fn a_domain_verified_by_the_sweep_is_announced_and_gets_a_certificate_requested() {
        let f = pending(Arc::new(AcceptingDnsResolver));
        let dispatcher = Arc::new(FakeEventDispatcher::new());

        assert_eq!(sweep(&f, dispatcher.clone()), 1);
        assert_eq!(status(&f), VerificationStatus::Verified);
        assert_eq!(
            dispatcher.tenant_of("tenant.domain_verified"),
            Some(f.owner)
        );
        assert!(f.queue.holds(PROVISION_TLS_JOB));
    }

    /// Acme's records are still not there. The sweep leaves the domain
    /// pending and announces nothing; announcing it would tell Acme it is
    /// done.
    #[test]
    fn a_domain_the_sweep_could_not_verify_announces_nothing() {
        let f = pending(Arc::new(RejectingDnsResolver));
        let dispatcher = Arc::new(FakeEventDispatcher::new());

        assert_eq!(sweep(&f, dispatcher.clone()), 0);
        assert_eq!(status(&f), VerificationStatus::Pending);
        assert!(dispatcher.records.lock().unwrap().is_empty());
        assert_eq!(f.queue.count(), 0);
    }

    /// Acme's domain lost its proof and Acme put the record back. The sweep
    /// verifies it again.
    #[test]
    fn a_failed_domain_is_verified_again() {
        let f = fixture(
            DomainSeed::verified("failed.acme.test").lost().build(),
            Arc::new(AcceptingDnsResolver),
        );

        assert_eq!(sweep(&f, Arc::new(FakeEventDispatcher::new())), 1);
        assert_eq!(status(&f), VerificationStatus::Verified);
    }

    /// No domain is due. The sweep verifies nothing.
    #[test]
    fn nothing_due_verifies_nothing() {
        let use_case = RetryUseCase::new(RetryPorts::fakes(), ProofRules::default());

        let verified = block_on(use_case.execute(
            &(),
            &test_auditor(Arc::new(FakeEventDispatcher::new())),
            (),
        ))
        .unwrap();

        assert_eq!(verified, 0);
    }

    /// The verification of Acme's domain cannot be recorded. It is not
    /// counted, and the change is rolled back with it.
    #[test]
    fn a_verification_that_cannot_be_recorded_is_rolled_back() {
        let f = pending(Arc::new(AcceptingDnsResolver));

        assert_eq!(sweep(&f, Arc::new(FailingEventDispatcher)), 0);
        assert_eq!(f.unit.settlements(), vec![Settlement::Rollback]);
    }

    /// Acme's domain comes through. Saving it and recording it are one
    /// unit.
    #[test]
    fn a_verified_domain_is_saved_and_recorded_as_one_unit() {
        let f = pending(Arc::new(AcceptingDnsResolver));

        sweep(&f, Arc::new(FakeEventDispatcher::new()));

        assert_eq!(f.unit.settlements(), vec![Settlement::Commit]);
    }
}
