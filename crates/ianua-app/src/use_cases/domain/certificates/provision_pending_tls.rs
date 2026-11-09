//! Provision pending TLS: the safety net behind the certificate job.
//!
//! Verification queues a `domain.provision_tls` job, and that job is what
//! normally gets a domain its certificate. This sweep is for the domains the
//! job never reached: one queued while the queue was unreachable, one whose
//! retries ran out, or one verified by a build that queued nothing.
//!
//! It waits before touching a domain. A domain verified seconds ago has a job
//! in flight, and asking a certificate authority for the same hostname twice
//! at once spends validation attempts against a rate limit measured in single
//! digits per hour.

use std::sync::Arc;

use ianua_domain::domains::tenant::custom_domains::registered_domain::RegisteredDomain;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::TenantId;

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::domain::CrossTenantDomainStore;
use crate::use_case::Command;
use crate::use_cases::domain::certificates::ProvisionTlsUseCase;
use crate::use_cases::domain::verification::verified::ProvisionTlsJob;

/// The ports [`ProvisionPendingTlsUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ProvisionPendingTlsPorts {
    /// Lists the verified domains of every tenant still waiting on a
    /// certificate.
    pub cross_tenant_domains: Arc<dyn CrossTenantDomainStore>,
    /// The issuance the sweep hands each domain to, so there is one path to
    /// a certificate rather than two that can drift apart.
    pub provision_tls: Arc<ProvisionTlsUseCase>,
}

/// Issues certificates for verified domains that never got one.
pub struct ProvisionPendingTlsUseCase {
    ports: ProvisionPendingTlsPorts,
    stale_after_minutes: u32,
}

impl ProvisionPendingTlsUseCase {
    /// A use case working through `ports`.
    ///
    /// `stale_after_minutes` is how long a domain must have waited before the
    /// sweep takes it on: long enough that the queued job, retries included,
    /// has had its chance. Anything still waiting after that is stuck.
    #[must_use]
    pub fn new(ports: ProvisionPendingTlsPorts, stale_after_minutes: u32) -> Self {
        Self {
            ports,
            stale_after_minutes,
        }
    }
}

impl Command for ProvisionPendingTlsUseCase {
    type Caller = ();
    type Input = ();
    type Output = Result<u32, AppError>;

    /// Issues certificates for every verified domain still waiting on one,
    /// each recording `tenant.domain_tls_provisioned` against its own tenant.
    /// Returns how many were issued.
    ///
    /// # Errors
    ///
    /// Returns `AppError::Internal` if listing domains fails. A domain that
    /// cannot be issued is logged and skipped: one authority refusing one
    /// hostname must not hold up every other tenant.
    async fn execute(&self, (): &(), auditor: &RequestAuditor, (): ()) -> Result<u32, AppError> {
        let waiting = self
            .ports
            .cross_tenant_domains
            .list_awaiting_certificate(self.stale_after_minutes)
            .await
            .or_internal()?;

        let mut issued = 0u32;
        for (tenant_id, domain) in waiting {
            if was_issued(&self.ports, auditor, tenant_id, &domain).await {
                issued += 1;
            }
        }
        Ok(issued)
    }
}

/// Issues one domain's certificate through the queued job's own issuance.
/// A failure is logged and reported as not issued.
async fn was_issued(
    ports: &ProvisionPendingTlsPorts,
    auditor: &RequestAuditor,
    tenant_id: TenantId,
    domain: &RegisteredDomain<ResolvedTenant>,
) -> bool {
    let job = ProvisionTlsJob {
        tenant_id,
        domain_id: *domain.id(),
    };
    let Err(error) = ports.provision_tls.execute(&(), auditor, job).await else {
        tracing::info!(
            domain = domain.domain().as_str(),
            "certificate issued by the pending TLS sweep"
        );
        return true;
    };
    tracing::warn!(
        domain = domain.domain().as_str(),
        %error,
        "the pending TLS sweep could not issue a certificate"
    );
    false
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::tenant::custom_domains::verification_status::TlsStatus;
    use ianua_domain::shared::clock;
    use time::Duration;

    use super::*;
    use crate::test_support::domain::{DomainSeed, FakeDomainStore, FakeTlsProvisioner};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor};
    use crate::use_cases::domain::certificates::{ProvisionTlsPorts, TlsProvisioners};

    struct Fixture {
        use_case: ProvisionPendingTlsUseCase,
        domains: Arc<FakeDomainStore>,
        audit: Arc<FakeEventDispatcher>,
    }

    fn fixture(tenant_id: TenantId, domain: RegisteredDomain<ResolvedTenant>) -> Fixture {
        let domains = Arc::new(FakeDomainStore::holding(tenant_id, [domain]));
        let provision = Arc::new(ProvisionTlsUseCase::new(ProvisionTlsPorts {
            domain_store: domains.clone(),
            tls_provisioners: TlsProvisioners::uniform(Arc::new(FakeTlsProvisioner)),
            ..ProvisionTlsPorts::fakes()
        }));
        let use_case = ProvisionPendingTlsUseCase::new(
            ProvisionPendingTlsPorts {
                cross_tenant_domains: domains.clone(),
                provision_tls: provision,
            },
            30,
        );
        Fixture {
            use_case,
            domains,
            audit: Arc::new(FakeEventDispatcher::new()),
        }
    }

    fn sweep(f: &Fixture) -> u32 {
        block_on(f.use_case.execute(&(), &test_auditor(f.audit.clone()), ())).unwrap()
    }

    fn verified_two_hours_ago(name: &str) -> RegisteredDomain<ResolvedTenant> {
        DomainSeed::pending(name)
            .delegated()
            .proved_at(clock::now() - Duration::hours(2))
            .build()
    }

    /// Acme's domain was verified two hours ago and never got its
    /// certificate. The sweep issues it, recorded against Acme.
    #[test]
    fn a_domain_stuck_provisioning_gets_its_certificate() {
        let tenant_id = TenantId::new();
        let domain = verified_two_hours_ago("stuck.acme.test");
        let id = *domain.id();
        let f = fixture(tenant_id, domain);

        assert_eq!(sweep(&f), 1);
        assert_eq!(
            f.domains.domain_of(tenant_id, &id).unwrap().tls_status(),
            TlsStatus::Active
        );
        assert_eq!(
            f.audit.tenants.lock().unwrap().as_slice(),
            [("tenant.domain_tls_provisioned".to_owned(), Some(tenant_id))]
        );
    }

    /// Acme's domain was verified seconds ago and has a job in flight. The
    /// sweep leaves it to that job.
    #[test]
    fn a_domain_verified_just_now_is_left_to_its_queued_job() {
        let tenant_id = TenantId::new();
        let domain = DomainSeed::verified("fresh.acme.test").delegated().build();
        let id = *domain.id();
        let f = fixture(tenant_id, domain);

        assert_eq!(sweep(&f), 0);
        assert_eq!(
            f.domains.domain_of(tenant_id, &id).unwrap().tls_status(),
            TlsStatus::Provisioning
        );
    }

    /// Acme's domain already serves a certificate. The sweep does not ask
    /// for another.
    #[test]
    fn a_domain_already_holding_a_certificate_is_skipped() {
        let domain = DomainSeed::pending("served.acme.test")
            .delegated()
            .proved_at(clock::now() - Duration::hours(2))
            .tls(TlsStatus::Active)
            .build();
        let f = fixture(TenantId::new(), domain);

        assert_eq!(sweep(&f), 0);
    }
}
