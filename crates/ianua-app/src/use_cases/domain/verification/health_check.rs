//! Domain health check: check DNS again for verified domains, to notice a
//! proof that was removed.

use std::sync::Arc;

use ianua_domain::domains::tenant::custom_domains::registered_domain::RegisteredDomain;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::{DomainName, TenantId};

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::domain::{CrossTenantDomainStore, DnsResolver, RegisteredDomainStore};
use crate::ports::runtime::UnitOfWork;
use crate::ports::tenant::TenantStore;
use crate::services::kept_together::kept_together;
use crate::services::lookup::existing_tenant;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::domain::primary::released_primary;
use crate::use_cases::domain::verification::proof::{ProofRules, ProofSources, is_proven};
use crate::use_cases::domain::verification::recorded::save_and_record;

/// The ports [`DomainHealthCheckUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct DomainHealthCheckPorts {
    /// Saves the domains that lost their proof.
    pub domain_store: Arc<dyn RegisteredDomainStore>,
    /// Lists every tenant's verified domains.
    pub cross_tenant_domains: Arc<dyn CrossTenantDomainStore>,
    /// The DNS lookups that prove ownership (`TXT` or `NS`).
    pub dns_resolver: Arc<dyn DnsResolver>,
    /// Tenants, which let go of a primary domain that lost its proof.
    pub tenants: Arc<dyn TenantStore>,
    /// Keeps each change and the record of it together.
    pub unit_of_work: Arc<dyn UnitOfWork>,
}

/// Checks verified domains again, as a periodic task.
///
/// A domain whose proof, its `TXT` record or for a delegated domain its `NS`
/// records, no longer holds is marked as having lost it. That catches a
/// tenant who removed their verification record by accident.
pub struct DomainHealthCheckUseCase {
    ports: DomainHealthCheckPorts,
    rules: ProofRules,
}

impl DomainHealthCheckUseCase {
    /// A use case working through `ports`, accepting what `rules` say proves
    /// a domain: the same rules the domains were verified under.
    #[must_use]
    pub fn new(ports: DomainHealthCheckPorts, rules: ProofRules) -> Self {
        Self { ports, rules }
    }
}

/// What one check found.
enum Health {
    /// The proof is still in place.
    Holding,
    /// The proof is gone and the domain is now marked as having lost it.
    Lost,
}

impl Command for DomainHealthCheckUseCase {
    type Caller = ();
    type Input = ();
    type Output = Result<Vec<DomainName>, AppError>;

    /// Checks every verified domain again, and records
    /// `tenant.domain_verification_lost` against its own tenant for each one
    /// whose proof is gone. A tenant whose primary domain lost its proof
    /// lets go of it, and `tenant.primary_domain_changed` is recorded too.
    /// Returns the names that lost their proof.
    ///
    /// # Errors
    ///
    /// Returns `AppError::Internal` if listing domains fails. A domain that
    /// cannot be checked, recorded or saved is logged and left as it was for
    /// the next run, so one bad domain never stops the sweep.
    async fn execute(
        &self,
        (): &(),
        auditor: &RequestAuditor,
        (): (),
    ) -> Result<Vec<DomainName>, AppError> {
        let verified = self
            .ports
            .cross_tenant_domains
            .list_verified()
            .await
            .or_internal()?;

        let mut lost = Vec::new();
        for (tenant_id, mut domain) in verified {
            match rechecked(&self.ports, &self.rules, auditor, tenant_id, &mut domain).await {
                Ok(Health::Lost) => lost.push(domain.domain().clone()),
                Ok(Health::Holding) => {}
                Err(error) => tracing::warn!(
                    domain = domain.domain().as_str(),
                    %error,
                    "domain health check failed; left as it was for the next run"
                ),
            }
        }
        Ok(lost)
    }
}

/// Checks one domain again and, once its proof is gone, marks it, then
/// saves and records it as one unit.
///
/// The same question, asked the same way, as when it was first verified.
/// Asking it differently is what once marked working delegated domains as
/// failed on every run.
async fn rechecked(
    ports: &DomainHealthCheckPorts,
    rules: &ProofRules,
    auditor: &RequestAuditor,
    tenant_id: TenantId,
    domain: &mut RegisteredDomain<ResolvedTenant>,
) -> Result<Health, AppError> {
    let sources = ProofSources {
        resolver: ports.dns_resolver.as_ref(),
        domains: ports.domain_store.as_ref(),
        rules,
    };
    let scope = ScopedTenant::for_background(tenant_id);
    let holding = is_proven(sources, &scope, domain).await.or_internal()?;
    if holding {
        return Ok(Health::Holding);
    }

    tracing::warn!(
        domain = domain.domain().as_str(),
        "DNS proof removed; marking the domain's verification lost"
    );
    domain
        .mark_verification_failed()
        .map_err(AppError::from_domain)?;
    let auditor = auditor.with_tenant(tenant_id);
    let saved = lose_and_release(ports, &auditor, tenant_id, domain);
    kept_together(ports.unit_of_work.as_ref(), saved).await?;
    Ok(Health::Lost)
}

/// Lets the tenant go of `domain` as its primary domain, now it lost its
/// proof, then saves the domain and records the loss and any release.
///
/// # Errors
///
/// - `AppError::NotFound` when the domain's tenant is gone.
/// - `AppError::Internal` on persistence or audit failure.
async fn lose_and_release(
    ports: &DomainHealthCheckPorts,
    auditor: &RequestAuditor,
    tenant_id: TenantId,
    domain: &mut RegisteredDomain<ResolvedTenant>,
) -> Result<(), AppError> {
    let tenants = ports.tenants.as_ref();
    let mut tenant = existing_tenant(tenants, &tenant_id).await?;
    let released = released_primary(tenants, &mut tenant, domain.domain()).await?;
    let scope = ScopedTenant::for_background(tenant_id);
    save_and_record(
        ports.domain_store.as_ref(),
        auditor,
        &scope,
        domain,
        released,
    )
    .await
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use ianua_domain::domains::tenant::custom_domains::dns_zone::{RecordName, TxtValue};
    use ianua_domain::domains::tenant::custom_domains::verification_status::VerificationStatus;
    use ianua_domain::shared::errors::DomainError;
    use ianua_domain::types::{DomainId, OrganizationId};

    use super::*;
    use crate::ports::runtime::Settlement;
    use crate::ports::shared::EventDispatcher;
    use crate::test_support::domain::{
        AcceptingDnsResolver, DomainSeed, FakeDomainStore, RejectingDnsResolver,
    };
    use crate::test_support::tenant::{FakeTenantStore, test_tenant_with_id};
    use crate::test_support::{
        FailingEventDispatcher, FakeEventDispatcher, RecordingUnitOfWork, block_on, test_auditor,
    };

    struct Fixture {
        use_case: DomainHealthCheckUseCase,
        domains: Arc<FakeDomainStore>,
        tenants: Arc<FakeTenantStore>,
        unit: Arc<RecordingUnitOfWork>,
        owner: TenantId,
        id: DomainId,
    }

    fn fixture(
        domain: RegisteredDomain<ResolvedTenant>,
        resolver: Arc<dyn DnsResolver>,
    ) -> Fixture {
        fixture_serving(domain, resolver, "acme.test")
    }

    /// Keeps the domain owner serving the selected primary name.
    fn tenants_serving(owner: TenantId, primary: &str) -> Arc<FakeTenantStore> {
        Arc::new(FakeTenantStore::holding(test_tenant_with_id(
            owner,
            OrganizationId::new(),
            "acme",
            primary,
        )))
    }

    /// Checks a stored domain while observing its owner's primary name and unit settlement.
    fn fixture_serving(
        domain: RegisteredDomain<ResolvedTenant>,
        resolver: Arc<dyn DnsResolver>,
        primary: &str,
    ) -> Fixture {
        let owner = TenantId::new();
        let id = *domain.id();
        let domains = Arc::new(FakeDomainStore::holding(owner, [domain]));
        let tenants = tenants_serving(owner, primary);
        let unit = Arc::new(RecordingUnitOfWork::default());
        let use_case = DomainHealthCheckUseCase::new(
            DomainHealthCheckPorts {
                domain_store: domains.clone(),
                cross_tenant_domains: domains.clone(),
                dns_resolver: resolver,
                tenants: tenants.clone(),
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
            tenants,
            unit,
            owner,
            id,
        }
    }

    fn delegated(resolver: Arc<dyn DnsResolver>) -> Fixture {
        fixture(
            DomainSeed::verified("app.acme.test").delegated().build(),
            resolver,
        )
    }

    fn check(f: &Fixture, sink: Arc<dyn EventDispatcher>) -> Vec<DomainName> {
        block_on(f.use_case.execute(&(), &test_auditor(sink), ())).unwrap()
    }

    fn status(f: &Fixture) -> VerificationStatus {
        f.domains
            .domain_of(f.owner, &f.id)
            .unwrap()
            .verification_status()
    }

    /// Answers yes to a delegation and no to everything else, as DNS does
    /// for a correctly delegated domain.
    struct DelegatedResolver;

    #[async_trait]
    impl DnsResolver for DelegatedResolver {
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

    /// Acme's domain is correctly delegated. It stays verified; a check that
    /// looked for a token would fail it within minutes of setup.
    #[test]
    fn a_correctly_delegated_domain_stays_verified() {
        let f = delegated(Arc::new(DelegatedResolver));

        let lost = check(&f, Arc::new(FakeEventDispatcher::new()));

        assert!(lost.is_empty());
        assert_eq!(status(&f), VerificationStatus::Verified);
    }

    /// Acme withdrew the delegation. The domain is marked as having lost its
    /// proof and reported.
    #[test]
    fn a_delegated_domain_whose_delegation_is_gone_fails() {
        let f = delegated(Arc::new(RejectingDnsResolver));

        let lost = check(&f, Arc::new(FakeEventDispatcher::new()));

        assert_eq!(lost.len(), 1);
        assert_eq!(status(&f), VerificationStatus::Failed);
    }

    /// Acme's domain stopped resolving. The loss is recorded against Acme,
    /// since it means something is broken rather than pending.
    #[test]
    fn a_domain_that_stopped_resolving_is_announced() {
        let f = delegated(Arc::new(RejectingDnsResolver));
        let dispatcher = Arc::new(FakeEventDispatcher::new());

        check(&f, dispatcher.clone());

        assert_eq!(
            dispatcher.tenant_of("tenant.domain_verification_lost"),
            Some(f.owner)
        );
    }

    /// Acme's primary domain `app.acme.test` lost its delegation. Acme lets
    /// go of it as its primary domain, so it no longer routes a name it has
    /// not proved, and the change is recorded beside the loss.
    #[test]
    fn a_primary_domain_that_lost_its_proof_is_let_go() {
        let f = fixture_serving(
            DomainSeed::verified("app.acme.test").delegated().build(),
            Arc::new(RejectingDnsResolver),
            "app.acme.test",
        );
        let dispatcher = Arc::new(FakeEventDispatcher::new());

        check(&f, dispatcher.clone());

        let tenant = block_on(f.tenants.find_by_id(&f.owner)).unwrap().unwrap();
        assert!(tenant.primary_domain().is_none());
        assert_eq!(
            *dispatcher.records.lock().unwrap(),
            vec![
                "tenant.domain_verification_lost",
                "tenant.primary_domain_changed"
            ]
        );
    }

    /// Answers yes only to a delegation of `0`, as DNS does for a delegated
    /// parent: a wildcard inside its zone has no `NS` records of its own.
    struct ParentDelegated(DomainName);

    #[async_trait]
    impl DnsResolver for ParentDelegated {
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
            domain: &DomainName,
            _: &[DomainName],
        ) -> Result<bool, DomainError> {
            Ok(*domain == self.0)
        }
    }

    /// Acme's `*.app.acme.test` over its delegated `app.acme.test`, checked
    /// with DNS as `resolver` answers.
    fn wildcard_over_parent(resolver: Arc<dyn DnsResolver>) -> Fixture {
        let f = fixture(
            DomainSeed::verified("*.app.acme.test").delegated().build(),
            resolver,
        );
        let parent = DomainSeed::verified("app.acme.test").delegated().build();
        block_on(f.domains.save(&ScopedTenant::for_test(f.owner), &parent)).unwrap();
        f
    }

    /// Acme's `app.acme.test` is delegated to us, and `*.app.acme.test`
    /// lives inside its zone. The wildcard stays verified: it is proved
    /// through its parent, and has no delegation of its own to find.
    #[test]
    fn a_wildcard_over_a_delegated_parent_stays_verified() {
        let parent = DomainName::new("app.acme.test").unwrap();
        let f = wildcard_over_parent(Arc::new(ParentDelegated(parent)));

        let lost = check(&f, Arc::new(FakeEventDispatcher::new()));

        assert!(lost.is_empty());
        assert_eq!(status(&f), VerificationStatus::Verified);
    }

    /// Acme withdrew the delegation of `app.acme.test`. Its wildcard proved
    /// nothing of its own, so it loses its proof with its parent.
    #[test]
    fn a_wildcard_loses_its_proof_with_its_parent() {
        let f = wildcard_over_parent(Arc::new(RejectingDnsResolver));

        check(&f, Arc::new(FakeEventDispatcher::new()));

        assert_eq!(status(&f), VerificationStatus::Failed);
    }

    /// Acme's `*.app.acme.test` stands on no registration of
    /// `app.acme.test`. It proves nothing and loses its proof.
    #[test]
    fn a_wildcard_without_its_parent_loses_its_proof() {
        let f = fixture(
            DomainSeed::verified("*.app.acme.test").delegated().build(),
            Arc::new(AcceptingDnsResolver),
        );

        check(&f, Arc::new(FakeEventDispatcher::new()));

        assert_eq!(status(&f), VerificationStatus::Failed);
    }

    /// Acme's domain still resolves. That is not news.
    #[test]
    fn a_domain_that_still_resolves_announces_nothing() {
        let f = fixture(
            DomainSeed::verified("app.acme.test").build(),
            Arc::new(AcceptingDnsResolver),
        );
        let dispatcher = Arc::new(FakeEventDispatcher::new());

        check(&f, dispatcher.clone());

        assert!(dispatcher.records.lock().unwrap().is_empty());
        assert_eq!(status(&f), VerificationStatus::Verified);
    }

    /// The loss of Acme's proof cannot be recorded. It is not reported, and
    /// the change is rolled back with it.
    #[test]
    fn a_loss_that_cannot_be_recorded_is_rolled_back() {
        let f = delegated(Arc::new(RejectingDnsResolver));

        let lost = check(&f, Arc::new(FailingEventDispatcher));

        assert!(lost.is_empty());
        assert_eq!(f.unit.settlements(), vec![Settlement::Rollback]);
    }

    /// Acme's domain lost its proof. Saving it and recording the loss are
    /// one unit.
    #[test]
    fn a_lost_domain_is_saved_and_recorded_as_one_unit() {
        let f = delegated(Arc::new(RejectingDnsResolver));

        check(&f, Arc::new(FakeEventDispatcher::new()));

        assert_eq!(f.unit.settlements(), vec![Settlement::Commit]);
    }
}
