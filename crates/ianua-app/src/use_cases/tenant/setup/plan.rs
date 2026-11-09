//! Plan a tenant's setup: a tenant announced as provisioned gets its setup
//! begun and one job queued for each step ready to run, keyed by tenant and
//! step, so the announcement delivered twice queues nothing twice.

use std::sync::Arc;

use ianua_domain::types::event_type::{EventType, TenantEvent};

use crate::auditor::RequestAuditor;
use crate::error::AppError;
use crate::ports::shared::PublishedEvent;
use crate::ports::tenant::{TenantSetupStore, TenantStore};
use crate::use_case::Command;
use crate::use_cases::scheduling::PlanReport;
use crate::use_cases::tenant::setup::job::SetupSteps;
use crate::use_cases::tenant::setup::start::SetupStart;

/// The ports [`PlanUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct PlanPorts {
    /// Loads provisioning progress to determine the next queued step.
    pub setups: Arc<dyn TenantSetupStore>,
    /// The tenants, for the one announced.
    pub tenants: Arc<dyn TenantStore>,
    /// Where the steps are queued.
    pub steps: SetupSteps,
}

/// Plans the setup a provisioned tenant needs.
///
/// The event pipeline runs it, for nobody, so its caller is `()`.
pub struct PlanUseCase {
    ports: PlanPorts,
}

impl PlanUseCase {
    /// A planner over `ports`.
    #[must_use]
    pub fn new(ports: PlanPorts) -> Self {
        Self { ports }
    }
}

impl Command for PlanUseCase {
    type Caller = ();
    type Input = PublishedEvent;
    type Output = Result<PlanReport, AppError>;

    /// Begins the setup of the tenant `event` announces as provisioned,
    /// unless it has one, and queues a job for each step ready to run.
    /// Any other event plans nothing, and so does a tenant gone or no
    /// longer provisioning. Records nothing: each step records what it
    /// does.
    ///
    /// # Errors
    ///
    /// `AppError::Internal` when a store cannot be read or written or a job
    /// cannot be queued. The pipeline delivers the event again, and what
    /// was queued is not queued twice.
    async fn execute(
        &self,
        (): &(),
        _auditor: &RequestAuditor,
        event: PublishedEvent,
    ) -> Result<PlanReport, AppError> {
        let provisioned = EventType::Tenant(TenantEvent::Provisioned);
        let Some(tenant_id) = event.event.tenant_id().copied() else {
            return Ok(PlanReport::default());
        };
        if event.event.event_type() != provisioned {
            return Ok(PlanReport::default());
        }
        SetupStart {
            setups: self.ports.setups.as_ref(),
            tenants: self.ports.tenants.as_ref(),
            steps: &self.ports.steps,
        }
        .queued(tenant_id)
        .await
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::audit::builder::AuditContext;
    use ianua_domain::domains::tenant::lifecycle::Tenant;
    use ianua_domain::shared::events::event::DomainEvent;
    use ianua_domain::test_support::events::{sample_tenant_event, sample_tenant_provisioned};
    use ianua_domain::types::AuditRecordId;

    use super::*;
    use crate::test_support::scheduling::FakeJobQueue;
    use crate::test_support::tenant::{
        FakeTenantSetupStore, FakeTenantStore, setup_steps, test_tenant,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor};
    use crate::use_cases::tenant::setup::SETUP_STEP_JOB;

    struct Bench {
        plan: PlanUseCase,
        setups: Arc<FakeTenantSetupStore>,
        queue: Arc<FakeJobQueue>,
    }

    fn bench(tenant: Tenant) -> Bench {
        let setups = Arc::new(FakeTenantSetupStore::empty());
        let queue = Arc::new(FakeJobQueue::new());
        let plan = PlanUseCase::new(PlanPorts {
            setups: setups.clone(),
            tenants: Arc::new(FakeTenantStore::holding(tenant)),
            steps: setup_steps(queue.clone()),
        });
        Bench {
            plan,
            setups,
            queue,
        }
    }

    fn published(event: DomainEvent) -> PublishedEvent {
        PublishedEvent {
            id: AuditRecordId::new(),
            event,
            context: AuditContext::system(),
        }
    }

    impl Bench {
        fn plan(&self, event: PublishedEvent) -> PlanReport {
            let audit = Arc::new(FakeEventDispatcher::new());
            block_on(self.plan.execute(&(), &test_auditor(audit), event)).unwrap()
        }
    }

    /// Acme is announced as provisioned: its setup begins, and its signing
    /// key, assertion key and starting roles are queued, the steps that wait
    /// on nothing.
    #[test]
    fn a_provisioned_tenant_gets_its_setup_and_first_steps() {
        let tenant = test_tenant("acme", "acme.com");
        let bench = bench(tenant.clone());

        let report = bench.plan(published(sample_tenant_provisioned(&tenant)));

        assert_eq!(report.queued, 3);
        assert!(bench.setups.of(tenant.id()).is_some());
        assert_eq!(bench.queue.jobs_of(SETUP_STEP_JOB).len(), 3);
    }

    /// The bus delivers Acme's announcement twice before a worker took its
    /// steps. Nothing is queued twice.
    #[test]
    fn an_announcement_delivered_twice_queues_nothing_twice() {
        let tenant = test_tenant("acme", "acme.com");
        let bench = bench(tenant.clone());
        bench.plan(published(sample_tenant_provisioned(&tenant)));

        let again = bench.plan(published(sample_tenant_provisioned(&tenant)));

        assert_eq!((again.queued, again.already_queued), (0, 3));
        assert_eq!(bench.queue.jobs_of(SETUP_STEP_JOB).len(), 3);
    }

    /// Any other event plans no setup.
    #[test]
    fn another_event_plans_nothing() {
        let tenant = test_tenant("acme", "acme.com");
        let bench = bench(tenant.clone());

        let report = bench.plan(published(sample_tenant_event(*tenant.id())));

        assert_eq!(report, PlanReport::default());
        assert!(bench.setups.of(tenant.id()).is_none());
    }
}
