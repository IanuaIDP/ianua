//! Plan a tenant's teardown: a tenant announced as deleted gets its
//! teardown begun and one job queued for each step ready to run, keyed by
//! tenant and step, so a repeated announcement queues nothing twice.

use std::sync::Arc;

use ianua_domain::types::event_type::{EventType, TenantEvent};

use crate::auditor::RequestAuditor;
use crate::error::AppError;
use crate::ports::shared::PublishedEvent;
use crate::ports::tenant::{TenantStore, TenantTeardownStore};
use crate::use_case::Command;
use crate::use_cases::scheduling::PlanReport;
use crate::use_cases::tenant::teardown::job::TeardownSteps;
use crate::use_cases::tenant::teardown::start::TeardownStart;

/// The ports [`PlanUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct PlanPorts {
    /// Loads removal progress to determine the next queued step.
    pub teardowns: Arc<dyn TenantTeardownStore>,
    /// The tenants, for the one announced.
    pub tenants: Arc<dyn TenantStore>,
    /// Where the steps are queued.
    pub steps: TeardownSteps,
}

/// Plans the teardown a deleted tenant needs.
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

    /// Begins the teardown of the tenant `event` announces as deleted,
    /// unless it has one, and queues a job for each step ready to run. Any
    /// other event plans nothing, and so does a tenant gone or not deleted.
    /// Records nothing: each step records what it does.
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
        let deleted = EventType::Tenant(TenantEvent::Deleted);
        let Some(tenant_id) = event.event.tenant_id().copied() else {
            return Ok(PlanReport::default());
        };
        if event.event.event_type() != deleted {
            return Ok(PlanReport::default());
        }
        TeardownStart {
            teardowns: self.ports.teardowns.as_ref(),
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
    use ianua_domain::test_support::events::{sample_tenant_deleted, sample_tenant_event};
    use ianua_domain::types::AuditRecordId;

    use super::*;
    use crate::test_support::scheduling::FakeJobQueue;
    use crate::test_support::tenant::{
        FakeTenantStore, FakeTenantTeardownStore, teardown_steps, test_tenant, test_tenant_deleted,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor};
    use crate::use_cases::tenant::teardown::TEARDOWN_STEP_JOB;

    struct Bench {
        plan: PlanUseCase,
        teardowns: Arc<FakeTenantTeardownStore>,
        queue: Arc<FakeJobQueue>,
    }

    fn bench(tenant: Tenant) -> Bench {
        let teardowns = Arc::new(FakeTenantTeardownStore::empty());
        let queue = Arc::new(FakeJobQueue::new());
        let plan = PlanUseCase::new(PlanPorts {
            teardowns: teardowns.clone(),
            tenants: Arc::new(FakeTenantStore::holding(tenant)),
            steps: teardown_steps(queue.clone()),
        });
        Bench {
            plan,
            teardowns,
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

    /// Acme is announced as deleted: its teardown begins, and removing its
    /// data is queued.
    #[test]
    fn a_deleted_tenant_gets_its_teardown_and_first_step() {
        let tenant = test_tenant_deleted();
        let bench = bench(tenant.clone());

        let report = bench.plan(published(sample_tenant_deleted(*tenant.id())));

        assert_eq!(report.queued, 1);
        assert!(bench.teardowns.of(tenant.id()).is_some());
        assert_eq!(bench.queue.jobs_of(TEARDOWN_STEP_JOB).len(), 1);
    }

    /// The deletion is delivered twice. Nothing is queued twice.
    #[test]
    fn an_announcement_repeated_queues_nothing_twice() {
        let tenant = test_tenant_deleted();
        let bench = bench(tenant.clone());
        bench.plan(published(sample_tenant_deleted(*tenant.id())));

        let again = bench.plan(published(sample_tenant_deleted(*tenant.id())));

        assert_eq!((again.queued, again.already_queued), (0, 1));
        assert_eq!(bench.queue.jobs_of(TEARDOWN_STEP_JOB).len(), 1);
    }

    /// A deletion event for a provisioning tenant produces an empty planning
    /// report and creates no teardown.
    #[test]
    fn a_tenant_not_deleted_is_not_torn_down() {
        let tenant = test_tenant("acme", "acme.com");
        let bench = bench(tenant.clone());

        let report = bench.plan(published(sample_tenant_deleted(*tenant.id())));

        assert_eq!(report, PlanReport::default());
        assert!(bench.teardowns.of(tenant.id()).is_none());
    }

    /// Any other event plans no teardown, even for a deleted tenant.
    #[test]
    fn another_event_plans_nothing() {
        let tenant = test_tenant_deleted();
        let bench = bench(tenant.clone());

        let report = bench.plan(published(sample_tenant_event(*tenant.id())));

        assert_eq!(report, PlanReport::default());
        assert!(bench.teardowns.of(tenant.id()).is_none());
    }
}
