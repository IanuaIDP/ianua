//! Plan event starts: a recorded tenant event becomes one start job for
//! each version in service that starts on it, keyed by the event and the
//! workflow, so a repeated delivery of the event starts nothing twice.

use std::sync::Arc;

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::shared::PublishedEvent;
use crate::ports::workflows::WorkflowStore;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::scheduling::PlanReport;
use crate::use_cases::workflows::executions::starts::event_job::EventStarts;

/// The ports [`PlanEventStartsUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct PlanEventStartsPorts {
    /// The versions, for the ones in service that start on the event.
    pub workflows: Arc<dyn WorkflowStore>,
    /// Where event start jobs are queued.
    pub jobs: EventStarts,
}

/// Plans the workflow starts a recorded event means.
///
/// The event pipeline runs it, for nobody, so its caller is `()`.
pub struct PlanEventStartsUseCase {
    ports: PlanEventStartsPorts,
}

impl PlanEventStartsUseCase {
    /// A planner over `ports`.
    #[must_use]
    pub fn new(ports: PlanEventStartsPorts) -> Self {
        Self { ports }
    }
}

impl Command for PlanEventStartsUseCase {
    type Caller = ();
    type Input = PublishedEvent;
    type Output = Result<PlanReport, AppError>;

    /// Queues one start job for each of the tenant's versions in service
    /// that start on `event`'s type, carrying where the event came from.
    /// An event of no tenant plans nothing. Records nothing: planning only
    /// queues work, and each start records itself or its refusal.
    ///
    /// # Errors
    ///
    /// - `AppError::Internal` when the versions cannot be read or a job
    ///   cannot be queued. The pipeline delivers the event again, and what
    ///   was queued is not queued twice.
    async fn execute(
        &self,
        (): &(),
        _auditor: &RequestAuditor,
        event: PublishedEvent,
    ) -> Result<PlanReport, AppError> {
        let Some(tenant_id) = event.event.tenant_id().copied() else {
            return Ok(PlanReport::default());
        };
        let tenant = ScopedTenant::for_background(tenant_id);
        let versions = self
            .ports
            .workflows
            .list_published_on(&tenant, event.event.event_type())
            .await
            .or_internal()?;
        let origin = event.event.origin();
        let mut report = PlanReport::default();
        for workflow in &versions {
            let enqueued = self
                .ports
                .jobs
                .queue(tenant_id, *workflow.id(), event.id, origin)
                .await?;
            report = report.counting(enqueued);
        }
        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;

    use ianua_domain::domains::audit::builder::AuditContext;
    use ianua_domain::domains::workflows::triggers::{EventTrigger, Trigger};
    use ianua_domain::test_support::events::sample_tenant_event;
    use ianua_domain::types::AuditRecordId;
    use ianua_domain::types::event_type::{EventType, MessagingEvent};

    use super::*;
    use crate::test_support::scheduling::FakeJobQueue;
    use crate::test_support::workflows::{
        FakeWorkflowStore, draft_on, person, published_by, tidy_step,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};
    use crate::use_cases::workflows::executions::starts::event_job::START_ON_EVENT_JOB;

    struct Setup {
        uc: PlanEventStartsUseCase,
        queue: Arc<FakeJobQueue>,
    }

    /// Ann's workflow, published to start when a topic is paused.
    fn setup() -> Setup {
        let ann = person("ann@corp.test");
        let paused = EventType::from(MessagingEvent::TopicPaused);
        let draft = draft_on(
            &ann,
            vec![tidy_step("tidy")],
            Vec::new(),
            Trigger::Event(EventTrigger::new(paused).unwrap()),
        );
        let queue = Arc::new(FakeJobQueue::new());
        let uc = PlanEventStartsUseCase::new(PlanEventStartsPorts {
            workflows: Arc::new(FakeWorkflowStore::holding(&[published_by(&ann, draft)])),
            jobs: EventStarts {
                queue: queue.clone(),
                attempts: NonZeroU32::MIN,
            },
        });
        Setup { uc, queue }
    }

    fn topic_paused(id: AuditRecordId) -> PublishedEvent {
        PublishedEvent {
            id,
            event: sample_tenant_event(test_ctx().tenant_id()),
            context: AuditContext::system(),
        }
    }

    fn plan(setup: &Setup, event: PublishedEvent) -> PlanReport {
        block_on(setup.uc.execute(
            &(),
            &test_auditor(Arc::new(FakeEventDispatcher::new())),
            event,
        ))
        .unwrap()
    }

    /// A topic is paused, and Ann's workflow starts on that. One start job
    /// is queued for it.
    #[test]
    fn each_version_on_the_event_gets_one_job() {
        let setup = setup();

        let report = plan(&setup, topic_paused(AuditRecordId::new()));

        assert_eq!(report.queued, 1);
        assert_eq!(setup.queue.jobs_of(START_ON_EVENT_JOB).len(), 1);
    }

    /// The pipeline delivers the event twice. The workflow is planned to
    /// start once.
    #[test]
    fn a_repeated_event_starts_nothing_twice() {
        let setup = setup();
        let id = AuditRecordId::new();

        plan(&setup, topic_paused(id));
        let second = plan(&setup, topic_paused(id));

        assert_eq!((second.queued, second.already_queued), (0, 1));
    }
}
