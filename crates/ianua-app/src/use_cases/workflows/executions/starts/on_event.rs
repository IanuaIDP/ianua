//! Start on event: something happened in the tenant, and a published
//! version that starts on it starts for its publisher.
//!
//! An event job runs this, one per event and version, planned when the
//! event was recorded. The event is read back from its record, and its
//! details are what the workflow is handed.
//!
//! The event's origin goes with it. An event an execution's work raised
//! starts the next one a step deeper in the same chain, and a chain stops at
//! its limit, so two workflows cannot set each other off without end.

use std::sync::Arc;

use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::domains::workflows::execution::Cause;
use ianua_domain::domains::workflows::triggers::event_input::event_input;
use ianua_domain::message;
use ianua_domain::shared::events::chain::EventOrigin;
use ianua_domain::types::{AuditRecordId, WorkflowId};

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal, OrNotFound};
use crate::ports::shared::RecordedEvents;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::workflows::executions::starts::triggered::{
    Admission, Firing, started_for_publisher,
};
use crate::use_cases::workflows::executions::{TriggerStartPorts, TriggeredStart};
use crate::use_cases::workflows::lookup::published_version;

/// The data class an event's details are handed to a workflow under: they
/// are the tenant's own, and stay inside it.
const EVENT_EXPOSURE: DataClassLevel = DataClassLevel::Internal;

/// An event that happened in the tenant, as one workflow is handed it.
pub struct StartOnEventRequest {
    /// The workflow whose version in service starts on the event.
    pub workflow_id: WorkflowId,
    /// The event's audit record.
    pub record_id: AuditRecordId,
    /// Where it came from: outside any workflow, or an execution's work.
    pub origin: EventOrigin,
}

/// The ports [`StartOnEventUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct StartOnEventPorts {
    /// What a start for a workflow's publisher needs.
    pub starts: TriggerStartPorts,
    /// The tenant's recorded events, read back by id.
    pub records: Arc<dyn RecordedEvents>,
}

/// Starts a version in service that starts on an event.
pub struct StartOnEventUseCase {
    ports: StartOnEventPorts,
}

impl StartOnEventUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: StartOnEventPorts) -> Self {
        Self { ports }
    }
}

impl Command for StartOnEventUseCase {
    type Caller = ScopedTenant;
    type Input = StartOnEventRequest;
    type Output = Result<TriggeredStart, AppError>;

    /// Starts the version of `request.workflow_id` in service for its
    /// publisher, on the event `request.record_id` recorded, and says how
    /// it came out.
    ///
    /// # Errors
    ///
    /// - `AppError::NotFound` when the event's record is gone, or no
    ///   version of the workflow is published.
    /// - `AppError::Domain` when the version does not start on the event,
    ///   as when it was republished on another trigger since.
    /// - `AppError::Internal` when the record or the version cannot be
    ///   read, the event's details are too large to hand on, a publisher's
    ///   records name a role that is not there, or the start or its record
    ///   cannot be kept.
    async fn execute(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        request: StartOnEventRequest,
    ) -> Result<TriggeredStart, AppError> {
        let record = self
            .ports
            .records
            .find(tenant, &request.record_id)
            .await
            .or_internal()?
            .or_not_found(message!("workflows-event-record", "event record"))?;
        let starts = &self.ports.starts;
        let workflow =
            published_version(starts.workflows.as_ref(), tenant, &request.workflow_id).await?;
        let firing = Firing {
            cause: Cause::Event {
                event: record.event_type,
                origin: request.origin,
            },
            admission: Admission::Trigger,
            input: event_input(&record.payload).or_internal()?,
            exposure: EVENT_EXPOSURE,
        };
        started_for_publisher(starts, tenant, auditor, &workflow, firing).await
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{SystemPermission, WorkflowAction};
    use ianua_domain::domains::workflows::execution::StartRefusal;
    use ianua_domain::domains::workflows::triggers::{EventTrigger, Trigger};
    use ianua_domain::shared::events::chain::{ChainDepth, MAX_CHAIN_DEPTH};
    use ianua_domain::types::event_type::IdentityEvent;
    use ianua_domain::types::{EventType, Human};

    use super::*;
    use crate::test_support::tenant::{FakeRecordedEvents, test_audit_record};
    use crate::test_support::workflows::{
        FakeWorkflowExecutionStore, FakeWorkflowStore, accounts_now_of, draft_on, person,
        published_by, tidy_step,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    const REGISTERED: EventType = EventType::Identity(IdentityEvent::UserRegistered);

    fn on_registration(publisher: &Human) -> (FakeWorkflowStore, WorkflowId) {
        let draft = draft_on(
            publisher,
            vec![tidy_step("welcome")],
            Vec::new(),
            Trigger::Event(EventTrigger::new(REGISTERED).unwrap()),
        );
        let published = published_by(publisher, draft);
        let id = *published.id();
        (FakeWorkflowStore::holding(&[published]), id)
    }

    /// A user registered in the test tenant, and the record of it.
    fn registration() -> (FakeRecordedEvents, AuditRecordId) {
        let record = test_audit_record(test_ctx().tenant_id(), REGISTERED.as_str());
        let id = record.id;
        (FakeRecordedEvents::holding([record]), id)
    }

    fn start(
        starts: TriggerStartPorts,
        workflow_id: WorkflowId,
        sink: Arc<FakeEventDispatcher>,
        origin: EventOrigin,
    ) -> Result<TriggeredStart, AppError> {
        let (records, record_id) = registration();
        let use_case = StartOnEventUseCase::new(StartOnEventPorts {
            starts,
            records: Arc::new(records),
        });
        let request = StartOnEventRequest {
            workflow_id,
            record_id,
            origin,
        };
        block_on(use_case.execute(&test_ctx().tenant(), &test_auditor(sink), request))
    }

    /// Ann published a welcome workflow on new registrations and may still
    /// run it. A user registers, and it starts for Ann.
    #[test]
    fn an_event_starts_the_version_on_it_for_its_publisher() {
        let ann = person("ann@corp.test");
        let (workflows, id) = on_registration(&ann);
        let executions = Arc::new(FakeWorkflowExecutionStore::empty());
        let starts = TriggerStartPorts {
            workflows: Arc::new(workflows),
            executions: executions.clone(),
            accounts_now: Arc::new(accounts_now_of(&[(&ann, SystemPermission::all())])),
            ..TriggerStartPorts::fakes()
        };

        let outcome = start(
            starts,
            id,
            Arc::new(FakeEventDispatcher::new()),
            EventOrigin::Outside,
        );

        assert!(matches!(outcome, Ok(TriggeredStart::Started(_))));
        assert!(executions.all()[0].acting_for().is_same_account_as(&ann));
    }

    /// An event at the execution-chain limit returns chain-too-long without
    /// saving an execution or recording an audit event.
    #[test]
    fn an_event_from_a_chain_at_its_limit_starts_nothing() {
        let ann = person("ann@corp.test");
        let (workflows, id) = on_registration(&ann);
        let sink = Arc::new(FakeEventDispatcher::new());
        let executions = Arc::new(FakeWorkflowExecutionStore::empty());
        let starts = TriggerStartPorts {
            workflows: Arc::new(workflows),
            executions: executions.clone(),
            accounts_now: Arc::new(accounts_now_of(&[(&ann, SystemPermission::all())])),
            ..TriggerStartPorts::fakes()
        };
        let last = ChainDepth::from_stored(MAX_CHAIN_DEPTH).unwrap();

        let outcome = start(starts, id, sink.clone(), EventOrigin::Execution(last));

        assert!(matches!(outcome, Ok(TriggeredStart::ChainTooLong)));
        assert!(executions.all().is_empty());
        assert!(sink.records.lock().unwrap().is_empty());
    }

    /// A registration event cannot start its workflow for a missing publisher;
    /// the refusal is recorded in the audit trail.
    #[test]
    fn a_version_whose_publisher_left_is_refused_out_loud() {
        let ann = person("ann@corp.test");
        let (workflows, id) = on_registration(&ann);
        let sink = Arc::new(FakeEventDispatcher::new());
        let starts = TriggerStartPorts {
            workflows: Arc::new(workflows),
            ..TriggerStartPorts::fakes()
        };

        let outcome = start(starts, id, sink.clone(), EventOrigin::Outside);

        assert!(matches!(outcome, Ok(TriggeredStart::Refused(_))));
        assert_eq!(*sink.records.lock().unwrap(), ["workflows.start_refused"]);
    }

    /// Run rights alone do not permit starting on a user event the publisher
    /// cannot view. The event-visibility refusal saves no execution and is audited.
    #[test]
    fn an_event_the_publisher_may_no_longer_see_is_refused_out_loud() {
        let ann = person("ann@corp.test");
        let (workflows, id) = on_registration(&ann);
        let sink = Arc::new(FakeEventDispatcher::new());
        let executions = Arc::new(FakeWorkflowExecutionStore::empty());
        let runs_only = [SystemPermission::Workflows(WorkflowAction::Run)];
        let starts = TriggerStartPorts {
            workflows: Arc::new(workflows),
            executions: executions.clone(),
            accounts_now: Arc::new(accounts_now_of(&[(&ann, &runs_only)])),
            ..TriggerStartPorts::fakes()
        };

        let outcome = start(starts, id, sink.clone(), EventOrigin::Outside);

        assert!(matches!(
            outcome,
            Ok(TriggeredStart::Refused(StartRefusal::EventNotVisible))
        ));
        assert!(executions.all().is_empty());
        assert_eq!(*sink.records.lock().unwrap(), ["workflows.start_refused"]);
    }

    /// The welcome workflow was unpublished while its start waited. Nothing
    /// starts, and the job knows it is gone.
    #[test]
    fn a_workflow_no_longer_published_is_not_found() {
        let outcome = start(
            TriggerStartPorts::fakes(),
            WorkflowId::new(),
            Arc::new(FakeEventDispatcher::new()),
            EventOrigin::Outside,
        );

        assert!(matches!(outcome, Err(AppError::NotFound(_))));
    }
}
