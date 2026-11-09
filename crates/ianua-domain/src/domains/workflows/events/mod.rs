//! Events for workflow versions, executions and their steps, integration
//! accounts and risk overrides.
//!
//! An execution's events come from the records its changes hand back,
//! through [`execution_events`]. So every step that starts, succeeds, fails
//! or is skipped reaches the audit trail by one path.

use time::OffsetDateTime;

use crate::domains::workflows::design::node::{NodeKey, Port};
use crate::domains::workflows::design::workflow::{FailureAlert, MissingAccount};
use crate::domains::workflows::execution::WorkflowExecution;
use crate::domains::workflows::execution::record::{
    ExecutionEnd, ExecutionRecord, ItemsShown, StepRecord,
};
use crate::domains::workflows::execution::step::StepFailure;
use crate::isolation::scope::TenantScope;
use crate::shared::events::data::{EventData, RefKind, Reference};
use crate::shared::events::event::{DomainEvent, tenant_event};
use crate::shared::events::raised::scoped;
use crate::types::event_type::WorkflowsEvent;
use crate::types::{EventLabel, PrincipalRef, TenantId, WorkflowExecutionId, WorkflowId};

mod account;
mod channel;
mod connection;
mod evaluation;
mod flow;
mod guardrail;
mod pass;
mod retry;
mod risk;
mod sandbox;
mod start;
mod subscription;
mod test;
mod trigger_secret;
mod watch;

pub use account::*;
pub(crate) use channel::{
    AccountChannelClosed, AccountChannelLapsed, AccountChannelReady, AccountChannelTokenShown,
    ChannelRef,
};
pub use connection::*;
pub(crate) use evaluation::{
    EvaluationEnded, EvaluationRef, EvaluationSetSaved, EvaluationStarted,
};
pub(crate) use flow::{WorkflowFlowCreated, WorkflowFlowDeleted};
pub(crate) use guardrail::WorkflowGuardrailFound;
pub(crate) use retry::{WorkflowStepCallTurnedAway, WorkflowStepDeferred};
pub use risk::*;
pub use sandbox::*;
pub(crate) use start::{WorkflowExecutionStarted, WorkflowStartRefused};
pub(crate) use subscription::{
    ServiceSubscriptionLapsed, ServiceSubscriptionRegistered, ServiceSubscriptionRemoved,
    SubscriptionRef,
};
pub(crate) use test::WorkflowTestEnded;
pub(crate) use trigger_secret::{
    TriggerSecretRef, WorkflowTriggerSecretIssued, WorkflowTriggerSecretRevoked,
    WorkflowTriggerSecretRotated,
};
pub use watch::*;

/// The reference kind for a workflow.
const WORKFLOW: RefKind = RefKind::new("workflow");
/// The reference kind for one execution of a workflow.
const EXECUTION: RefKind = RefKind::new("workflow_execution");
/// The reference kind for an integration account.
const ACCOUNT: RefKind = RefKind::new("integration_account");

/// Which version of a workflow an event is about.
#[derive(Debug, Clone)]
pub(crate) struct VersionRef {
    /// The stable identity shared by every revision of this automation.
    pub(crate) workflow_id: WorkflowId,
    /// The positive revision sequence identifying the affected definition.
    pub(crate) version: u32,
    /// The workflow's name when the event fired.
    pub(crate) label: EventLabel,
}

impl VersionRef {
    fn payload(&self) -> EventData {
        EventData::new()
            .reference(
                "workflow",
                Reference::new(WORKFLOW, self.workflow_id.to_string(), self.label.as_str()),
            )
            .field("version", self.version.to_string())
    }
}

macro_rules! version_event {
    ($(#[$meta:meta])* $name:ident => $kind:ident) => {
        $(#[$meta])*
        #[derive(Debug)]
        pub struct $name {
            /// The version.
            pub(crate) version: VersionRef,
            /// When it happened.
            pub(crate) occurred_at: OffsetDateTime,
        }

        tenant_event! {
            $name => WorkflowsEvent::$kind,
            fn payload(&self) -> EventData {
                self.version.payload()
            }
        }
    };
}

version_event! {
    /// A workflow's first version was drafted.
    WorkflowCreated => WorkflowCreated
}

version_event! {
    /// A workflow's next version was drafted.
    WorkflowVersionDrafted => VersionDrafted
}

version_event! {
    /// A draft was renamed.
    WorkflowDraftRenamed => DraftRenamed
}

version_event! {
    /// A draft's steps and edges were replaced.
    WorkflowDraftStepsReplaced => DraftStepsReplaced
}

version_event! {
    /// What starts a draft was changed.
    WorkflowDraftTriggerChanged => DraftTriggerChanged
}

version_event! {
    /// How long a draft's executions may run was changed.
    WorkflowDraftRunLimitChanged => DraftRunLimitChanged
}

version_event! {
    /// What a draft does was described, or its description taken away.
    WorkflowDraftDescribed => DraftDescribed
}

version_event! {
    /// Who is told when a run of a draft fails was changed.
    WorkflowDraftFailureAlertChanged => DraftFailureAlertChanged
}

version_event! {
    /// A version was published.
    WorkflowVersionPublished => VersionPublished
}

version_event! {
    /// A version was archived.
    WorkflowVersionArchived => VersionArchived
}

/// A version in service was held because an account it acts through can
/// no longer be used for its publisher; nothing starts it until a next
/// version is published.
#[derive(Debug)]
pub(crate) struct WorkflowVersionHeld {
    /// The published definition prevented from starting because its account is unusable.
    pub(crate) version: VersionRef,
    /// The account it needs, where, and why it cannot be used.
    pub(crate) missing: MissingAccount,
    /// When it was held.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    WorkflowVersionHeld => WorkflowsEvent::VersionHeld,
    fn payload(&self) -> EventData {
        self.version
            .payload()
            .reference(
                "account",
                Reference::new(ACCOUNT, self.missing.account.to_string(), "integration account"),
            )
            .field("at", self.missing.at.as_str().to_owned())
            .field("reason", self.missing.why.as_str().to_owned())
    }
}

/// Which execution an event is about.
#[derive(Debug, Clone)]
pub(crate) struct ExecutionRef {
    /// The run identity correlating its steps and final outcome.
    pub(crate) execution_id: WorkflowExecutionId,
    /// The workflow it runs.
    pub(crate) workflow_id: WorkflowId,
    /// The version it runs.
    pub(crate) version: u32,
}

impl ExecutionRef {
    fn payload(&self) -> EventData {
        EventData::new()
            .reference(
                "execution",
                Reference::new(
                    EXECUTION,
                    self.execution_id.to_string(),
                    self.execution_id.to_string(),
                ),
            )
            .field("workflow_id", self.workflow_id.to_string())
            .field("version", self.version.to_string())
    }
}

/// Which step of which execution an event is about.
#[derive(Debug, Clone)]
pub(crate) struct StepRef {
    /// The run and definition revision containing the referenced node.
    pub(crate) execution: ExecutionRef,
    /// The step.
    pub(crate) key: NodeKey,
}

impl StepRef {
    fn payload(&self) -> EventData {
        self.execution
            .payload()
            .field("step", self.key.as_str().to_owned())
    }
}

macro_rules! bare_step_event {
    ($(#[$meta:meta])* $name:ident => $kind:ident) => {
        $(#[$meta])*
        #[derive(Debug)]
        pub struct $name {
            /// The step.
            pub(crate) step: StepRef,
            /// When it happened.
            pub(crate) occurred_at: OffsetDateTime,
        }

        impl $name {
            fn new(step: StepRef, occurred_at: OffsetDateTime) -> Self {
                Self {
                    step,
                    occurred_at,
                }
            }
        }

        tenant_event! {
            $name => WorkflowsEvent::$kind,
            fn payload(&self) -> EventData {
                self.step.payload()
            }
        }
    };
}

bare_step_event! {
    /// A step's work started outside the domain.
    WorkflowStepStarted => StepStarted
}

bare_step_event! {
    /// No path reached a step.
    WorkflowStepSkipped => StepSkipped
}

bare_step_event! {
    /// An execution ended while a step was ready or under way.
    WorkflowStepAbandoned => StepAbandoned
}

bare_step_event! {
    /// In a test, a step stood in instead of doing its work.
    WorkflowStepStoodIn => StepStoodIn
}

/// A step finished.
#[derive(Debug)]
pub(crate) struct WorkflowStepSucceeded {
    /// The node instance whose output port became available to successors.
    pub(crate) step: StepRef,
    /// The way out it left by.
    pub(crate) port: Port,
    /// When it finished.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    WorkflowStepSucceeded => WorkflowsEvent::StepSucceeded,
    fn payload(&self) -> EventData {
        self.step
            .payload()
            .field("port", self.port.as_str())
    }
}

/// Records a node's refusal reason and execution identity for the audit trail.
#[derive(Debug)]
pub(crate) struct WorkflowStepFailed {
    /// The node instance whose work ended unsuccessfully.
    pub(crate) step: StepRef,
    /// Why.
    pub(crate) failure: StepFailure,
    /// When it failed.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    WorkflowStepFailed => WorkflowsEvent::StepFailed,
    fn payload(&self) -> EventData {
        self.step
            .payload()
            .field("failure", self.failure.code())
            .field("detail", self.failure.detail())
    }
}

/// A person approved an approval step, or every item of a loop.
#[derive(Debug)]
pub(crate) struct WorkflowApprovalGranted {
    /// The approval step, or the loop whose items were approved.
    pub(crate) step: StepRef,
    /// Who approved it.
    pub(crate) by: PrincipalRef,
    /// For an approval of every item of a loop, what the approver was
    /// shown first; `None` for an approval step's own approval.
    pub(crate) shown: Option<ItemsShown>,
    /// When it was approved.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    WorkflowApprovalGranted => WorkflowsEvent::ApprovalGranted,
    fn payload(&self) -> EventData {
        let payload = self.step.payload().field("approved_by", self.by.label());
        let Some(shown) = &self.shown else {
            return payload;
        };
        payload
            .field("covers", "whole_loop")
            .field("items_shown", shown.items.to_string())
            .field("pages_opened", shown.pages.to_string())
            .field("every_item_shown_at", shown.every_item_at.to_string())
    }
}

/// Records the run's terminal outcome and the authors to notify on failure.
#[derive(Debug)]
pub(crate) struct WorkflowExecutionEnded {
    /// The run and definition revision whose work has ended.
    pub(crate) execution: ExecutionRef,
    /// How it ended.
    pub(crate) end: ExecutionEnd,
    /// Who the version it ran tells when a run fails, so notifications can
    /// reach its authors too.
    pub(crate) alert: FailureAlert,
    /// When it ended.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    WorkflowExecutionEnded => WorkflowsEvent::ExecutionEnded,
    fn payload(&self) -> EventData {
        ended_payload(&self.execution, self.end).field("alert", self.alert.as_str())
    }
}

/// What every end of an execution records: the execution, how it ended
/// and, when someone cancelled it, who.
fn ended_payload(execution: &ExecutionRef, end: ExecutionEnd) -> EventData {
    let payload = execution.payload().field("end", end.as_str());
    match end {
        ExecutionEnd::Cancelled(by) => payload.field("cancelled_by", by.label()),
        ExecutionEnd::Succeeded
        | ExecutionEnd::Failed
        | ExecutionEnd::TimedOut
        | ExecutionEnd::LoopEnded => payload,
    }
}

/// The audit events for what `execution` reports it did.
///
/// Each is marked as raised by the execution at its chain depth. So a
/// workflow these events trigger continues the chain and cannot start a new
/// one.
#[must_use]
pub fn execution_events<T: TenantScope>(
    tenant_id: TenantId,
    execution: &WorkflowExecution<T>,
    records: Vec<ExecutionRecord>,
) -> Vec<DomainEvent> {
    let reference = ExecutionRef {
        execution_id: *execution.id(),
        workflow_id: *execution.workflow_id(),
        version: execution.version(),
    };
    let occurred_at = crate::shared::clock::now();
    records
        .into_iter()
        .map(|record| {
            let at = EventAt {
                tenant_id,
                reference: reference.clone(),
                occurred_at,
            };
            execution_event(execution, at, record).from_execution(execution.chain_depth())
        })
        .collect()
}

/// Where and when every event from one batch of records happened.
struct EventAt {
    tenant_id: TenantId,
    reference: ExecutionRef,
    occurred_at: OffsetDateTime,
}

fn execution_event<T: TenantScope>(
    execution: &WorkflowExecution<T>,
    at: EventAt,
    record: ExecutionRecord,
) -> DomainEvent {
    match record {
        ExecutionRecord::Started => pass::started_event(execution, at),
        ExecutionRecord::Ended(end) => pass::ended_event(execution, at, end),
        ExecutionRecord::Step {
            key,
            happened: StepRecord::Failed(failure),
        } if execution.mode().is_test() => test::failed_step_event(at, key, failure),
        ExecutionRecord::Step { key, happened } => {
            let step = StepRef {
                execution: at.reference,
                key,
            };
            step_event(at.tenant_id, step, at.occurred_at, happened)
        }
    }
}

// One arm per step record, with no catch-all: a new record must be given
// its audit event here before it builds, so none reaches the trail
// unnamed. Splitting it would bring a catch-all back.
#[allow(clippy::too_many_lines)]
fn step_event(
    tenant_id: TenantId,
    step: StepRef,
    occurred_at: OffsetDateTime,
    happened: StepRecord,
) -> DomainEvent {
    match happened {
        StepRecord::Started => scoped(tenant_id, WorkflowStepStarted::new(step, occurred_at)),
        StepRecord::Skipped => scoped(tenant_id, WorkflowStepSkipped::new(step, occurred_at)),
        StepRecord::StoodIn => scoped(tenant_id, WorkflowStepStoodIn::new(step, occurred_at)),
        StepRecord::Abandoned => scoped(tenant_id, WorkflowStepAbandoned::new(step, occurred_at)),
        StepRecord::Succeeded(port) => scoped(
            tenant_id,
            WorkflowStepSucceeded {
                step,
                port,
                occurred_at,
            },
        ),
        StepRecord::Failed(failure) => scoped(
            tenant_id,
            WorkflowStepFailed {
                step,
                failure,
                occurred_at,
            },
        ),
        StepRecord::ApprovalGranted(by) => scoped(
            tenant_id,
            WorkflowApprovalGranted {
                step,
                by,
                shown: None,
                occurred_at,
            },
        ),
        StepRecord::ItemsApprovalGranted(shown) => scoped(
            tenant_id,
            WorkflowApprovalGranted {
                step,
                by: shown.by,
                shown: Some(shown),
                occurred_at,
            },
        ),
        StepRecord::CallTurnedAway(call) => scoped(
            tenant_id,
            WorkflowStepCallTurnedAway {
                step,
                call,
                occurred_at,
            },
        ),
        StepRecord::StartDeferred { due } => scoped(
            tenant_id,
            WorkflowStepDeferred {
                step,
                due,
                occurred_at,
            },
        ),
        StepRecord::GuardrailFound(found) => scoped(
            tenant_id,
            WorkflowGuardrailFound {
                step,
                found,
                occurred_at,
            },
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::data_classification::level::DataClassLevel;
    use crate::domains::workflows::design::node::Join;
    use crate::domains::workflows::execution::WorkflowExecution;
    use crate::domains::workflows::execution::tests::fixtures::{
        agent, agent_execution, ann, approval, by_hand, condition, draft, edge, key, managing,
        published, start, started, transform, wait,
    };
    use crate::shared::events::chain::EventOrigin;
    use crate::types::EventType;

    fn kinds(events: &[DomainEvent]) -> Vec<EventType> {
        events.iter().map(DomainEvent::event_type).collect()
    }

    /// A check passes and the run goes to "yes". The audit trail gets, in
    /// order, the start, the check and "yes" succeeding, "no" skipped and
    /// the end, with one event per record.
    #[test]
    fn every_record_becomes_one_audit_event_of_its_kind() {
        let workflow = published(
            vec![
                condition("check"),
                transform("yes", Join::All),
                transform("no", Join::All),
            ],
            vec![
                edge("check", Port::WhenTrue, "yes"),
                edge("check", Port::WhenFalse, "no"),
            ],
        );
        let (execution, records) = start(&workflow);

        let events = execution_events(TenantId::new(), &execution, records);

        assert_eq!(
            kinds(&events),
            vec![
                EventType::from(WorkflowsEvent::ExecutionStarted),
                WorkflowsEvent::StepSucceeded.into(),
                WorkflowsEvent::StepSucceeded.into(),
                WorkflowsEvent::StepSkipped.into(),
                WorkflowsEvent::ExecutionEnded.into(),
            ]
        );
    }

    /// A draft test records its approval as a stand-in and its end as a test
    /// event. Supplied failure records likewise become test-step-failed and
    /// test-ended events.
    #[test]
    fn a_test_leaves_quiet_records_of_failing_and_ending() {
        let workflow = draft(
            vec![transform("tidy", Join::All), approval("check")],
            vec![edge("tidy", Port::Next, "check")],
        );
        let (test, records) = WorkflowExecution::start_test(
            &workflow,
            managing(&ann()),
            by_hand(DataClassLevel::Internal),
            &[],
        )
        .unwrap();
        let failing = failed_test_records();

        let ended = execution_events(TenantId::new(), &test, records);
        let failed = execution_events(TenantId::new(), &test, failing);

        assert_eq!(
            kinds(&ended),
            vec![
                EventType::from(WorkflowsEvent::ExecutionStarted),
                WorkflowsEvent::StepSucceeded.into(),
                WorkflowsEvent::StepStoodIn.into(),
                WorkflowsEvent::TestEnded.into(),
            ]
        );
        assert_eq!(
            kinds(&failed),
            vec![
                EventType::from(WorkflowsEvent::TestStepFailed),
                WorkflowsEvent::TestEnded.into(),
            ]
        );
    }

    /// A failed transform followed by its failed execution, for testing quiet audit conversion.
    fn failed_test_records() -> Vec<ExecutionRecord> {
        vec![
            ExecutionRecord::Step {
                key: key("tidy"),
                happened: StepRecord::Failed(StepFailure::InputTooLarge),
            },
            ExecutionRecord::Ended(ExecutionEnd::Failed),
        ]
    }

    /// A one-step run reports its events. Each is marked as coming from that
    /// execution at its chain depth, so a workflow they trigger continues
    /// the chain and cannot start a new one.
    #[test]
    fn every_event_of_an_execution_carries_its_chain_depth() {
        let (execution, records) =
            start(&published(vec![transform("tidy", Join::All)], Vec::new()));

        let events = execution_events(TenantId::new(), &execution, records);

        assert!(!events.is_empty());
        assert!(
            events
                .iter()
                .all(|event| event.origin() == EventOrigin::Execution(execution.chain_depth()))
        );
    }

    /// Acme's plan has no room for another run, so Ann's agent step is put
    /// off. The audit trail gets one record of it, saying when it is tried
    /// again and why.
    #[test]
    fn a_step_put_off_is_audited_with_when_it_is_tried_again() {
        let agent = agent();
        let mut execution = agent_execution(&agent, &[]);
        let records = execution.defer_agent_run(&key("summarise")).unwrap();

        let events = execution_events(TenantId::new(), &execution, records);

        assert_eq!(
            kinds(&events),
            vec![EventType::from(WorkflowsEvent::StepDeferred)]
        );
        let payload = events[0].payload();
        assert!(payload.get("scheduled_at").is_some());
        assert_eq!(payload.get("reason"), Some("active_agent_run_limit"));
    }

    /// A run asks for an approval, then Ann cancels it. The audit trail
    /// gets the approval step starting, both open steps abandoned and the
    /// end.
    #[test]
    fn steps_left_behind_and_approvals_are_audited_too() {
        let mut execution = started(vec![approval("check"), wait("pause")], Vec::new());
        let mut records = execution.request_approval(&key("check")).unwrap();
        records.extend(execution.cancel(&managing(&ann())).unwrap());

        let events = execution_events(TenantId::new(), &execution, records);

        assert_eq!(
            kinds(&events),
            vec![
                EventType::from(WorkflowsEvent::StepStarted),
                WorkflowsEvent::StepAbandoned.into(),
                WorkflowsEvent::StepAbandoned.into(),
                WorkflowsEvent::ExecutionEnded.into(),
            ]
        );
    }
}
