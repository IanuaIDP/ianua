//! What recorded events show those who watch workflows: a run's moments,
//! for whoever has the run open, a change to a draft, for whoever has the
//! draft open, and a failed run whose authors are told too.

use crate::domains::workflows::design::node::NodeKey;
use crate::domains::workflows::design::workflow::FailureAlert;
use crate::shared::events::event::DomainEvent;
use crate::types::event_type::WorkflowsEvent;
use crate::types::{EventType, TenantId, WorkflowExecutionId, WorkflowId};

/// What just happened in one run, as its watchers are shown it live.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunMoment {
    /// The tenant the run is in.
    pub tenant_id: TenantId,
    /// The run.
    pub execution_id: WorkflowExecutionId,
    /// What happened.
    pub happened: RunHappening,
}

/// One thing that happens in a run that its watchers see.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunHappening {
    /// The execution has become available for watchers to follow.
    Started,
    /// A step's work began outside, or it began waiting for a person.
    StepStarted(NodeKey),
    /// A step finished.
    StepSucceeded(NodeKey),
    /// The named node ended unsuccessfully; watchers may read its permitted details.
    StepFailed(NodeKey),
    /// In a test, a step stood in.
    StepStoodIn(NodeKey),
    /// No path reached a step.
    StepSkipped(NodeKey),
    /// Someone approved a step.
    StepApproved(NodeKey),
    /// The execution reached a terminal outcome, without exposing who cancelled it.
    Ended(RunEnd),
}

/// How a run ended, as its watchers are shown it: without who cancelled
/// it, which the run itself shows to whoever may read it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunEnd {
    /// Every step it reached finished.
    Succeeded,
    /// A step failed.
    Failed,
    /// Someone cancelled it.
    Cancelled,
    /// It ran out of time.
    TimedOut,
    /// It was a loop's pass, stopped as its loop ended.
    LoopEnded,
}

impl RunEnd {
    /// Every way a run ends.
    const ALL: [Self; 5] = [
        Self::Succeeded,
        Self::Failed,
        Self::Cancelled,
        Self::TimedOut,
        Self::LoopEnded,
    ];

    /// The end `name` names, as an execution's end is recorded; `None` for
    /// a name that is none.
    #[must_use]
    pub fn named(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|end| end.as_str() == name)
    }

    /// Its name, as an execution's end is recorded.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::TimedOut => "timed_out",
            Self::LoopEnded => "loop_ended",
        }
    }
}

/// The moment a step's event shows, made from the step.
type StepMoment = fn(NodeKey) -> RunHappening;

/// The events of one step that a run's watchers see, each with the moment
/// it shows.
const STEP_MOMENTS: [(WorkflowsEvent, StepMoment); 7] = [
    (WorkflowsEvent::StepStarted, RunHappening::StepStarted),
    (WorkflowsEvent::StepSucceeded, RunHappening::StepSucceeded),
    (WorkflowsEvent::StepFailed, RunHappening::StepFailed),
    (WorkflowsEvent::TestStepFailed, RunHappening::StepFailed),
    (WorkflowsEvent::StepStoodIn, RunHappening::StepStoodIn),
    (WorkflowsEvent::StepSkipped, RunHappening::StepSkipped),
    (WorkflowsEvent::ApprovalGranted, RunHappening::StepApproved),
];

/// What `event` shows a run's watchers, when it is about a run; `None`
/// for every other event, and for the passes of loops, which their run's
/// own loop step stands for.
#[must_use]
pub fn run_moment(event: &DomainEvent) -> Option<RunMoment> {
    let DomainEvent::Tenant { event: inner, .. } = event else {
        return None;
    };
    let EventType::Workflows(kind) = inner.event_type() else {
        return None;
    };
    let payload = inner.payload();
    let step = || payload.get("step").and_then(|key| NodeKey::new(key).ok());
    let of_a_step = STEP_MOMENTS.iter().find(|(shown, _)| *shown == kind);
    let happened = match of_a_step {
        Some((_, moment)) => moment(step()?),
        None if kind == WorkflowsEvent::ExecutionStarted => RunHappening::Started,
        None if matches!(
            kind,
            WorkflowsEvent::ExecutionEnded | WorkflowsEvent::TestEnded
        ) =>
        {
            RunHappening::Ended(RunEnd::named(payload.get("end")?)?)
        }
        None => return None,
    };
    let execution = uuid::Uuid::parse_str(payload.get("execution")?).ok()?;
    Some(RunMoment {
        tenant_id: *inner.tenant_id(),
        execution_id: WorkflowExecutionId::from_uuid(execution),
        happened,
    })
}

/// The tenant and workflow whose draft `event` changed, so whoever has it
/// open sees someone else changed it; `None` for every other event.
#[must_use]
pub fn draft_changed(event: &DomainEvent) -> Option<(TenantId, WorkflowId)> {
    let DomainEvent::Tenant { event: inner, .. } = event else {
        return None;
    };
    let EventType::Workflows(kind) = inner.event_type() else {
        return None;
    };
    let edit = matches!(
        kind,
        WorkflowsEvent::DraftRenamed
            | WorkflowsEvent::DraftStepsReplaced
            | WorkflowsEvent::DraftTriggerChanged
            | WorkflowsEvent::DraftRunLimitChanged
            | WorkflowsEvent::DraftDescribed
            | WorkflowsEvent::DraftFailureAlertChanged
            | WorkflowsEvent::VersionPublished
    );
    if !edit {
        return None;
    }
    let workflow = uuid::Uuid::parse_str(inner.payload().get("workflow")?).ok()?;
    Some((*inner.tenant_id(), WorkflowId::from_uuid(workflow)))
}

/// The tenant and run whose authors are told too, when `event` is a run
/// that failed or ran out of time and whose version asked for its authors
/// to hear of that. `None` for every other event.
#[must_use]
pub fn failed_run_telling_authors(event: &DomainEvent) -> Option<(TenantId, WorkflowExecutionId)> {
    let DomainEvent::Tenant { event: inner, .. } = event else {
        return None;
    };
    if inner.event_type() != WorkflowsEvent::ExecutionEnded.into() {
        return None;
    }
    let payload = inner.payload();
    let failed = matches!(
        RunEnd::named(payload.get("end")?),
        Some(RunEnd::Failed | RunEnd::TimedOut)
    );
    if !failed || payload.get("alert")? != FailureAlert::AlsoAuthors.as_str() {
        return None;
    }
    let execution = uuid::Uuid::parse_str(payload.get("execution")?).ok()?;
    Some((
        *inner.tenant_id(),
        WorkflowExecutionId::from_uuid(execution),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::workflows::events::{ExecutionRef, WorkflowExecutionEnded};
    use crate::domains::workflows::execution::record::ExecutionEnd;
    use crate::shared::events::raised::scoped;

    fn ended(
        end: ExecutionEnd,
        alert: FailureAlert,
    ) -> (TenantId, WorkflowExecutionId, DomainEvent) {
        let tenant = TenantId::new();
        let execution_id = WorkflowExecutionId::new();
        let event = scoped(
            tenant,
            WorkflowExecutionEnded {
                execution: ExecutionRef {
                    execution_id,
                    workflow_id: WorkflowId::new(),
                    version: 1,
                },
                end,
                alert,
                occurred_at: crate::shared::clock::now(),
            },
        );
        (tenant, execution_id, event)
    }

    /// Ann's version tells its authors of failures. A run of it that fails
    /// names the run whose authors are told; one that times out does too.
    #[test]
    fn a_failed_run_of_a_version_telling_authors_names_the_run() {
        for end in [ExecutionEnd::Failed, ExecutionEnd::TimedOut] {
            let (tenant, execution_id, event) = ended(end, FailureAlert::AlsoAuthors);

            assert_eq!(
                failed_run_telling_authors(&event),
                Some((tenant, execution_id))
            );
        }
    }

    /// A run that ends is shown to its watchers as ended, with how; a
    /// draft's edit is not a run's moment but a change to that draft.
    #[test]
    fn a_runs_end_is_a_moment_its_watchers_see() {
        let (tenant, execution_id, event) =
            ended(ExecutionEnd::Failed, FailureAlert::Administrators);

        assert_eq!(
            run_moment(&event),
            Some(RunMoment {
                tenant_id: tenant,
                execution_id,
                happened: RunHappening::Ended(RunEnd::Failed),
            })
        );
        assert_eq!(draft_changed(&event), None);
    }

    /// A run that succeeds tells no authors, and neither does a failed run
    /// of a version that tells only the administrators.
    #[test]
    fn other_ends_and_versions_tell_no_authors() {
        let (_, _, succeeded) = ended(ExecutionEnd::Succeeded, FailureAlert::AlsoAuthors);
        let (_, _, admins_only) = ended(ExecutionEnd::Failed, FailureAlert::Administrators);

        assert_eq!(failed_run_telling_authors(&succeeded), None);
        assert_eq!(failed_run_telling_authors(&admins_only), None);
    }

    /// Successful, failed, timed-out and loop-ended runs read back under their
    /// recorded names; `paused` is not recognized as a run end.
    #[test]
    fn a_run_end_is_named_as_its_execution_records_it() {
        for end in [
            ExecutionEnd::Succeeded,
            ExecutionEnd::Failed,
            ExecutionEnd::TimedOut,
            ExecutionEnd::LoopEnded,
        ] {
            assert_eq!(
                RunEnd::named(end.as_str()).map(RunEnd::as_str),
                Some(end.as_str())
            );
        }
        assert_eq!(RunEnd::named("paused"), None);
    }
}
