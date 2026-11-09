//! Starting a failed execution again: from the trigger, or from the steps
//! that did not finish.
//!
//! The run that failed stays as it ended, for the audit trail. Starting it
//! again makes a new execution of the same version, with the same trigger's
//! data, acting for the person the failed run acted for. Only that person
//! starts it again: the steps it keeps produced their outputs with their
//! authority, and anyone else would read them.
//!
//! An approval is never kept. It covered the failed run for a while, and
//! is asked for again, so no action runs on a stale yes.

use crate::domains::agents::authority::delegation::HeldResources;
use crate::domains::authorization::permission::WorkflowAction;
use crate::domains::workflows::control::WorkflowControl;
use crate::domains::workflows::design::node::NodeKey;
use crate::domains::workflows::design::workflow::{Workflow, WorkflowStatus};
use crate::domains::workflows::execution::record::{ExecutionEnd, ExecutionRecord};
use crate::domains::workflows::execution::step::{Holding, StepState};
use crate::domains::workflows::execution::{
    ActingAuthority, Cause, ExecutionStatus, StartExecutionParams, StartRefusal, WorkflowExecution,
};
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::chain::ChainDepth;
use crate::types::Human;

/// Where a failed execution started again picks up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestartFrom {
    /// From the trigger: every step runs again.
    Beginning,
    /// From the steps that did not finish. A step that finished for good,
    /// and every step that led to it, keeps what it produced. The rest run
    /// again.
    FailedStep,
}

impl RestartFrom {
    /// The stored and audited name of a start made this way.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Beginning => "rerun",
            Self::FailedStep => "retry",
        }
    }
}

/// What a person starts a failed execution again with.
pub struct RestartParams {
    /// The relationship graph's answer for the person starting it again:
    /// the resources they were given use of. Their permissions come from
    /// their control.
    pub resources: HeldResources,
    /// Where it picks up.
    pub from: RestartFrom,
}

impl<T: TenantScope> WorkflowExecution<T> {
    /// `by` starts this failed execution of `workflow` again, from where
    /// `params.from` says, with the trigger's data it had. Every step the
    /// domain finishes itself runs as far as it goes.
    ///
    /// The new execution acts for `by` with what they hold now, so a person
    /// who lost a right since does not get it back through an old run.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::Forbidden`] without run rights, for another acting person,
    /// or for resources resolved for someone else.
    /// Returns [`DomainError::Conflict`] unless failed or timed out, for loop passes
    /// or test runs, or for a different or no-longer-published workflow version.
    pub fn restart(
        &self,
        workflow: &Workflow<T>,
        by: WorkflowControl<'_>,
        params: RestartParams,
    ) -> Result<(Self, Vec<ExecutionRecord>), DomainError> {
        let RestartParams { resources, from } = params;
        by.ensure_may(WorkflowAction::Run)?;
        self.ensure_restartable_by(by.by())?;
        self.ensure_still_runs(workflow)?;
        let start = StartExecutionParams {
            acting_for: ActingAuthority::of_signed_in(by.authority(), &resources)?,
            cause: Cause::Restart { of: self.id, from },
            input: self.input.clone(),
            exposure: self.exposure,
        };
        if let Some(refusal) = StartRefusal::of(workflow, &start) {
            return Err(refusal.into());
        }
        let mut restarted = Self::fresh(workflow, start, ChainDepth::FIRST);
        restarted.steps = self.kept_for(from);
        let mut records = vec![ExecutionRecord::Started];
        restarted.advance(&mut records);
        Ok((restarted, records))
    }

    /// Refuses a start again by anyone but the person it acted for, or of a
    /// run that did not fail or run out of time.
    fn ensure_restartable_by(&self, person: &Human) -> Result<(), DomainError> {
        if self.mode.is_test() {
            return Err(DomainError::conflict(message!(
                "workflows-a-test-is-run-again-as-a-new-test",
                "a test is run again as a new test, never started again as a real run"
            )));
        }
        if self.pass.is_some() {
            return Err(DomainError::conflict(message!(
                "workflows-a-pass-is-started-again-with-its-run",
                "a pass of a loop is started again only with the run it belongs to"
            )));
        }
        if !person.is_same_person_as(&self.acting_for) {
            return Err(DomainError::forbidden(message!(
                "workflows-only-the-person-a-run-acted",
                "only the person a run acted for starts it again"
            )));
        }
        match self.status {
            ExecutionStatus::Ended(ExecutionEnd::Failed | ExecutionEnd::TimedOut) => Ok(()),
            ExecutionStatus::Running
            | ExecutionStatus::Ended(
                ExecutionEnd::Succeeded | ExecutionEnd::Cancelled(_) | ExecutionEnd::LoopEnded,
            ) => Err(DomainError::conflict(message!(
                "workflows-only-a-run-that-failed-or",
                "only a run that failed or ran out of time is started again"
            ))),
        }
    }

    /// Refuses `workflow` unless it is the version this ran, still in
    /// service.
    fn ensure_still_runs(&self, workflow: &Workflow<T>) -> Result<(), DomainError> {
        let same_version = *workflow.id() == self.workflow_id && workflow.version() == self.version;
        if same_version && workflow.status() == WorkflowStatus::Published {
            return Ok(());
        }
        Err(DomainError::conflict(message!(
            "workflows-a-run-is-started-again-only",
            "a run is started again only on its own version, while that is still published"
        )))
    }

    /// The step states a run starting again `from` there begins with.
    fn kept_for(&self, from: RestartFrom) -> Vec<StepState> {
        match from {
            RestartFrom::Beginning => vec![StepState::Waiting; self.steps.len()],
            RestartFrom::FailedStep => self.finished_for_good(),
        }
    }

    /// Every step that finished for good, or was skipped, after steps that
    /// all did too. Everything else waits again.
    ///
    /// The steps are walked in the graph's order, so every step's leads are
    /// decided before it is.
    fn finished_for_good(&self) -> Vec<StepState> {
        let mut kept = vec![StepState::Waiting; self.steps.len()];
        for key in self.graph.in_order() {
            let Ok(index) = self.position(key) else {
                continue;
            };
            let Some(state) = self.steps.get(index).filter(|state| keeps(state)) else {
                continue;
            };
            let leads_kept = self.leads_kept(key, &kept);
            let Some(slot) = kept.get_mut(index).filter(|_| leads_kept) else {
                continue;
            };
            *slot = state.clone();
        }
        kept
    }

    /// Whether every step with an edge into `key` is kept in `kept`.
    fn leads_kept(&self, key: &NodeKey, kept: &[StepState]) -> bool {
        self.graph.incoming(key).all(|edge| {
            self.position(edge.from())
                .ok()
                .and_then(|lead| kept.get(lead))
                .is_some_and(|state| !matches!(state, StepState::Waiting))
        })
    }
}

/// Whether a step in `state` keeps it when its run starts again: it
/// finished for good, or no path reached it.
fn keeps(state: &StepState) -> bool {
    matches!(
        state,
        StepState::Succeeded {
            holds: Holding::ForGood,
            ..
        } | StepState::Skipped
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::data_classification::level::DataClassLevel;
    use crate::domains::workflows::design::node::{Join, NodeKind, Port};
    use crate::domains::workflows::design::workflow::{CodeReach, RunnableCode};
    use crate::domains::workflows::execution::record::StepRecord;
    use crate::domains::workflows::execution::tests::fixtures::{
        Execution, ann, approval, approve, bob, by_hand, code, deciding, draft, edge, key,
        managing, published, start_as, state, stored, transform,
    };
    use crate::isolation::scope::ResolvedTenant;

    /// A published version of a workflow, as these tests run it.
    type Version = Workflow<ResolvedTenant>;

    /// `person`'s answer from the relationship graph, starting again from
    /// `from`.
    fn again(person: &Human, from: RestartFrom) -> RestartParams {
        RestartParams {
            resources: HeldResources::answered(person.principal(), Vec::new()),
            from,
        }
    }

    /// Ann's run in which "tidy" ran, then Bob refused the approval
    /// "check", so the run failed.
    fn tidy_then_check() -> (Version, Execution) {
        let workflow = published(
            vec![transform("tidy", Join::All), approval("check")],
            vec![edge("tidy", Port::Next, "check")],
        );
        let (mut execution, _) =
            start_as(&workflow, &ann(), by_hand(DataClassLevel::Internal)).unwrap();
        execution.request_approval(&key("check")).unwrap();
        execution.deny(&key("check"), &deciding(&bob())).unwrap();
        (workflow, execution)
    }

    /// Ann's run failed when Bob refused its approval. She runs it again
    /// from the beginning: a new run acting for her, with the same data,
    /// whose "tidy" runs again and whose approval is asked for again.
    #[test]
    fn a_rerun_starts_every_step_again_as_a_new_run() {
        let (workflow, failed) = tidy_then_check();

        let (rerun, records) = failed
            .restart(
                &workflow,
                managing(&ann()),
                again(&ann(), RestartFrom::Beginning),
            )
            .unwrap();

        assert_ne!(rerun.id(), failed.id());
        assert_eq!(rerun.acting_for(), &ann());
        assert_eq!(rerun.input(), failed.input());
        assert_eq!(rerun.status(), ExecutionStatus::Running);
        assert_eq!(rerun.cause().as_str(), "rerun");
        assert!(records.contains(&ExecutionRecord::step(
            &key("tidy"),
            StepRecord::Succeeded(Port::Next)
        )));
        assert!(matches!(state(&rerun, "check"), StepState::Ready { .. }));
    }

    /// Ann retries her failed run from its failed step. "Tidy" keeps what
    /// it produced and does not run again; the approval is asked for again.
    #[test]
    fn a_retry_keeps_the_steps_that_finished_and_runs_the_failed_one_again() {
        let (workflow, failed) = tidy_then_check();

        let (retry, records) = failed
            .restart(
                &workflow,
                managing(&ann()),
                again(&ann(), RestartFrom::FailedStep),
            )
            .unwrap();

        assert_eq!(state(&retry, "tidy"), state(&failed, "tidy"));
        assert!(!records.contains(&ExecutionRecord::step(
            &key("tidy"),
            StepRecord::Succeeded(Port::Next)
        )));
        assert!(matches!(state(&retry, "check"), StepState::Ready { .. }));
        assert_eq!(
            retry.cause(),
            Cause::Restart {
                of: *failed.id(),
                from: RestartFrom::FailedStep
            }
        );
    }

    /// Retrying after Bob approves "first" and denies "second" makes the
    /// first approval ready again. The second step waits for that new
    /// approval.
    #[test]
    fn a_retry_asks_again_for_an_approval_the_failed_run_was_given() {
        let workflow = published(
            vec![approval("first"), approval("second")],
            vec![edge("first", Port::Next, "second")],
        );
        let (mut failed, _) =
            start_as(&workflow, &ann(), by_hand(DataClassLevel::Internal)).unwrap();
        approve(&mut failed, "first");
        failed.request_approval(&key("second")).unwrap();
        failed.deny(&key("second"), &deciding(&bob())).unwrap();

        let (retry, _) = failed
            .restart(
                &workflow,
                managing(&ann()),
                again(&ann(), RestartFrom::FailedStep),
            )
            .unwrap();

        assert!(matches!(state(&retry, "first"), StepState::Ready { .. }));
        assert_eq!(state(&retry, "second"), StepState::Waiting);
    }

    /// Workflow management rights do not let Bob retry a failed run that
    /// acted for Ann; the restart returns a forbidden error.
    #[test]
    fn only_the_person_a_run_acted_for_starts_it_again() {
        let (workflow, failed) = tidy_then_check();

        let by_bob = failed.restart(
            &workflow,
            managing(&bob()),
            again(&bob(), RestartFrom::FailedStep),
        );

        assert!(matches!(by_bob, Err(DomainError::Forbidden(_))));
    }

    /// Ann's run that succeeded, and one still running, are not started
    /// again. Each is refused as a conflict.
    #[test]
    fn only_a_failed_run_is_started_again() {
        let workflow = published(vec![transform("tidy", Join::All)], Vec::new());
        let (succeeded, _) =
            start_as(&workflow, &ann(), by_hand(DataClassLevel::Internal)).unwrap();
        let waiting = published(vec![approval("check")], Vec::new());
        let (running, _) = start_as(&waiting, &ann(), by_hand(DataClassLevel::Internal)).unwrap();

        let again_succeeded = succeeded.restart(
            &workflow,
            managing(&ann()),
            again(&ann(), RestartFrom::Beginning),
        );
        let again_running = running.restart(
            &waiting,
            managing(&ann()),
            again(&ann(), RestartFrom::Beginning),
        );

        assert!(matches!(again_succeeded, Err(DomainError::Conflict(_))));
        assert!(matches!(again_running, Err(DomainError::Conflict(_))));
    }

    /// Archiving the version of Ann's failed run prevents a retry, which
    /// returns a conflict.
    #[test]
    fn a_run_of_an_archived_version_is_not_started_again() {
        let (mut workflow, failed) = tidy_then_check();
        workflow.archive(&managing(&ann())).unwrap();

        let retried = failed.restart(
            &workflow,
            managing(&ann()),
            again(&ann(), RestartFrom::FailedStep),
        );

        assert!(matches!(retried, Err(DomainError::Conflict(_))));
    }

    /// Ann retries her failed run and the retry is stored. It reads back,
    /// since every step it kept fits the steps that led to it.
    #[test]
    fn a_retried_run_reads_back_from_storage() {
        let (workflow, failed) = tidy_then_check();
        let (retry, _) = failed
            .restart(
                &workflow,
                managing(&ann()),
                again(&ann(), RestartFrom::FailedStep),
            )
            .unwrap();

        let read = Execution::reconstitute(stored(&retry));

        assert!(read.is_ok());
    }

    /// Ann's draft test reaches its deadline. Restarting that test as a real
    /// run returns a conflict.
    #[test]
    fn a_test_is_never_started_again() {
        let workflow = draft(vec![code("crunch")], Vec::new());
        let NodeKind::Code(step) = workflow.graph().nodes()[0].kind() else {
            panic!("the draft runs code");
        };
        let runnable = [RunnableCode {
            version: step.version(),
            reach: CodeReach::Closed,
        }];
        let (mut test, _) = Execution::start_test(
            &workflow,
            managing(&ann()),
            by_hand(DataClassLevel::Internal),
            &runnable,
        )
        .unwrap();
        let _late = crate::shared::clock::freeze(test.deadline() + time::Duration::SECOND);
        test.expire().unwrap();

        let again = test.restart(
            &workflow,
            managing(&ann()),
            again(&ann(), RestartFrom::Beginning),
        );

        assert!(matches!(again, Err(DomainError::Conflict(_))));
    }
}
