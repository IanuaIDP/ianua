//! Putting off an agent run step while the tenant's plan has no room for
//! another run in flight.
//!
//! The step stays ready with the input it had, and is tried again after a
//! pause. A full plan is a reason to wait, not a fault in the workflow, so
//! the step never fails over it. Starting it again asks every question a
//! first start asks, so a person who left or an agent suspended meanwhile
//! still stops it.

use time::{Duration, OffsetDateTime};

use crate::domains::workflows::design::node::{NodeKey, NodeKind};
use crate::domains::workflows::execution::WorkflowExecution;
use crate::domains::workflows::execution::record::{ExecutionRecord, StepRecord};
use crate::domains::workflows::execution::step::{Attempt, StepState};
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;

/// How long an agent run step waits before it is tried again, once the
/// tenant's plan had no room for its run.
pub const RUN_LIMIT_PAUSE: Duration = Duration::minutes(1);

impl<T: TenantScope> WorkflowExecution<T> {
    /// Puts off starting the ready agent run step `key`, because the tenant
    /// already has as many agent runs in flight as its plan allows.
    ///
    /// The step stays ready and is due again [`RUN_LIMIT_PAUSE`] from now,
    /// or at the execution's deadline when that comes first. Putting a step
    /// off starts nothing and grants nothing, so it only ever delays the
    /// work. If the plan stays full, the execution runs out of time as it
    /// would waiting on anything else.
    ///
    /// # Errors
    ///
    /// - [`DomainError::NotFound`] when the workflow has no such step.
    /// - [`DomainError::InvalidTransition`] when the step is not ready, or
    ///   the execution has ended.
    /// - [`DomainError::Conflict`] once the execution ran out of time.
    /// - [`DomainError::Validation`] when it is neither an agent run step
    ///   nor a code step, whose version may hold an agent.
    pub fn defer_agent_run(&mut self, key: &NodeKey) -> Result<Vec<ExecutionRecord>, DomainError> {
        let ready = self.ready_step(key)?;
        if !matches!(ready.node.kind(), NodeKind::AgentRun(_) | NodeKind::Code(_)) {
            return Err(DomainError::invalid(message!(
                "workflows-only-an-agent-run-step-waits",
                "only an agent run step waits for room under the plan"
            )));
        }
        let due = crate::shared::clock::now()
            .saturating_add(RUN_LIMIT_PAUSE)
            .min(self.deadline);
        let waiting = StepState::Ready {
            input: ready.input,
            exposure: ready.exposure,
            seen: ready.seen,
            attempt: Attempt::Deferred { due },
        };
        self.put(ready.index, waiting);
        let happened = StepRecord::StartDeferred { due };
        Ok(vec![ExecutionRecord::step(ready.node.key(), happened)])
    }
}

/// Refuses starting a step at `now` that was put off and is not due again
/// yet.
pub(in crate::domains::workflows::execution) fn ensure_due_again(
    attempt: Attempt,
    now: OffsetDateTime,
) -> Result<(), DomainError> {
    let Attempt::Deferred { due } = attempt else {
        return Ok(());
    };
    if now < due {
        return Err(DomainError::conflict(message!(
            "workflows-the-step-waits-for-room-under",
            "the step waits for room under the plan and is not due again yet"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::agents::identity::agent::AgentIdentity;
    use crate::domains::workflows::execution::tests::fixtures::{
        Execution, acting, agent, agent_execution, approval, frozen_at, instant, key,
        running_agent, started, state, stored,
    };
    use crate::domains::workflows::execution::{AgentRunStart, RunAuthority, WorkflowExecutionRow};
    use crate::isolation::scope::ResolvedTenant;

    /// When the agent step in `execution` is due again, or a panic when it
    /// was not put off.
    fn deferred_until(execution: &Execution) -> OffsetDateTime {
        let StepState::Ready {
            attempt: Attempt::Deferred { due },
            ..
        } = state(execution, "summarise")
        else {
            panic!("the agent step is not put off");
        };
        due
    }

    /// An execution of `agent`'s step, put off at noon.
    fn put_off_at_noon(agent: &AgentIdentity<ResolvedTenant>) -> Execution {
        let _noon = frozen_at(0);
        let mut execution = agent_execution(agent, &[]);
        execution.defer_agent_run(&key("summarise")).unwrap();
        execution
    }

    /// The worker starts `execution`'s agent step as `agent`.
    fn start(
        execution: &mut Execution,
        agent: &AgentIdentity<ResolvedTenant>,
    ) -> Result<AgentRunStart<ResolvedTenant>, DomainError> {
        let person = acting(execution.acting_for());
        execution.start_agent_run(
            &key("summarise"),
            &RunAuthority::NoDelegation,
            agent,
            &person,
        )
    }

    /// Ann's workflow reaches its agent step at noon while Acme's plan has
    /// no room for another run. The step stays ready, due a minute later,
    /// and the record says so. Nothing failed.
    #[test]
    fn a_step_put_off_stays_ready_and_is_due_after_the_pause() {
        let agent = agent();
        let _noon = frozen_at(0);
        let mut execution = agent_execution(&agent, &[]);

        let records = execution.defer_agent_run(&key("summarise")).unwrap();

        assert_eq!(deferred_until(&execution), instant(60));
        assert_eq!(
            records,
            vec![ExecutionRecord::step(
                &key("summarise"),
                StepRecord::StartDeferred { due: instant(60) }
            )]
        );
    }

    /// Starting a deferred step after ten seconds returns a conflict and
    /// preserves its due time of one minute after deferral.
    #[test]
    fn a_step_put_off_is_not_started_before_it_is_due() {
        let agent = agent();
        let mut execution = put_off_at_noon(&agent);
        let _soon = frozen_at(10);

        let result = start(&mut execution, &agent);

        assert!(matches!(result, Err(DomainError::Conflict(_))));
        assert_eq!(deferred_until(&execution), instant(60));
    }

    /// The minute passes and the plan has room again. The put-off step
    /// starts its run, as a first start would.
    #[test]
    fn a_step_put_off_starts_its_run_once_it_is_due() {
        let agent = agent();
        let mut execution = put_off_at_noon(&agent);
        let _due = frozen_at(60);

        let started = start(&mut execution, &agent).unwrap();

        assert!(matches!(started, AgentRunStart::Started(..)));
        assert!(matches!(
            state(&execution, "summarise"),
            StepState::Running { .. }
        ));
    }

    /// Ann's execution has thirty seconds left when its agent step is put
    /// off. It is due at the deadline, not after it.
    #[test]
    fn a_step_put_off_near_the_deadline_is_due_at_the_deadline() {
        let agent = agent();
        let mut execution = agent_execution(&agent, &[]);
        let deadline = execution.deadline();
        let _late = crate::shared::clock::freeze(deadline - Duration::seconds(30));

        execution.defer_agent_run(&key("summarise")).unwrap();

        assert_eq!(deferred_until(&execution), deadline);
    }

    /// An approval step cannot be deferred for an agent-run plan limit;
    /// the attempt returns a validation error.
    #[test]
    fn only_an_agent_run_step_is_put_off() {
        let mut execution = started(vec![approval("check")], Vec::new());

        let result = execution.defer_agent_run(&key("check"));

        assert!(matches!(result, Err(DomainError::Validation(_))));
    }

    /// Deferring an already running agent step returns an invalid transition
    /// and leaves the step running.
    #[test]
    fn a_running_step_is_not_put_off() {
        let agent = agent();
        let mut execution = agent_execution(&agent, &[]);
        running_agent(&mut execution, &agent);

        let result = execution.defer_agent_run(&key("summarise"));

        assert!(matches!(result, Err(DomainError::InvalidTransition(_))));
        assert!(matches!(
            state(&execution, "summarise"),
            StepState::Running { .. }
        ));
    }

    /// A put-off step is stored and read back. Stored due a day later, or
    /// put off on an approval step, it is refused as corrupt.
    #[test]
    fn a_stored_step_put_off_keeps_to_its_kind_and_its_pause() {
        let agent = agent();
        let execution = put_off_at_noon(&agent);
        let due = deferred_until(&execution);
        let a_day_later = with_attempt(
            stored(&execution),
            Attempt::Deferred {
                due: due.saturating_add(Duration::days(1)),
            },
        );
        let approval_row = {
            let _noon = frozen_at(0);
            with_attempt(
                stored(&started(vec![approval("check")], Vec::new())),
                Attempt::Deferred { due },
            )
        };

        assert!(Execution::reconstitute(stored(&execution)).is_ok());
        assert!(matches!(
            Execution::reconstitute(a_day_later),
            Err(DomainError::Infrastructure(_))
        ));
        assert!(matches!(
            Execution::reconstitute(approval_row),
            Err(DomainError::Infrastructure(_))
        ));
    }

    /// Changes the first stored ready step without bypassing reconstitution in the assertion.
    fn with_attempt(mut row: WorkflowExecutionRow, attempt: Attempt) -> WorkflowExecutionRow {
        if let Some(StepState::Ready { attempt: slot, .. }) = row.steps.get_mut(0) {
            *slot = attempt;
        }
        row
    }
}
