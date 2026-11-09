//! How a person pauses a run between its steps and resumes it later.

use crate::domains::agents::events::steering::{AgentRunSteered, RunSteering};
use crate::domains::agents::execution::run::AgentRun;
use crate::domains::agents::execution::run::status::RunState;
use crate::domains::agents::identity::agent::AgentIdentity;
use crate::domains::agents::identity::control::AgentControl;
use crate::domains::authorization::permission::AgentAction;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::types::{EventLabel, Human};

impl<T: TenantScope> AgentRun<T> {
    /// Pauses the run between its steps, as the person `by` asks.
    ///
    /// The run takes no step while paused. An approved call it was about to
    /// make stays held, and its approval still lapses on time. The person
    /// who started the run may pause it, and so may the agent's owner or
    /// someone allowed to change agents. Sam cannot pause Ann's runs.
    ///
    /// The worker driving the run reads it again before each step, so a
    /// pause saved between two steps stops it at the next.
    ///
    /// Raises `agents.run_paused`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `agent` is not the run's agent.
    /// - [`DomainError::Forbidden`] when the person neither started the run
    ///   nor may change the agent.
    /// - [`DomainError::InvalidTransition`] when the run is not running: it
    ///   waits on a person already, is paused, or has ended.
    pub fn pause(
        &mut self,
        by: &AgentControl<'_>,
        agent: &AgentIdentity<T>,
    ) -> Result<(), DomainError> {
        self.ensure_may_steer(by, agent)?;
        let RunState::Running(next) = &self.state else {
            return Err(DomainError::invalid_transition(message!(
                "agents-only-a-running-run-is-paused",
                "only a running run is paused"
            )));
        };
        self.state = RunState::Paused(next.clone());
        self.record_steering(by.by(), agent, RunSteering::Paused);
        Ok(())
    }

    /// Resumes a run a person paused, as the person `by` asks, so it takes
    /// its next step.
    ///
    /// Its agent must still be free to act. Ann's agent is suspended while
    /// its run is paused. Without this check, resuming the run sends it on
    /// with authority its agent lost. The app then hands the run back to
    /// its worker with [`announce_start`](Self::announce_start).
    ///
    /// Raises `agents.run_resumed`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `agent` is not the run's agent, or
    ///   may not act.
    /// - [`DomainError::Forbidden`] when the person neither started the run
    ///   nor may change the agent.
    /// - [`DomainError::InvalidTransition`] when the run is not paused.
    pub fn resume(
        &mut self,
        by: &AgentControl<'_>,
        agent: &AgentIdentity<T>,
    ) -> Result<(), DomainError> {
        self.ensure_may_steer(by, agent)?;
        self.ensure_agent_may_act(agent)?;
        let RunState::Paused(next) = &self.state else {
            return Err(DomainError::invalid_transition(message!(
                "agents-only-a-paused-run-is-resumed",
                "only a paused run is resumed"
            )));
        };
        self.state = RunState::Running(next.clone());
        self.record_steering(by.by(), agent, RunSteering::Resumed);
        Ok(())
    }

    /// Refuses a person who may not steer the run of `agent`: only the
    /// person who started it, the agent's owner, or someone allowed to
    /// change agents.
    fn ensure_may_steer(
        &self,
        by: &AgentControl<'_>,
        agent: &AgentIdentity<T>,
    ) -> Result<(), DomainError> {
        if agent.id() != &self.agent_id {
            return Err(DomainError::forbidden(message!(
                "agents-the-agent-is-not-the-run",
                "the agent is not the run's agent"
            )));
        }
        if self.started_by.is(by.by()) {
            return Ok(());
        }
        by.ensure_may(agent.owner(), AgentAction::Update)
    }

    /// Marks the run changed now, and raises that `person` steered it so.
    pub(super) fn record_steering(
        &mut self,
        person: &Human,
        agent: &AgentIdentity<T>,
        steering: RunSteering,
    ) {
        self.touch();
        self.raised.raise(AgentRunSteered {
            run_id: self.id,
            agent_id: self.agent_id,
            agent_label: EventLabel::of(agent.name().as_str()),
            by: person.principal(),
            steering,
            occurred_at: self.updated_at,
        });
    }
}

#[cfg(test)]
mod tests {
    use crate::domains::agents::execution::run::tests::fixtures::{
        agent, ann, by_ann, calling, constraints, delegation, params, released, run, tool,
    };
    use crate::domains::agents::execution::run::{AgentRun, RunStatus};
    use crate::domains::agents::execution::tool::tests::fixtures::{MANAGE, holding, person};
    use crate::domains::agents::identity::agent::SuspendedBy;
    use crate::shared::errors::DomainError;
    use crate::test_support::events::raised_names;

    /// Ann pauses her run. It takes no step and is not over. She resumes
    /// it, and it steps again. Both moves are raised.
    #[test]
    fn the_starter_pauses_and_resumes_her_run() {
        let (mut r, agent) = run(5);
        let ann = ann();

        r.pause(&holding(&ann, &[]), &agent).unwrap();
        let while_paused = (r.status(), r.can_step());
        r.resume(&holding(&ann, &[]), &agent).unwrap();

        assert_eq!(while_paused, (RunStatus::Paused, false));
        assert!(r.can_step());
        assert_eq!(
            raised_names(&mut r),
            ["agents.run_paused", "agents.run_resumed"]
        );
    }

    /// Someone who neither started the run nor controls its agent cannot
    /// pause or resume it. A manager can pause it, and it stays paused after
    /// the outsider's resume attempt.
    #[test]
    fn only_the_starter_or_someone_with_a_say_steers_a_run() {
        let (mut r, agent) = run(5);
        let (sam, bob) = (person("sam@corp.test"), person("bob@corp.test"));

        let paused_by_sam = r.pause(&holding(&sam, &[]), &agent);
        r.pause(&holding(&bob, &MANAGE), &agent).unwrap();
        let resumed_by_sam = r.resume(&holding(&sam, &[]), &agent);

        assert!(matches!(paused_by_sam, Err(DomainError::Forbidden(_))));
        assert!(matches!(resumed_by_sam, Err(DomainError::Forbidden(_))));
        assert_eq!(r.status(), RunStatus::Paused);
    }

    /// A run paused before its agent is suspended cannot resume and remains
    /// paused after the forbidden attempt.
    #[test]
    fn a_run_whose_agent_may_not_act_is_not_resumed() {
        let (mut r, mut agent) = run(5);
        let ann = ann();
        r.pause(&holding(&ann, &[]), &agent).unwrap();
        agent.suspend(SuspendedBy::Monitor).unwrap();

        let resumed = r.resume(&holding(&ann, &[]), &agent);

        assert!(matches!(resumed, Err(DomainError::Forbidden(_))));
        assert_eq!(r.status(), RunStatus::Paused);
    }

    /// A run already waiting for a person to approve a call, or already
    /// paused, is not paused again. A running run is not resumed.
    #[test]
    fn only_a_running_run_pauses_and_only_a_paused_run_resumes() {
        let (mut r, agent) = run(5);
        let ann = ann();

        let not_paused = r.resume(&holding(&ann, &[]), &agent);
        r.await_approval(calling(&tool("delete_order"), "{\"id\":1}"), &agent)
            .unwrap();
        let awaiting = r.pause(&holding(&ann, &[]), &agent);

        assert!(matches!(not_paused, Err(DomainError::InvalidTransition(_))));
        assert!(matches!(awaiting, Err(DomainError::InvalidTransition(_))));
    }

    /// Ann pauses a run that holds an approved call. Resumed, it still holds
    /// that call to make next.
    #[test]
    fn a_paused_run_keeps_the_approved_call_it_holds() {
        let (mut r, agent) = run(5);
        let ann = ann();
        r.await_approval(calling(&tool("delete_order"), "{\"id\":1}"), &agent)
            .unwrap();
        r.approve_pending(&released(&r, "delete_order", "{\"id\":1}"))
            .unwrap();

        r.pause(&holding(&ann, &[]), &agent).unwrap();
        let held_while_paused = r.pending().is_some();
        r.resume(&holding(&ann, &[]), &agent).unwrap();

        assert!(held_while_paused);
        assert!(r.approved_call().is_some());
    }

    /// Pausing a run through a different agent is forbidden even for its starter.
    #[test]
    fn a_run_is_steered_only_through_its_own_agent() {
        let ann_agent = agent();
        let run_of = AgentRun::start(
            by_ann(),
            params(5),
            &delegation(&ann_agent, constraints()),
            &ann_agent,
        );
        let mut r = run_of.unwrap();

        let result = r.pause(&holding(&ann(), &[]), &agent());

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }
}
