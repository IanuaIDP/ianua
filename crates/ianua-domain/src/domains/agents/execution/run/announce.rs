//! What a run announces: that it started or resumed, paused for a person,
//! was asked to stop, or ended.
//!
//! The audit trail names a run's agent and model provider as the tenant
//! knows them, which the run does not hold. So the run announces each move
//! once it is made, with the names it is handed, and where it stands picks
//! what it announces: a run still going announces no end, a run not paused
//! announces no pause. Every announcement is marked with where the run came
//! from when it is taken, so a workflow it sets off continues the chain
//! that started the run.

use crate::domains::agents::events::execution::{
    AgentRunAwaitingApproval, AgentRunCancelRequested, AgentRunFinished, AgentRunStarted,
};
use crate::domains::agents::execution::run::AgentRun;
use crate::domains::agents::execution::run::cancel::CancelOrder;
use crate::domains::agents::execution::run::status::{RunState, RunStatus};
use crate::domains::agents::identity::agent::AgentIdentity;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::clock;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{Raises, SavedFor};
use crate::types::{EventLabel, UntrustedText};

/// The names the audit trail shows for a run's agent and model provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunNames {
    agent: EventLabel,
    provider: EventLabel,
}

impl RunNames {
    /// The run's agent shown as `agent`, and its model provider as
    /// `provider`.
    #[must_use]
    pub fn new(agent: EventLabel, provider: EventLabel) -> Self {
        Self { agent, provider }
    }
}

impl<T: TenantScope> AgentRun<T> {
    /// Hands the running run to the worker that drives it, when it first
    /// starts and when a decision resumes it, with its agent and provider
    /// named as `names` says.
    ///
    /// Raises `agents.run_started`, once however often it is announced
    /// before the run is saved. A run that is not running announces
    /// nothing.
    pub fn announce_start(&mut self, names: RunNames) {
        if self.status() != RunStatus::Running {
            return;
        }
        self.raised.raise_latest(AgentRunStarted {
            run_id: self.id,
            agent_id: self.agent_id,
            agent_label: names.agent,
            provider_id: self.provider_id,
            provider_label: names.provider,
            occurred_at: clock::now(),
        });
    }

    /// Announces that the run waits for a person to approve the call it
    /// holds, its agent named `agent`.
    ///
    /// Raises `agents.run_awaiting_approval`, naming the tool the call
    /// waits on. A run that is not paused announces nothing.
    pub fn announce_pause(&mut self, agent: EventLabel) {
        let RunState::AwaitingApproval(call) = &self.state else {
            return;
        };
        let tool = UntrustedText::record(call.tool());
        self.raised.raise_latest(AgentRunAwaitingApproval {
            run_id: self.id,
            agent_id: self.agent_id,
            agent_label: agent,
            tool,
            occurred_at: clock::now(),
        });
    }

    /// Announces how the run ended, its agent named `agent`, so whatever
    /// waits on it moves on.
    ///
    /// Raises `agents.run_finished`, with how it ended and how many steps it
    /// took. A run still going announces nothing.
    pub fn announce_end(&mut self, agent: EventLabel) {
        if !self.status().is_terminal() {
            return;
        }
        self.raised.raise_latest(AgentRunFinished {
            run_id: self.id,
            agent_id: self.agent_id,
            agent_label: agent,
            status: self.status(),
            steps: u32::try_from(self.steps.len()).unwrap_or(u32::MAX),
            occurred_at: clock::now(),
        });
    }

    /// Announces that the person `order` names asked the run of `agent` to
    /// stop. It is recorded when they ask, not when the run stops, since
    /// that is when they acted.
    ///
    /// Raises `agents.run_cancel_requested`. A run that already ended has
    /// nothing to stop, and announces nothing.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `order` is for another run.
    /// - [`DomainError::Forbidden`] when `agent` is not the run's agent.
    pub fn announce_cancel_request(
        &mut self,
        order: &CancelOrder,
        agent: &AgentIdentity<T>,
    ) -> Result<(), DomainError> {
        if order.run_id() != &self.id {
            return Err(DomainError::forbidden(message!(
                "agents-the-cancel-order-is-for-another",
                "the cancel order is for another run"
            )));
        }
        if agent.id() != &self.agent_id {
            return Err(DomainError::forbidden(message!(
                "agents-the-agent-is-not-the-run",
                "the agent is not the run's agent"
            )));
        }
        if self.status().is_terminal() {
            return Ok(());
        }
        self.raised.raise_latest(AgentRunCancelRequested {
            run_id: self.id,
            agent_id: self.agent_id,
            agent_label: EventLabel::of(agent.name().as_str()),
            occurred_at: clock::now(),
        });
        Ok(())
    }
}

impl<T: TenantScope> Raises for AgentRun<T> {
    fn take_events(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent> {
        let origin = self.origin;
        self.raised
            .take(saved_for)
            .into_iter()
            .map(|event| origin.mark(event))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::agents::execution::run::tests::fixtures::{calling, params, run, tool};
    use crate::domains::agents::identity::control::AgentControl;
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::events::chain::{ChainDepth, EventOrigin};
    use crate::shared::events::data::FieldValue;
    use crate::test_support::authority::assumed_authority;
    use crate::test_support::events::{raised, raised_names};
    use crate::types::TenantId;

    fn names() -> RunNames {
        RunNames::new(
            EventLabel::of("nightly-report"),
            EventLabel::of("prod-deepseek"),
        )
    }

    fn label(event: &DomainEvent, key: &str) -> String {
        match event.payload().value(key) {
            Some(FieldValue::Reference(reference)) => reference.label().to_owned(),
            other => panic!("{key} is not an entity reference: {other:?}"),
        }
    }

    fn paused() -> (AgentRun<ResolvedTenant>, AgentIdentity<ResolvedTenant>) {
        let (mut r, agent) = run(5);
        r.await_approval(calling(&tool("delete_order"), "{\"id\":1}"), &agent)
            .unwrap();
        (r, agent)
    }

    fn order_by_owner(
        r: &AgentRun<ResolvedTenant>,
        agent: &AgentIdentity<ResolvedTenant>,
    ) -> CancelOrder {
        let control =
            AgentControl::new(assumed_authority(agent.owner(), TenantId::new(), &[], &[]));
        r.order_cancel(&control, agent).unwrap()
    }

    /// Ann starts a run of "nightly-report" on "prod-deepseek". Announcing it
    /// raises "agent run started", naming both as the audit trail knows
    /// them.
    #[test]
    fn announcing_a_start_raises_run_started_with_both_names() {
        let (mut r, _) = run(5);

        r.announce_start(names());

        let events = raised(&mut r);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type().to_string(), "agents.run_started");
        assert_eq!(label(&events[0], "agent"), "nightly-report");
        assert_eq!(label(&events[0], "provider"), "prod-deepseek");
    }

    /// A start is announced twice before the run is saved. It is recorded
    /// once.
    #[test]
    fn a_start_announced_twice_is_recorded_once() {
        let (mut r, _) = run(5);

        r.announce_start(names());
        r.announce_start(names());

        assert_eq!(raised_names(&mut r), ["agents.run_started"]);
    }

    /// A run pauses on `delete_order`. Announcing the pause raises "agent
    /// run awaiting approval", naming the tool the call waits on.
    #[test]
    fn announcing_a_pause_names_the_tool_the_call_waits_on() {
        let (mut r, _) = paused();

        r.announce_pause(EventLabel::of("nightly-report"));

        let events = raised(&mut r);
        assert_eq!(
            events[0].event_type().to_string(),
            "agents.run_awaiting_approval"
        );
        assert_eq!(
            events[0].payload().value("tool"),
            Some(&FieldValue::Text("delete_order".to_owned()))
        );
    }

    /// Announcing a pause or end for a running run, or a start while awaiting
    /// approval, raises no events for those nonexistent transitions.
    #[test]
    fn an_announcement_of_a_move_the_run_did_not_make_raises_nothing() {
        let (mut running, _) = run(5);
        let (mut waiting, _) = paused();

        running.announce_pause(EventLabel::of("nightly-report"));
        running.announce_end(EventLabel::of("nightly-report"));
        waiting.announce_start(names());

        assert!(raised(&mut running).is_empty());
        assert!(raised(&mut waiting).is_empty());
    }

    /// A run answers after one step. Announcing its end raises "agent run
    /// finished" with how it ended and how many steps it took.
    #[test]
    fn announcing_an_end_raises_run_finished_with_how_it_ended() {
        let (mut r, _) = run(5);
        r.complete("done").unwrap();

        r.announce_end(EventLabel::of("nightly-report"));

        let events = raised(&mut r);
        assert_eq!(events[0].event_type().to_string(), "agents.run_finished");
        assert_eq!(
            events[0].payload().value("status"),
            Some(&FieldValue::Text("completed".to_owned()))
        );
        assert_eq!(
            events[0].payload().value("steps"),
            Some(&FieldValue::Text("1".to_owned()))
        );
    }

    /// The agent's owner asks a running run to stop. The request raises
    /// "agent run cancel requested", naming the agent by its name.
    #[test]
    fn a_stop_request_raises_cancel_requested_naming_the_agent() {
        let (mut r, agent) = run(5);
        let order = order_by_owner(&r, &agent);

        r.announce_cancel_request(&order, &agent).unwrap();

        let events = raised(&mut r);
        assert_eq!(
            events[0].event_type().to_string(),
            "agents.run_cancel_requested"
        );
        assert_eq!(label(&events[0], "agent"), "nightly-report");
    }

    /// A cancellation order for another run is refused without raising an
    /// event on the run receiving it.
    #[test]
    fn a_stop_request_for_another_run_is_refused_and_raises_nothing() {
        let (first, agent) = run(5);
        let (mut other, _) = run(5);
        let order = order_by_owner(&first, &agent);

        let result = other.announce_cancel_request(&order, &agent);

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
        assert!(raised(&mut other).is_empty());
    }

    /// A run already completed is asked to stop. There is nothing to stop,
    /// so nothing is raised.
    #[test]
    fn a_stop_request_for_an_ended_run_raises_nothing() {
        let (mut r, agent) = run(5);
        r.complete("done").unwrap();
        let order = order_by_owner(&r, &agent);

        r.announce_cancel_request(&order, &agent).unwrap();

        assert!(raised(&mut r).is_empty());
    }

    /// A workflow execution at the first depth of its chain starts a run.
    /// What the run raises is taken marked with that depth, so a workflow
    /// it sets off continues the chain. A run started by hand raises from
    /// outside any workflow.
    #[test]
    fn what_a_workflows_run_raises_carries_the_chain_depth() {
        let chain = EventOrigin::Execution(ChainDepth::FIRST);
        let (mut from_workflow, _) =
            crate::domains::agents::execution::run::tests::fixtures::started(
                crate::domains::agents::execution::run::StartRunParams {
                    origin: chain,
                    ..params(5)
                },
            );
        let (mut by_hand, _) = run(5);

        from_workflow.announce_start(names());
        by_hand.announce_start(names());

        assert_eq!(raised(&mut from_workflow)[0].origin(), chain);
        assert_eq!(raised(&mut by_hand)[0].origin(), EventOrigin::Outside);
    }
}
