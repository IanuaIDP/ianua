//! Events from people steering a run: pausing it, resuming it, and
//! revising the call it holds.

use time::OffsetDateTime;

use crate::domains::agents::events::authority::principal_reference;
use crate::domains::agents::events::execution::run_reference;
use crate::domains::agents::execution::usage::Spend;
use crate::shared::events::data::{EventData, RefKind, Reference};
use crate::shared::events::event::{DomainEventCore, tenant_event};
use crate::shared::events::raised::TenantEventBody;
use crate::types::event_type::AgentsEvent;
use crate::types::{AgentId, AgentRunId, EventLabel, EventType, PrincipalRef};

/// How a person steered a run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RunSteering {
    /// They paused it between its steps.
    Paused,
    /// They resumed it.
    Resumed,
    /// They changed the arguments of the call it holds for approval.
    CallRevised,
}

/// A person paused or resumed a run, or revised the call it holds.
///
/// It names the run by its id, as every run event does, and never the
/// call's arguments: they may quote what the run read.
#[derive(Debug)]
pub(crate) struct AgentRunSteered {
    /// The execution affected by a person's intervention.
    pub(crate) run_id: AgentRunId,
    /// The run's agent.
    pub(crate) agent_id: AgentId,
    /// The agent's name when the event fired.
    pub(crate) agent_label: EventLabel,
    /// The person who steered it.
    pub(crate) by: PrincipalRef,
    /// How they steered it.
    pub(crate) steering: RunSteering,
    /// When they did.
    pub(crate) occurred_at: OffsetDateTime,
}

impl DomainEventCore for AgentRunSteered {
    fn event_type(&self) -> EventType {
        match self.steering {
            RunSteering::Paused => AgentsEvent::RunPaused,
            RunSteering::Resumed => AgentsEvent::RunResumed,
            RunSteering::CallRevised => AgentsEvent::HeldCallRevised,
        }
        .into()
    }

    fn occurred_at(&self) -> OffsetDateTime {
        self.occurred_at
    }

    fn payload(&self) -> EventData {
        EventData::new()
            .reference("run", run_reference(&self.run_id))
            .reference(
                "agent",
                Reference::new(
                    RefKind::AGENT,
                    self.agent_id.to_string(),
                    self.agent_label.as_str(),
                ),
            )
            .reference("person", principal_reference(&self.by))
    }
}

impl TenantEventBody for AgentRunSteered {}

/// A run paused itself before its next model call, having spent what it
/// may spend before a person says it may go on.
///
/// It names the amount it paused at and what it had spent, so whoever is
/// told knows what they are asked to let go on.
#[derive(Debug)]
pub(crate) struct AgentRunHeldAtSpend {
    /// The execution paused at its approval threshold.
    pub(crate) run_id: AgentRunId,
    /// The run's agent.
    pub(crate) agent_id: AgentId,
    /// The agent's name when the event fired.
    pub(crate) agent_label: EventLabel,
    /// What the run had spent.
    pub(crate) spent: Spend,
    /// The amount it asks a person at.
    pub(crate) mark: Spend,
    /// When it paused.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    AgentRunHeldAtSpend => AgentsEvent::RunHeldAtSpend,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference("run", run_reference(&self.run_id))
            .reference(
                "agent",
                Reference::new(
                    RefKind::AGENT,
                    self.agent_id.to_string(),
                    self.agent_label.as_str(),
                ),
            )
            .field("spent_micros", self.spent.micros().to_string())
            .field("asks_at_micros", self.mark.micros().to_string())
    }
}

/// A run stopped as over budget: it spent its limit, or a call's cost could
/// not be told under a limit.
///
/// It names what the run had spent and its limit, so a workflow that starts
/// from it can tell the agent's owner how far past the line it went.
#[derive(Debug)]
pub(crate) struct AgentRunStoppedOverBudget {
    /// The run that stopped.
    pub(crate) run_id: AgentRunId,
    /// The run's agent.
    pub(crate) agent_id: AgentId,
    /// The agent's name when the event fired.
    pub(crate) agent_label: EventLabel,
    /// What the run had spent.
    pub(crate) spent: Spend,
    /// The most it may spend.
    pub(crate) limit: Spend,
    /// When it stopped.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    AgentRunStoppedOverBudget => AgentsEvent::RunStoppedOverBudget,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference("run", run_reference(&self.run_id))
            .reference(
                "agent",
                Reference::new(
                    RefKind::AGENT,
                    self.agent_id.to_string(),
                    self.agent_label.as_str(),
                ),
            )
            .field("spent_micros", self.spent.micros().to_string())
            .field("limit_micros", self.limit.micros().to_string())
    }
}
