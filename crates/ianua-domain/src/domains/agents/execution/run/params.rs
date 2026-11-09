//! What a run is started with, and how it is stored.

use time::OffsetDateTime;

use crate::domains::agents::authority::capability::ActionApproval;
use crate::domains::agents::authority::delegation::ActingUnder;
use crate::domains::agents::authority::intent::IntentEnvelope;
use crate::domains::agents::execution::run::call::RunStep;
use crate::domains::agents::execution::run::check::RunCheck;
use crate::domains::agents::execution::run::goal::RunGoal;
use crate::domains::agents::execution::run::spend::SpendCheck;
use crate::domains::agents::execution::run::status::RunState;
use crate::domains::agents::execution::tool::ToolName;
use crate::domains::agents::execution::usage::{ModelTokens, Spend};
use crate::domains::data_classification::level::DataClassLevel;
use crate::shared::events::chain::EventOrigin;
use crate::shared::model::restriction::Restriction;
use crate::types::{ActionClass, AgentId, AgentRunId, Initiator, ModelProviderId};

/// The most model steps a run may be given.
pub const MAX_RUN_STEPS: u32 = 1000;

/// Parameters for starting a run.
///
/// The agent, the delegation and who starts the run are not among them. The
/// run takes them from the
/// [`Delegation`](crate::domains::agents::authority::delegation::Delegation),
/// [`AgentIdentity`](crate::domains::agents::identity::agent::AgentIdentity)
/// and [`RunStarter`](crate::domains::agents::execution::run::RunStarter) it
/// is started with, which it checks.
pub struct StartRunParams {
    /// The model provider to reason with.
    pub provider_id: ModelProviderId,
    /// The goal to pursue.
    pub goal: RunGoal,
    /// The action classes the run's tool calls may take. It must fit inside
    /// the delegation's intent, when the delegation has one.
    pub purpose: IntentEnvelope,
    /// The tools the run may call, by name. Empty means none.
    pub granted_tools: Vec<ToolName>,
    /// Action classes whose tool calls a person must approve before they run.
    pub approval_classes: Vec<ActionClass>,
    /// The most model steps before the run fails.
    pub max_steps: u32,
    /// The most the run may spend on its model before it stops, or that it
    /// has no spend limit.
    pub spend_limit: Restriction<Spend>,
    /// What the run may spend before it pauses for a person to let it go
    /// on, or that it never pauses over spend. Below the spend limit when
    /// both are set.
    pub ask_past: Restriction<Spend>,
    /// The most sensitive data the run holds before its first step.
    ///
    /// It is public for a run a person starts. For a workflow step it is the
    /// step's input exposure, because its goal carries what earlier steps
    /// produced.
    ///
    /// The domain cannot read a goal and tell how sensitive it is, so this
    /// comes from the caller. A person who pastes confidential text into a
    /// goal must start the run at that class. Every call check, model check
    /// and approval then holds the run to it, and it only rises.
    pub exposure: DataClassLevel,
    /// Where the run came from: outside any workflow, or a workflow
    /// execution at its depth. Every event the run raises carries it.
    pub origin: EventOrigin,
}

/// Persisted state for reconstitution.
pub struct AgentRunRow {
    /// Unique identifier.
    pub id: AgentRunId,
    /// The acting agent.
    pub agent_id: AgentId,
    /// The model provider.
    pub provider_id: ModelProviderId,
    /// The stored instructions the model follows during this execution.
    pub goal: RunGoal,
    /// The action classes the run's tool calls may take.
    pub purpose: IntentEnvelope,
    /// The tools the run may call, by name.
    pub granted_tools: Vec<ToolName>,
    /// Action classes whose tool calls a person must approve.
    pub approval_classes: Vec<ActionClass>,
    /// Whether every tool call waits for a person, taken from the
    /// delegation when the run started.
    pub approval: ActionApproval,
    /// The delegation the run acts under, if any.
    pub delegation_id: ActingUnder,
    /// The most model steps allowed.
    pub max_steps: u32,
    /// The most the run may spend on its model, or no limit.
    pub spend_limit: Restriction<Spend>,
    /// Where it waits for a person before spending more.
    pub spend_check: SpendCheck,
    /// The tokens its model calls used so far.
    pub usage: ModelTokens,
    /// What its model calls cost so far.
    pub spent: Spend,
    /// Who started the run.
    pub started_by: Initiator,
    /// The most sensitive data class the run has read.
    pub exposure: DataClassLevel,
    /// Where the run came from.
    pub origin: EventOrigin,
    /// Recorded steps.
    pub steps: Vec<RunStep>,
    /// Where the run stands. See [`RunState::from_stored`].
    pub state: RunState,
    /// What its answers are held to before it completes.
    pub check: RunCheck,
    /// When started.
    pub created_at: OffsetDateTime,
    /// When last updated.
    pub updated_at: OffsetDateTime,
}
