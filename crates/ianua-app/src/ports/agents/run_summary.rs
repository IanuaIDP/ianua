//! Run listings without the step trace loaded by an individual run read.

use ianua_domain::domains::agents::authority::delegation::ActingUnder;
use ianua_domain::domains::agents::authority::intent::IntentEnvelope;
use ianua_domain::domains::agents::execution::run::{AgentRun, RunGoal, RunState, SpendCheck};
use ianua_domain::domains::agents::execution::usage::{ModelTokens, Spend};
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::model::aggregate::Aggregate as _;
use ianua_domain::shared::model::restriction::Restriction;
use ianua_domain::types::{ActionClass, AgentId, AgentRunId, Initiator, ModelProviderId};
use time::OffsetDateTime;

use crate::define_sort_field;
use crate::listing::{SortKey, SortKeys};

/// A run's listing projection. Its trace and final answer require a detail read.
#[derive(Debug, Clone)]
pub struct RunSummary {
    /// The run.
    pub id: AgentRunId,
    /// The agent doing the work.
    pub agent_id: AgentId,
    /// The model provider used.
    pub provider_id: ModelProviderId,
    /// The goal to pursue.
    pub goal: RunGoal,
    /// The permitted action classes.
    pub purpose: IntentEnvelope,
    /// Classes that need a person's approval.
    pub approval_classes: Vec<ActionClass>,
    /// The delegation backing the run, when it has one.
    pub delegation_id: ActingUnder,
    /// The maximum tool calls.
    pub max_steps: u32,
    /// The spending limit, when one was set.
    pub spend_limit: Restriction<Spend>,
    /// Where the run waits for a person before spending more.
    pub spend_check: SpendCheck,
    /// Model tokens consumed.
    pub usage: ModelTokens,
    /// Model spend so far.
    pub spent: Spend,
    /// Who started the run.
    pub started_by: Initiator,
    /// The highest sensitivity the run has read.
    pub exposure: DataClassLevel,
    /// The lifecycle state and held call, without historical steps.
    pub state: RunState,
    /// When the run started.
    pub created_at: OffsetDateTime,
    /// When the run last changed.
    pub updated_at: OffsetDateTime,
}

impl RunSummary {
    /// Projects an already validated run without cloning its step history.
    #[must_use]
    pub fn of(run: &AgentRun<ResolvedTenant>) -> Self {
        Self {
            id: *run.id(),
            agent_id: *run.agent_id(),
            provider_id: *run.provider_id(),
            goal: run.goal().clone(),
            purpose: run.purpose().clone(),
            approval_classes: run.approval_classes().to_vec(),
            delegation_id: *run.delegation_id(),
            max_steps: run.max_steps(),
            spend_limit: run.spend_limit(),
            spend_check: run.spend_check(),
            usage: run.usage(),
            spent: run.spent(),
            started_by: run.started_by().clone(),
            exposure: run.exposure(),
            state: run.state().clone(),
            created_at: run.created_at(),
            updated_at: run.updated_at(),
        }
    }
}

define_sort_field! {
    /// The fixed newest-first run listing order.
    pub enum RunSortField {
        /// Run creation time, with the run id breaking ties.
        CreatedAt => "created_at",
    }
    default = CreatedAt;
    default direction = Desc;
}

impl SortKeys<RunSortField> for RunSummary {
    fn sort_key(&self, field: RunSortField) -> SortKey {
        match field {
            RunSortField::CreatedAt => self.created_at.into(),
        }
    }

    fn tiebreak(&self) -> SortKey {
        self.id.as_uuid().into()
    }
}
