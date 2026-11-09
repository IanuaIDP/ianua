//! Agent flows and webhook workflows, as the workflows tests build them.

use ianua_domain::domains::agents::authority::intent::IntentEnvelope;
use ianua_domain::domains::agents::execution::run::GoalTemplate;
use ianua_domain::domains::workflows::design::graph::WorkflowGraph;
use ianua_domain::domains::workflows::design::node::{AgentRunParams, Checks, Mapping};
use ianua_domain::domains::workflows::design::workflow::{FlowDescription, NewFlow, Workflow};
use ianua_domain::domains::workflows::triggers::Trigger;
use ianua_domain::domains::workflows::triggers::secret::WorkflowTriggerSecret;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::model::restriction::Restriction;
use ianua_domain::types::{ActionClass, AgentId, Human, Label};

use crate::test_support::workflows::graphs::{
    draft_on, managing, published_by, test_provider, tidy_step,
};
use crate::test_support::workflows::trigger_secrets::trigger_secret_hash;

/// The secret every webhook secret these tests issue up front was made as.
pub const HOOK_SECRET: &str = "hook-secret-0";

/// One run of a flow's stage: a new agent summarising the open incidents,
/// reading nothing but what the stage before it answered.
#[must_use]
pub fn stage_run() -> AgentRunParams {
    AgentRunParams {
        agent_id: AgentId::new(),
        provider_id: test_provider(),
        goal: GoalTemplate::new("summarise the open incidents").expect("a goal"),
        inputs: Mapping::new(Vec::new()).expect("no field is a mapping"),
        purpose: IntentEnvelope::new([ActionClass::Read]),
        tools: Vec::new(),
        approval_classes: Vec::new(),
        max_steps: 5,
        spend_cap: Restriction::Unrestricted,
        ask_past: Restriction::Unrestricted,
        checks: Checks::Nothing,
    }
}

/// Two runs side by side, then one that reads both their answers.
#[must_use]
pub fn two_stages() -> Vec<Vec<AgentRunParams>> {
    vec![vec![stage_run(), stage_run()], vec![stage_run()]]
}

/// The flow "Incident digest" `maker` made of [`two_stages`].
///
/// # Panics
///
/// Panics if the stages do not make a flow.
#[must_use]
pub fn flow_by(maker: &Human) -> Workflow<ResolvedTenant> {
    let flow = NewFlow {
        name: Label::new("name", "Incident digest").expect("a name"),
        description: FlowDescription::Blank,
        graph: WorkflowGraph::staged(two_stages()).expect("two stages lay out"),
    };
    Workflow::flow(&managing(maker), flow).expect("someone managing workflows makes a flow")
}

/// A workflow `publisher` wrote and published that starts on its webhook
/// and only tidies its data.
#[must_use]
pub fn hooked_by(publisher: &Human) -> Workflow<ResolvedTenant> {
    published_by(
        publisher,
        draft_on(
            publisher,
            vec![tidy_step("tidy")],
            Vec::new(),
            Trigger::Webhook,
        ),
    )
}

/// The secret `by` issued for `workflow`'s webhook, made as [`HOOK_SECRET`].
///
/// # Panics
///
/// Panics if `workflow` does not start on its webhook.
#[must_use]
pub fn hook_secret(
    workflow: &Workflow<ResolvedTenant>,
    by: &Human,
) -> WorkflowTriggerSecret<ResolvedTenant> {
    WorkflowTriggerSecret::issue(workflow, trigger_secret_hash(HOOK_SECRET), &managing(by))
        .expect("someone managing workflows issues a webhook secret")
}
