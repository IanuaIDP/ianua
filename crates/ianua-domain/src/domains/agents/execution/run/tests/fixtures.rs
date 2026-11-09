//! Agents, delegations, tools and runs for the run tests.

use crate::domains::agents::authority::capability::{CapabilitySet, DelegationConstraints};
use crate::domains::agents::authority::delegation::{
    Delegate, Delegation, GrantDelegationParams, HeldBy, HeldResources, ReviewDuty,
};
use crate::domains::agents::authority::intent::IntentEnvelope;
use crate::domains::agents::execution::model_provider::{
    CreateModelProviderParams, ModelEndpoint, ModelName, ModelProvider, ModelProviderKind,
    ProviderKey,
};
use crate::domains::agents::execution::run::{
    AgentRun, DeniedCall, PendingCall, PendingCallRef, ReleasedCall, ResolvedCall, RunGoal,
    RunStarter, StartRunParams, ToolCall,
};
use crate::domains::agents::execution::tool::tests::fixtures::{
    MANAGE, holding, person, registered,
};
use crate::domains::agents::execution::tool::{
    AgentTool, PathValue, PathValues, ToolMethod, ToolName,
};
use crate::domains::agents::execution::usage::ModelPricing;
use crate::domains::agents::identity::agent::{AgentIdentity, CreateAgentParams};
use crate::domains::data_classification::level::DataClassLevel;
use crate::isolation::scope::ResolvedTenant;
use crate::shared::events::chain::EventOrigin;
use crate::shared::model::restriction::Restriction;
use crate::test_support::authority::assumed_authority;
use crate::types::{
    ActionClass, DeclaredAction, Human, HumanAccount, Label, ModelProviderId, PersonKey, Seconds,
    TenantId, UserId,
};

/// The tools the standard run is given.
pub(crate) const GRANTED: [&str; 8] = [
    "get_order",
    "read_order",
    "delete_order",
    "get_salary",
    "get_weather",
    "lookup",
    "pay_invoice",
    "get_item",
];

/// Ann, who owns the standard agent, delegates to it and starts its runs.
pub(crate) fn ann() -> Human {
    Human::new(
        HumanAccount::User(UserId::from_uuid(uuid::Uuid::from_u128(1))),
        PersonKey::new("ann@corp.test").unwrap(),
    )
}

/// Ann's agent `nightly-report`, active and free to act.
pub(crate) fn agent() -> AgentIdentity<ResolvedTenant> {
    AgentIdentity::create(
        &holding(&ann(), &MANAGE),
        CreateAgentParams {
            name: Label::new("name", "nightly-report").unwrap(),
            description: None,
        },
    )
    .unwrap()
}

/// Limits of an hour and one link, with no intent and no approval rule.
pub(crate) fn constraints() -> DelegationConstraints {
    DelegationConstraints::new(Seconds::new(3600), 1).unwrap()
}

/// Ann's delegation to `agent` under `constraints`.
pub(crate) fn delegation(
    agent: &AgentIdentity<ResolvedTenant>,
    constraints: DelegationConstraints,
) -> Delegation<ResolvedTenant> {
    let ann = ann();
    let nothing_more = CapabilitySet::default();
    Delegation::grant(
        GrantDelegationParams {
            granted: CapabilitySet::default(),
            constraints,
            name: None,
        },
        &HeldBy::worked_out::<ResolvedTenant>(
            &holding(&ann, &MANAGE),
            &nothing_more,
            &HeldResources::answered(ann.principal(), Vec::new()),
            &[],
        )
        .unwrap(),
        &Delegate {
            agent,
            duty: ReviewDuty::NotReviewing,
        },
    )
    .unwrap()
}

/// The standard run: it reads, writes and deletes, may take `max_steps`
/// steps, is given every tool in [`GRANTED`] and starts at public.
pub(crate) fn params(max_steps: u32) -> StartRunParams {
    StartRunParams {
        provider_id: ModelProviderId::new(),
        goal: RunGoal::new("reconcile the orders ledger").unwrap(),
        purpose: IntentEnvelope::new([ActionClass::Read, ActionClass::Write, ActionClass::Delete]),
        granted_tools: GRANTED.map(|name| ToolName::new(name).unwrap()).to_vec(),
        approval_classes: Vec::new(),
        max_steps,
        spend_limit: Restriction::Unrestricted,
        ask_past: Restriction::Unrestricted,
        exposure: DataClassLevel::Public,
        origin: EventOrigin::Outside,
    }
}

/// Ann, signed in, starting a run.
pub(crate) fn by_ann() -> RunStarter<'static> {
    RunStarter::person(assumed_authority(&ann(), TenantId::new(), &[], &[]))
}

/// A run Ann started with `params` for a fresh agent under her plain
/// delegation, with that agent.
pub(crate) fn started(
    params: StartRunParams,
) -> (AgentRun<ResolvedTenant>, AgentIdentity<ResolvedTenant>) {
    let agent = agent();
    let delegation = delegation(&agent, constraints());
    let run = AgentRun::start(by_ann(), params, &delegation, &agent).unwrap();
    (run, agent)
}

/// The standard run, allowed `max_steps` steps, with its agent.
pub(crate) fn run(max_steps: u32) -> (AgentRun<ResolvedTenant>, AgentIdentity<ResolvedTenant>) {
    started(params(max_steps))
}

/// The tool registered under `name`: `delete_order` deletes, `pay_invoice`
/// moves money, `get_salary` holds confidential data, `get_item` reads
/// `/items/{kind}`, and every other one reads public orders.
pub(crate) fn tool(name: &str) -> AgentTool<ResolvedTenant> {
    let (method, path, classification) = match name {
        "delete_order" => (ToolMethod::Delete, "/orders/{id}", DataClassLevel::Public),
        "pay_invoice" => (ToolMethod::Post, "/invoices/pay", DataClassLevel::Public),
        "get_salary" => (ToolMethod::Get, "/salaries", DataClassLevel::Confidential),
        "get_item" => (ToolMethod::Get, "/items/{kind}", DataClassLevel::Public),
        _ => (ToolMethod::Get, "/orders", DataClassLevel::Public),
    };
    registered(
        name,
        method,
        path,
        DeclaredAction::Undeclared,
        classification,
    )
}

/// The call to `tool` with `arguments`, as the model made it.
pub(crate) fn call(tool: &str, arguments: &str) -> ToolCall {
    ToolCall::new(tool, arguments).unwrap()
}

/// A call to `tool` with `arguments`, each part of its path filled with
/// `1`.
pub(crate) fn calling<'a>(
    tool: &'a AgentTool<ResolvedTenant>,
    arguments: &str,
) -> ResolvedCall<'a, ResolvedTenant> {
    let values = tool
        .path()
        .placeholders()
        .into_iter()
        .fold(PathValues::new(), |values, name| {
            values.with(name, PathValue::new("1").unwrap())
        });
    ResolvedCall::resolve(call(tool.name().as_str(), arguments), tool, &values).unwrap()
}

/// What a granted approval for `run`'s current pause on this call hands
/// over.
pub(crate) fn released(
    run: &AgentRun<ResolvedTenant>,
    tool: &str,
    arguments: &str,
) -> ReleasedCall {
    let at_step = run.pending().map_or(1, PendingCall::at_step);
    ReleasedCall::new(
        *run.id(),
        PendingCallRef::new(call(tool, arguments), at_step),
    )
}

/// A denial of the call `tool` with `arguments`, as a denied approval
/// request raised by `run` would give.
pub(crate) fn denied(run: &AgentRun<ResolvedTenant>, tool: &str, arguments: &str) -> DeniedCall {
    let at_step = run.pending().map_or(1, PendingCall::at_step);
    DeniedCall::new(
        *run.id(),
        PendingCallRef::new(call(tool, arguments), at_step),
    )
}

/// A model provider Bob connected, cleared for `clearance`.
pub(crate) fn provider(clearance: DataClassLevel) -> ModelProvider<ResolvedTenant> {
    let bob = person("bob@corp.test");
    ModelProvider::create(
        &holding(&bob, &MANAGE),
        CreateModelProviderParams {
            id: ModelProviderId::new(),
            name: Label::new("name", "prod-deepseek").unwrap(),
            kind: ModelProviderKind::SelfHosted,
            endpoint: ModelEndpoint::new("http://deepseek.models.svc:8000/v1").unwrap(),
            model: ModelName::new("deepseek-chat").unwrap(),
            pricing: ModelPricing::Unpriced,
            credential_ref: ProviderKey::Keyless,
            clearance,
        },
    )
    .unwrap()
}
