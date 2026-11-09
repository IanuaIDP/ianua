//! Workflows, steps, people and agents the execution tests build on.

use time::OffsetDateTime;

use crate::domains::agents::authority::capability::{
    CapabilitySet, DelegationConstraints, ResourceCapability,
};
use crate::domains::agents::authority::delegation::{
    Delegate, Delegation, GrantDelegationParams, HeldBy, HeldResources, ReviewDuty,
};
use crate::domains::agents::authority::intent::IntentEnvelope;
use crate::domains::agents::execution::run::{AgentRun, GoalTemplate};
use crate::domains::agents::execution::tool::ToolName;
use crate::domains::agents::execution::usage::Spend;
use crate::domains::agents::identity::agent::{AgentIdentity, CreateAgentParams};
use crate::domains::agents::identity::control::AgentControl;
use crate::domains::agents::oversight::approval::ApprovalAction;
use crate::domains::authorization::permission::{AgentAction, SystemPermission, WorkflowAction};
use crate::domains::data_classification::level::DataClassLevel;
use crate::domains::workflows::account::{
    AccountSharing, ConnectAccountParams, IntegrationAccount, OperationScope,
};
use crate::domains::workflows::data::{DataPath, FieldName, FlowData};
use crate::domains::workflows::design::condition::{Clause, ConditionRule, Matching, Test};
use crate::domains::workflows::design::graph::{Edge, WorkflowGraph};
use crate::domains::workflows::design::node::{
    AgentRunParams, AgentRunStep, Checks, CodeStep, Join, Mapping, Node, NodeKey, NodeKind, Port,
    Source, WaitStep, WorkflowApprovalStep,
};
use crate::domains::workflows::design::workflow::{
    CanvasLayout, CreateWorkflowParams, FailureAlert, RunLimit, Workflow,
};
use crate::domains::workflows::execution::record::ExecutionRecord;
use crate::domains::workflows::execution::step::StepState;
use crate::domains::workflows::execution::{
    ActingAuthority, AgentRunStart, Cause, ManualStartParams, RunAuthority, StartExecutionParams,
    WorkflowExecution,
};
use crate::domains::workflows::integration::risk_override::TenantOperation;
use crate::domains::workflows::integration::{
    AccountNeed, ActionAccount, ActionStep, InputNeed, InputSpec, IntegrationKey, OperationKey,
    OperationSpec, OperationSpecParams,
};
use crate::domains::workflows::triggers::Trigger;
use crate::isolation::scope::ResolvedTenant;
use crate::shared::clock::{self, FrozenClock};
use crate::shared::model::restriction::Restriction;
use crate::test_support::authority::assumed_authority;
use crate::types::{
    ActionClass, AgentId, DeclaredAction, EventType, EventVisibility, Human, HumanAccount,
    IntegrationAccountId, Label, Lifetime, ModelProviderId, PersonKey, SandboxVersionId,
    SealedSecret, Seconds, TenantId, UserId,
};

mod held;
mod loops;
mod rights;
mod rows;

pub(crate) use self::held::{held_code, held_version};
pub(crate) use self::loops::{approving_every_item, each, each_running, listing};
pub(crate) use self::rights::{deciding, holding_only, managing, publish_as, viewing};
pub(crate) use self::rows::stored;

pub(crate) type Execution = WorkflowExecution<ResolvedTenant>;

fn known(id: u128, address: &str) -> Human {
    Human::new(
        HumanAccount::User(UserId::from_uuid(uuid::Uuid::from_u128(id))),
        PersonKey::new(address).unwrap(),
    )
}

pub(crate) fn ann() -> Human {
    known(0xa, "ann@corp.test")
}

pub(crate) fn bob() -> Human {
    known(0xb, "bob@corp.test")
}

pub(crate) fn cid() -> Human {
    known(0xc, "cid@corp.test")
}

pub(crate) fn key(name: &str) -> NodeKey {
    NodeKey::new(name).unwrap()
}

pub(crate) fn field(name: &str) -> FieldName {
    FieldName::new(name).unwrap()
}

pub(crate) fn path(text: &str) -> DataPath {
    DataPath::parse(text).unwrap()
}

pub(crate) fn node(name: &str, kind: NodeKind, join: Join) -> Node {
    Node::new(key(name), Label::new("name", name).unwrap(), kind, join)
}

pub(crate) fn transform(name: &str, join: Join) -> Node {
    let mapping =
        Mapping::new(vec![(field("seen"), Source::Literal(FlowData::bool(true)))]).unwrap();
    node(name, NodeKind::Transform(mapping), join)
}

pub(crate) fn copy(name: &str, fields: &[(&str, &str)]) -> Node {
    let mapping = Mapping::new(
        fields
            .iter()
            .map(|(name, from)| (field(name), Source::Input(path(from))))
            .collect(),
    )
    .unwrap();
    node(name, NodeKind::Transform(mapping), Join::All)
}

pub(crate) fn condition(name: &str) -> Node {
    let rule = ConditionRule::new(
        Matching::All,
        vec![Clause::new(path("trigger.ok"), Test::Equals(FlowData::bool(true))).unwrap()],
    )
    .unwrap();
    node(name, NodeKind::Condition(rule), Join::All)
}

pub(crate) fn approval_of(name: &str, class: DeclaredAction) -> Node {
    let step = WorkflowApprovalStep::new(
        ApprovalAction::new("send the weekly report").unwrap(),
        class,
        Lifetime::seconds(3600).unwrap(),
    )
    .unwrap();
    node(name, NodeKind::Approval(step), Join::All)
}

pub(crate) fn approval(name: &str) -> Node {
    approval_of(name, DeclaredAction::Declared(ActionClass::Communicate))
}

pub(crate) fn wait(name: &str) -> Node {
    let step = WaitStep::new(Lifetime::seconds(3600).unwrap()).unwrap();
    node(name, NodeKind::Wait(step), Join::All)
}

/// A step running a sandbox version's code on the trigger's `ok` field.
pub(crate) fn code(name: &str) -> Node {
    let inputs = Mapping::new(vec![(field("ok"), Source::Input(path("trigger.ok")))]).unwrap();
    let step = CodeStep::new(SandboxVersionId::new(), inputs);
    node(name, NodeKind::Code(step), Join::All)
}

/// The most an agent step's run may spend: two of the tenant's currency.
pub(crate) const STEP_SPEND_CAP: Spend = Spend::from_micros(2_000_000);

/// What an agent step's run may spend before it pauses for a person: one
/// of the tenant's currency.
pub(crate) const STEP_ASK_PAST: Spend = Spend::from_micros(1_000_000);

pub(crate) fn agent_step(agent: AgentId, tools: &[&str]) -> Node {
    let step = AgentRunStep::new(AgentRunParams {
        agent_id: agent,
        provider_id: provider(),
        goal: GoalTemplate::new("summarise the orders").unwrap(),
        inputs: Mapping::new(vec![(field("orders"), Source::Input(path("trigger")))]).unwrap(),
        purpose: IntentEnvelope::new([ActionClass::Read]),
        tools: tools
            .iter()
            .map(|tool| ToolName::new(*tool).unwrap())
            .collect(),
        approval_classes: vec![ActionClass::Write],
        max_steps: 5,
        spend_cap: Restriction::To(STEP_SPEND_CAP),
        ask_past: Restriction::To(STEP_ASK_PAST),
        checks: Checks::Nothing,
    })
    .unwrap();
    node("summarise", NodeKind::AgentRun(step), Join::All)
}

/// One agent run of a flow's stage, by a fresh agent, reading nothing of
/// its own.
pub(crate) fn stage_run() -> AgentRunParams {
    AgentRunParams {
        agent_id: AgentId::new(),
        provider_id: provider(),
        goal: GoalTemplate::new("summarise the open incidents").unwrap(),
        inputs: Mapping::new(Vec::new()).unwrap(),
        purpose: IntentEnvelope::new([ActionClass::Read]),
        tools: Vec::new(),
        approval_classes: Vec::new(),
        max_steps: 5,
        spend_cap: Restriction::Unrestricted,
        ask_past: Restriction::Unrestricted,
        checks: Checks::Nothing,
    }
}

pub(crate) fn spec_of(effect: ActionClass, ceiling: DataClassLevel) -> OperationSpec {
    OperationSpec::new(OperationSpecParams {
        integration: IntegrationKey::new("google-sheets").unwrap(),
        operation: OperationKey::new("append-row").unwrap(),
        inputs: vec![InputSpec::new(field("values"), InputNeed::Required)],
        effect: DeclaredAction::Declared(effect),
        account: AccountNeed::Account,
        ceiling,
    })
    .unwrap()
}

/// `spec` as a tenant that raised nothing treats it.
pub(crate) fn offered(spec: OperationSpec) -> TenantOperation {
    TenantOperation::of::<ResolvedTenant>(spec, &[])
}

pub(crate) fn append_row() -> OperationSpec {
    spec_of(ActionClass::Write, DataClassLevel::Internal)
}

pub(crate) fn append() -> OperationKey {
    OperationKey::new("append-row").unwrap()
}

pub(crate) fn sheet_account(
    owner: &Human,
    integration: &str,
) -> IntegrationAccount<ResolvedTenant> {
    IntegrationAccount::connect(
        ConnectAccountParams {
            id: IntegrationAccountId::new(),
            integration: IntegrationKey::new(integration).unwrap(),
            name: Label::new("name", "Finance sheets").unwrap(),
            credential: SealedSecret::new("v1.AAECAwQF").unwrap(),
            sharing: AccountSharing::Tenant,
            scope: OperationScope::All,
        },
        &managing(owner),
    )
    .unwrap()
}

pub(crate) fn action(name: &str, account: IntegrationAccountId) -> Node {
    let inputs = Mapping::new(vec![(field("values"), Source::Input(path("trigger")))]).unwrap();
    let step = ActionStep::new(&append_row(), ActionAccount::Account(account), inputs).unwrap();
    node(name, NodeKind::Action(step), Join::All)
}

pub(crate) fn draft_with(
    nodes: Vec<Node>,
    edges: Vec<Edge>,
    trigger: Trigger,
) -> Workflow<ResolvedTenant> {
    let designer = ann();
    Workflow::create(
        CreateWorkflowParams {
            name: Label::new("name", "Weekly report").unwrap(),
            description: None,
            graph: WorkflowGraph::new(nodes, edges).unwrap(),
            layout: CanvasLayout::default(),
            trigger,
            run_limit: RunLimit::new(Lifetime::seconds(86_400).unwrap()).unwrap(),
            failure_alert: FailureAlert::default(),
        },
        &rights::managing(&designer),
    )
    .unwrap()
}

pub(crate) fn draft(nodes: Vec<Node>, edges: Vec<Edge>) -> Workflow<ResolvedTenant> {
    draft_with(nodes, edges, Trigger::Manual)
}

/// A publisher who may see every event.
pub(crate) struct SeesAll;

impl EventVisibility for SeesAll {
    fn may_see(&self, _event_type: &EventType) -> bool {
        true
    }
}

pub(crate) fn published(nodes: Vec<Node>, edges: Vec<Edge>) -> Workflow<ResolvedTenant> {
    let mut workflow = draft(nodes, edges);
    publish_as(&mut workflow, &ann(), &[offered(append_row())], &SeesAll).unwrap();
    workflow
}

/// Whether the trigger's data passes the [`condition`] steps test.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Check {
    Passes,
    Fails,
}

pub(crate) fn trigger_data(check: Check) -> FlowData {
    let ok = matches!(check, Check::Passes);
    FlowData::map(vec![(field("ok"), FlowData::bool(ok))]).unwrap()
}

/// A start by hand with [`trigger_data`] that `check`s, at `exposure`, by
/// Ann, who was given use of no resources.
pub(crate) fn by_hand_where(check: Check, exposure: DataClassLevel) -> ManualStartParams {
    ManualStartParams {
        resources: HeldResources::answered(ann().principal(), Vec::new()),
        input: trigger_data(check),
        exposure,
    }
}

/// A start by hand whose data passes the [`condition`] steps test.
pub(crate) fn by_hand(exposure: DataClassLevel) -> ManualStartParams {
    by_hand_where(Check::Passes, exposure)
}

/// `person`, with full control of workflows and use of no resources,
/// starts `workflow` by hand.
pub(crate) fn start_as(
    workflow: &Workflow<ResolvedTenant>,
    person: &Human,
    params: ManualStartParams,
) -> Result<(Execution, Vec<ExecutionRecord>), crate::shared::errors::DomainError> {
    let theirs = ManualStartParams {
        resources: HeldResources::answered(person.principal(), Vec::new()),
        ..params
    };
    Execution::start_by_hand(workflow, managing(person), theirs)
}

/// What `cause` starts for `acting_for`, with data that passes, at public.
pub(crate) fn on_trigger(acting_for: &Human, cause: Cause) -> StartExecutionParams {
    StartExecutionParams {
        acting_for: acting(acting_for),
        cause,
        input: trigger_data(Check::Passes),
        exposure: DataClassLevel::Public,
    }
}

pub(crate) fn start(workflow: &Workflow<ResolvedTenant>) -> (Execution, Vec<ExecutionRecord>) {
    start_as(workflow, &ann(), by_hand(DataClassLevel::Internal)).unwrap()
}

pub(crate) fn started(nodes: Vec<Node>, edges: Vec<Edge>) -> Execution {
    start(&published(nodes, edges)).0
}

pub(crate) fn edge(from: &str, port: Port, to: &str) -> Edge {
    Edge::new(key(from), port, key(to))
}

pub(crate) fn state(execution: &Execution, name: &str) -> StepState {
    execution.step(&key(name)).unwrap().clone()
}

pub(crate) fn approve(execution: &mut Execution, name: &str) -> Vec<ExecutionRecord> {
    execution.request_approval(&key(name)).unwrap();
    approve_as(execution, name, &bob()).unwrap()
}

/// `by` approves the step `name`, after being shown its input.
pub(crate) fn approve_as(
    execution: &mut Execution,
    name: &str,
    by: &Human,
) -> Result<Vec<ExecutionRecord>, crate::shared::errors::DomainError> {
    let shown = execution.approval_input(&key(name)).unwrap();
    execution.approve(&key(name), &deciding(by), &shown)
}

pub(crate) fn instant(seconds: i64) -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_800_000_000 + seconds).unwrap()
}

pub(crate) fn frozen_at(seconds: i64) -> FrozenClock {
    clock::freeze(instant(seconds))
}

pub(crate) fn delegation_with(
    delegator: &Human,
    delegate: &AgentIdentity<ResolvedTenant>,
    constraints: DelegationConstraints,
) -> Delegation<ResolvedTenant> {
    Delegation::grant(
        GrantDelegationParams {
            granted: CapabilitySet::new(Vec::new(), Vec::new()),
            constraints,
            name: None,
        },
        &HeldBy::worked_out::<ResolvedTenant>(
            &control_by(delegator),
            &CapabilitySet::new(Vec::new(), Vec::new()),
            &HeldResources::answered(delegator.principal(), Vec::new()),
            &[],
        )
        .unwrap(),
        &Delegate {
            agent: delegate,
            duty: ReviewDuty::NotReviewing,
        },
    )
    .unwrap()
}

pub(crate) fn delegation(
    delegator: &Human,
    delegate: &AgentIdentity<ResolvedTenant>,
) -> Delegation<ResolvedTenant> {
    delegation_with(
        delegator,
        delegate,
        DelegationConstraints::new(Seconds::new(600), 1).unwrap(),
    )
}

pub(crate) fn agent() -> AgentIdentity<ResolvedTenant> {
    let owner = human("owner@corp.test");
    AgentIdentity::create(
        &AgentControl::new(assumed_authority(
            &owner,
            TenantId::new(),
            &[SystemPermission::Agents(AgentAction::Create)],
            &[],
        )),
        CreateAgentParams {
            name: Label::new("name", "order-summariser").unwrap(),
            description: None,
        },
    )
    .unwrap()
}

/// `by` acting on an agent with nothing but being who they are, which is
/// enough for the agent's owner.
pub(crate) fn control_by(by: &Human) -> AgentControl<'_> {
    AgentControl::new(assumed_authority(by, TenantId::new(), &[], &[]))
}

fn human(address: &str) -> Human {
    Human::new(
        HumanAccount::User(UserId::new()),
        PersonKey::new(address).unwrap(),
    )
}

pub(crate) fn agent_execution(agent: &AgentIdentity<ResolvedTenant>, tools: &[&str]) -> Execution {
    started(vec![agent_step(*agent.id(), tools)], Vec::new())
}

pub(crate) fn running_agent(
    execution: &mut Execution,
    agent: &AgentIdentity<ResolvedTenant>,
) -> AgentRun<ResolvedTenant> {
    let authority = acting(execution.acting_for());
    let started = execution
        .start_agent_run(
            &key("summarise"),
            &RunAuthority::NoDelegation,
            agent,
            &authority,
        )
        .unwrap();
    let AgentRunStart::Started(run, _) = started else {
        panic!("the agent run step was refused");
    };
    *run
}

/// The model provider every agent step in these tests reasons with.
pub(crate) fn provider() -> ModelProviderId {
    ModelProviderId::from_uuid(uuid::Uuid::from_u128(0x9e0))
}

/// What `person` holds: they may run workflows and use [`provider`].
pub(crate) fn acting(person: &Human) -> ActingAuthority {
    ActingAuthority::assumed(person.clone(), runs_workflows())
}

/// Leave to run workflows, lend the accounts one connected, and use
/// [`provider`].
pub(crate) fn runs_workflows() -> CapabilitySet {
    CapabilitySet::new(
        vec![
            SystemPermission::Workflows(WorkflowAction::Run),
            SystemPermission::Workflows(WorkflowAction::ConnectAccounts),
        ],
        Vec::new(),
    )
    .with_resources(vec![ResourceCapability::use_of_provider(&provider())])
}
