//! Workflows, steps and the people behind them, as the workflows tests build
//! them.

use ianua_domain::domains::agents::authority::intent::IntentEnvelope;
use ianua_domain::domains::agents::execution::run::GoalTemplate;
use ianua_domain::domains::agents::oversight::approval::ApprovalAction;
use ianua_domain::domains::authorization::permission::{SystemPermission, WorkflowAction};
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::domains::workflows::control::WorkflowControl;
use ianua_domain::domains::workflows::data::{DataPath, FieldName, FlowData};
use ianua_domain::domains::workflows::design::graph::{Edge, WorkflowGraph};
use ianua_domain::domains::workflows::design::node::{
    AgentRunParams, AgentRunStep, Checks, Covering, Join, LoopParams, LoopStep, Mapping, Node,
    NodeKey, NodeKind, Port, Source, WaitStep, WorkflowApprovalStep,
};
use ianua_domain::domains::workflows::design::workflow::{
    CanvasLayout, CodeReach, CreateWorkflowParams, FailureAlert, PublishFacts, Replaces, RunLimit,
    RunnableCode, Workflow,
};
use ianua_domain::domains::workflows::integration::company::{CompanyOperation, PERSON_INPUT};
use ianua_domain::domains::workflows::integration::events::ServiceEventSpec;
use ianua_domain::domains::workflows::integration::risk_override::{
    OperationRiskOverride, TenantOperation,
};
use ianua_domain::domains::workflows::integration::{
    AccountNeed, ActionAccount, ActionStep, InputNeed, InputSpec, IntegrationKey, OperationKey,
    OperationSpec, OperationSpecParams, ROUTE_INPUT,
};
use ianua_domain::domains::workflows::triggers::Trigger;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::model::restriction::Restriction;
use ianua_domain::test_support::authority::assumed_authority;
use ianua_domain::types::{
    ActionClass, AgentId, DeclaredAction, EventType, EventVisibility, Human, HumanAccount,
    IntegrationAccountId, Label, Lifetime, ModelProviderId, PersonKey, UserId,
};

use crate::test_support::test_ctx;

/// Every workflow right there is.
pub const WORKFLOW_RIGHTS: [SystemPermission; 8] = [
    SystemPermission::Workflows(WorkflowAction::Manage),
    SystemPermission::Workflows(WorkflowAction::View),
    SystemPermission::Workflows(WorkflowAction::Create),
    SystemPermission::Workflows(WorkflowAction::Update),
    SystemPermission::Workflows(WorkflowAction::Delete),
    SystemPermission::Workflows(WorkflowAction::Run),
    SystemPermission::Workflows(WorkflowAction::Approve),
    SystemPermission::Workflows(WorkflowAction::ConnectAccounts),
];

/// The integration every action step in these tests calls.
pub const SHEETS: &str = "google-sheets";

/// The operation every action step in these tests calls.
pub const APPEND_ROW: &str = "append-row";

/// A person with a tenant account of their own, reached at `address`.
///
/// # Panics
///
/// Panics if `address` is not an address.
#[must_use]
pub fn person(address: &str) -> Human {
    Human::new(
        HumanAccount::User(UserId::new()),
        PersonKey::new(address).expect("a test passes an address"),
    )
}

/// `by`, holding every workflow right, in the test tenant.
#[must_use]
pub fn managing(by: &Human) -> WorkflowControl<'static> {
    WorkflowControl::new(assumed_authority(
        by,
        test_ctx().tenant_id(),
        &WORKFLOW_RIGHTS,
        &[],
    ))
}

/// The step key `name`.
///
/// # Panics
///
/// Panics if `name` is not a step key.
#[must_use]
pub fn step(name: &str) -> NodeKey {
    NodeKey::new(name).expect("a test passes a step key")
}

fn field(name: &str) -> FieldName {
    FieldName::new(name).expect("a test passes a field name")
}

fn trigger_path() -> DataPath {
    DataPath::parse("trigger").expect("the trigger is a path")
}

fn node(name: &str, kind: NodeKind) -> Node {
    Node::new(
        step(name),
        Label::new("name", name).expect("a test passes a name"),
        kind,
        Join::All,
    )
}

/// A step that copies a fixed value, finishing the moment it is reached.
#[must_use]
pub fn tidy_step(name: &str) -> Node {
    let mapping = Mapping::new(vec![(field("seen"), Source::Literal(FlowData::bool(true)))])
        .expect("one field is a mapping");
    node(name, NodeKind::Transform(mapping))
}

/// An approval step for actions of `class`, open for an hour.
#[must_use]
pub fn approval_step(name: &str, class: ActionClass) -> Node {
    let approval = WorkflowApprovalStep::new(
        ApprovalAction::new("send the weekly report").expect("a summary"),
        DeclaredAction::Declared(class),
        Lifetime::seconds(3600).expect("an hour"),
    )
    .expect("an hour is a decision window");
    node(name, NodeKind::Approval(approval))
}

/// A step that waits an hour.
#[must_use]
pub fn wait_step(name: &str) -> Node {
    let wait = WaitStep::new(Lifetime::seconds(3600).expect("an hour")).expect("an hour wait");
    node(name, NodeKind::Wait(wait))
}

/// A step giving back `items` as a list of texts under `issues`, finishing
/// the moment it is reached.
#[must_use]
pub fn listing_step(name: &str, items: &[&str]) -> Node {
    let list = FlowData::list(
        items
            .iter()
            .map(|item| FlowData::text(*item).expect("a short text"))
            .collect(),
    )
    .expect("a short list");
    let mapping = Mapping::new(vec![(field("issues"), Source::Literal(list))])
        .expect("one field is a mapping");
    node(name, NodeKind::Transform(mapping))
}

/// A loop over the list at `over`, running `body` for each item, one at a
/// time, for at most ten items.
///
/// # Panics
///
/// Panics if `over` is not a path or `body` is not a graph.
#[must_use]
pub fn loop_step(name: &str, over: &str, body: Vec<Node>) -> Node {
    let step = LoopStep::new(LoopParams {
        over: DataPath::parse(over).expect("a test passes a path"),
        inputs: Mapping::new(Vec::new()).expect("no field is a mapping"),
        body: WorkflowGraph::new(body, Vec::new()).expect("a test passes a graph"),
        most: 10,
        at_once: 1,
    })
    .expect("a bounded loop");
    node(name, NodeKind::Loop(step))
}

/// A loop over the list at `over`, two at a time, for at most ten items,
/// whose first step `approve-all` asks one approval of `class` for every
/// item, then `tidy` tidies each.
///
/// # Panics
///
/// Panics if `over` is not a path.
#[must_use]
pub fn every_item_loop_step(name: &str, over: &str, class: ActionClass) -> Node {
    let approval = WorkflowApprovalStep::new(
        ApprovalAction::new("close the stale issues").expect("a summary"),
        DeclaredAction::Declared(class),
        Lifetime::seconds(3600).expect("an hour"),
    )
    .expect("an hour is a decision window")
    .covering(Covering::WholeLoop);
    let body = WorkflowGraph::new(
        vec![
            node("approve-all", NodeKind::Approval(approval)),
            tidy_step("tidy"),
        ],
        vec![next("approve-all", "tidy")],
    )
    .expect("a test passes a graph");
    let step = LoopStep::new(LoopParams {
        over: DataPath::parse(over).expect("a test passes a path"),
        inputs: Mapping::new(Vec::new()).expect("no field is a mapping"),
        body,
        most: 10,
        at_once: 2,
    })
    .expect("a bounded loop asking first");
    node(name, NodeKind::Loop(step))
}

/// The model provider every agent step in these tests reasons with.
#[must_use]
pub fn test_provider() -> ModelProviderId {
    ModelProviderId::from_uuid(uuid::Uuid::from_u128(0x9e0))
}

/// An agent run where `agent` summarises the trigger's data, calling no
/// tool: one step of a workflow, or one run of a flow's stage.
#[must_use]
pub fn summary_run(agent: AgentId) -> AgentRunParams {
    AgentRunParams {
        agent_id: agent,
        provider_id: test_provider(),
        goal: GoalTemplate::new("summarise the orders").expect("a goal"),
        inputs: Mapping::new(vec![(field("orders"), Source::Input(trigger_path()))])
            .expect("one field is a mapping"),
        purpose: IntentEnvelope::new([ActionClass::Read]),
        tools: Vec::new(),
        approval_classes: vec![ActionClass::Write],
        max_steps: 5,
        spend_cap: Restriction::Unrestricted,
        ask_past: Restriction::Unrestricted,
        checks: Checks::Nothing,
    }
}

/// A step that has `agent` summarise the trigger's data, calling no tool.
#[must_use]
pub fn agent_step(name: &str, agent: AgentId) -> Node {
    let run = AgentRunStep::new(summary_run(agent)).expect("a bounded agent step");
    node(name, NodeKind::AgentRun(run))
}

/// The spreadsheet's "append row" operation, declared as `class`, needing
/// an account and taking `values`.
#[must_use]
pub fn append_row(class: ActionClass) -> OperationSpec {
    OperationSpec::new(OperationSpecParams {
        integration: IntegrationKey::new(SHEETS).expect("an integration key"),
        operation: OperationKey::new(APPEND_ROW).expect("an operation key"),
        inputs: vec![InputSpec::new(field("values"), InputNeed::Required)],
        effect: DeclaredAction::Declared(class),
        account: AccountNeed::Account,
        ceiling: DataClassLevel::Confidential,
    })
    .expect("a valid operation")
}

/// A step that appends the trigger's data to a sheet through `account`.
#[must_use]
pub fn append_step(name: &str, account: IntegrationAccountId) -> Node {
    let inputs = Mapping::new(vec![(field("values"), Source::Input(trigger_path()))])
        .expect("one field is a mapping");
    let action = ActionStep::new(
        &append_row(ActionClass::Write),
        ActionAccount::Account(account),
        inputs,
    )
    .expect("the step fits its operation");
    node(name, NodeKind::Action(action))
}

/// Protected apps' "get": a read of one route behind the gateway, acting
/// as the run's person.
#[must_use]
pub fn app_read() -> OperationSpec {
    OperationSpec::new(OperationSpecParams {
        integration: IntegrationKey::new("apps").expect("an integration key"),
        operation: OperationKey::new("get").expect("an operation key"),
        inputs: vec![
            InputSpec::new(field(ROUTE_INPUT), InputNeed::Required),
            InputSpec::new(field("path"), InputNeed::Required),
        ],
        effect: DeclaredAction::Declared(ActionClass::Read),
        account: AccountNeed::RunPerson,
        ceiling: DataClassLevel::Confidential,
    })
    .expect("a valid operation")
}

/// A step reading `/orders` from the route `route`, written as given, as
/// the run's person.
#[must_use]
pub fn app_step(name: &str, route: &str) -> Node {
    let literal = |text: &str| Source::Literal(FlowData::text(text).expect("short text"));
    let inputs = Mapping::new(vec![
        (field(ROUTE_INPUT), literal(route)),
        (field("path"), literal("/orders")),
    ])
    .expect("two fields are a mapping");
    let action = ActionStep::new(&app_read(), ActionAccount::NoAccount, inputs)
        .expect("the step fits its operation");
    node(name, NodeKind::Action(action))
}

/// Protected data's Postgres "query": a read of one database behind a
/// stream route, acting as the run's person with the login the route keeps.
#[must_use]
pub fn data_query() -> OperationSpec {
    OperationSpec::new(OperationSpecParams {
        integration: IntegrationKey::new("postgres").expect("an integration key"),
        operation: OperationKey::new("query").expect("an operation key"),
        inputs: vec![
            InputSpec::new(field(ROUTE_INPUT), InputNeed::Required),
            InputSpec::new(field("statement"), InputNeed::Required),
        ],
        effect: DeclaredAction::Declared(ActionClass::Read),
        account: AccountNeed::RunPersonData,
        ceiling: DataClassLevel::Confidential,
    })
    .expect("a valid operation")
}

/// A step querying the orders table through the stream route `route`,
/// written as given, as the run's person.
#[must_use]
pub fn data_step(name: &str, route: &str) -> Node {
    let literal = |text: &str| Source::Literal(FlowData::text(text).expect("short text"));
    let inputs = Mapping::new(vec![
        (field(ROUTE_INPUT), literal(route)),
        (field("statement"), literal("select id from orders")),
    ])
    .expect("two fields are a mapping");
    let action = ActionStep::new(&data_query(), ActionAccount::NoAccount, inputs)
        .expect("the step fits its operation");
    node(name, NodeKind::Action(action))
}

/// The company's "sign out everywhere", as the catalog offers it.
///
/// # Panics
///
/// Never: the company's steps describe themselves.
#[must_use]
pub fn sign_out() -> OperationSpec {
    CompanyOperation::SignOut
        .spec(DataClassLevel::Confidential)
        .expect("a company step describes itself")
}

/// A step signing Lee out everywhere, one of the company's own steps,
/// made as the run's person.
///
/// # Panics
///
/// Never: the step is fixed and fits its operation.
#[must_use]
pub fn sign_out_step(name: &str) -> Node {
    let literal = |text: &str| Source::Literal(FlowData::text(text).expect("short text"));
    let inputs = Mapping::new(vec![(field(PERSON_INPUT), literal("lee@corp.test"))])
        .expect("one field is a mapping");
    let action = ActionStep::new(&sign_out(), ActionAccount::NoAccount, inputs)
        .expect("the step fits its spec");
    node(name, NodeKind::Action(action))
}

/// The company step Allow, which lets the change a "before" rule decides go
/// ahead.
///
/// # Panics
///
/// Never: the step is fixed and takes no inputs.
#[must_use]
pub fn allow_step(name: &str) -> Node {
    let inputs = Mapping::new(Vec::new()).expect("no fields is a mapping");
    let action = ActionStep::new(&allow(), ActionAccount::NoAccount, inputs)
        .expect("the step fits its spec");
    node(name, NodeKind::Action(action))
}

/// The company step Allow, as the catalog describes it.
fn allow() -> OperationSpec {
    CompanyOperation::Allow
        .spec(DataClassLevel::Internal)
        .expect("a company step describes itself")
}

/// An edge from `from` to `to`, on its one way out.
#[must_use]
pub fn next(from: &str, to: &str) -> Edge {
    Edge::new(step(from), Port::Next, step(to))
}

/// A draft `by` designed, of `nodes` joined by `edges`, started by hand and
/// allowed a day per run.
///
/// # Panics
///
/// Panics if the steps do not form a graph.
#[must_use]
pub fn draft_by(by: &Human, nodes: Vec<Node>, edges: Vec<Edge>) -> Workflow<ResolvedTenant> {
    draft_on(by, nodes, edges, Trigger::Manual)
}

/// A draft `by` designed, of `nodes` joined by `edges`, started by
/// `trigger`.
///
/// # Panics
///
/// Panics if the steps do not form a graph.
#[must_use]
pub fn draft_on(
    by: &Human,
    nodes: Vec<Node>,
    edges: Vec<Edge>,
    trigger: Trigger,
) -> Workflow<ResolvedTenant> {
    Workflow::create(
        CreateWorkflowParams {
            name: Label::new("name", "Weekly report").expect("a name"),
            description: None,
            graph: WorkflowGraph::new(nodes, edges).expect("the steps form a graph"),
            layout: CanvasLayout::default(),
            trigger,
            run_limit: RunLimit::new(Lifetime::seconds(86_400).expect("a day")).expect("a day"),
            failure_alert: FailureAlert::default(),
        },
        &managing(by),
    )
    .expect("someone managing workflows drafts one")
}

/// Someone a test says may see every event.
pub struct SeesEverything;

impl EventVisibility for SeesEverything {
    fn may_see(&self, _event_type: &EventType) -> bool {
        true
    }
}

/// The operations the test catalog offers, as no tenant overrides them.
fn offered_operations() -> [TenantOperation; 5] {
    let none: &[OperationRiskOverride<ResolvedTenant>] = &[];
    [
        TenantOperation::of(append_row(ActionClass::Write), none),
        TenantOperation::of(app_read(), none),
        TenantOperation::of(data_query(), none),
        TenantOperation::of(sign_out(), none),
        TenantOperation::of(allow(), none),
    ]
}

/// `workflow`, published by `by` as it stands, with the spreadsheet's
/// "append row" offered as a write, the company's sign-out and Allow
/// offered, and
/// every sandbox version its code steps name able to run.
///
/// # Panics
///
/// Panics if the draft may not be published.
#[must_use]
pub fn published_by(
    by: &Human,
    mut workflow: Workflow<ResolvedTenant>,
) -> Workflow<ResolvedTenant> {
    let offered = offered_operations();
    let events = offered_as_named(workflow.trigger());
    let runnable: Vec<_> = workflow
        .graph()
        .code_steps()
        .map(|(_, step)| RunnableCode {
            version: step.version(),
            reach: CodeReach::Closed,
        })
        .collect();
    let reviewed = workflow.revision();
    workflow
        .publish(
            &managing(by),
            reviewed,
            Replaces::Nothing,
            PublishFacts {
                offered: &offered,
                events: &events,
                sees: &SeesEverything,
                runnable: &runnable,
            },
        )
        .expect("the draft may be published");
    workflow
}

/// The service event `trigger` starts on, offered with exactly the filters
/// it gives, each required; none for any other trigger.
#[must_use]
pub fn offered_as_named(trigger: &Trigger) -> Vec<ServiceEventSpec> {
    let Trigger::Service(on) = trigger else {
        return Vec::new();
    };
    let filters = on
        .filters()
        .iter()
        .map(|filter| InputSpec::new(filter.name().clone(), InputNeed::Required))
        .collect();
    vec![
        ServiceEventSpec::new(on.integration().clone(), on.event().clone(), filters)
            .expect("a trigger's filters are named once"),
    ]
}
