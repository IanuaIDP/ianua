#![cfg(test)]
//! Whole workflows run through the public API, the way the app drives them:
//! an agent works under a person's delegation, a condition reads what it
//! answered, two people approve a payment, and the integration is called
//! only then. Each scenario checks what reaches the agent, what reaches the
//! integration, and what reaches the audit trail.

use ianua_domain::domains::agents::authority::capability::{
    CapabilitySet, DelegationConstraints, ResourceCapability,
};
use ianua_domain::domains::agents::authority::delegation::{
    ActingUnder, Delegate, Delegation, GrantDelegationParams, HeldBy, HeldResources, ReviewDuty,
};
use ianua_domain::domains::agents::authority::intent::IntentEnvelope;
use ianua_domain::domains::agents::execution::run::{AgentRun, GoalTemplate};
use ianua_domain::domains::agents::execution::tool::ToolName;
use ianua_domain::domains::agents::identity::agent::{
    AgentIdentity, CreateAgentParams, SuspendedBy,
};
use ianua_domain::domains::agents::identity::control::AgentControl;
use ianua_domain::domains::agents::oversight::approval::{ApprovalAction, Presence};
use ianua_domain::domains::authorization::permission::{
    AgentAction, SystemPermission, WorkflowAction,
};
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::domains::notifications::category::VisibleTo;
use ianua_domain::domains::workflows::account::{
    AccountSharing, ConnectAccountParams, IntegrationAccount, OperationScope,
};
use ianua_domain::domains::workflows::control::{StepApprover, WorkflowControl};
use ianua_domain::domains::workflows::data::{DataPath, FieldName, FlowData};
use ianua_domain::domains::workflows::design::condition::{Clause, ConditionRule, Matching, Test};
use ianua_domain::domains::workflows::design::graph::{Edge, WorkflowGraph};
use ianua_domain::domains::workflows::design::node::{
    AgentRunParams, AgentRunStep, Checks, Join, Mapping, Node, NodeKey, NodeKind, Port, Source,
    WorkflowApprovalStep,
};
use ianua_domain::domains::workflows::design::workflow::{
    CanvasLayout, CreateWorkflowParams, FailureAlert, PublishFacts, Replaces, RunLimit, Workflow,
};
use ianua_domain::domains::workflows::events::execution_events;
use ianua_domain::domains::workflows::execution::record::{
    ExecutionEnd, ExecutionRecord, StepRecord,
};
use ianua_domain::domains::workflows::execution::step::{ActionOutcome, StepState};
use ianua_domain::domains::workflows::execution::{
    ANSWER_FIELD, ActingAuthority, ActionCall, ActionClearance, ActionStart, AgentRunStart,
    ExecutionStatus, ManualStartParams, Offer, RunAuthority, WorkflowExecution,
};
use ianua_domain::domains::workflows::integration::risk_override::TenantOperation;
use ianua_domain::domains::workflows::integration::{
    AccountNeed, ActionAccount, ActionStep, InputNeed, InputSpec, IntegrationKey, OperationKey,
    OperationSpec, OperationSpecParams,
};
use ianua_domain::domains::workflows::triggers::Trigger;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::events::event::DomainEvent;
use ianua_domain::shared::model::restriction::Restriction;
use ianua_domain::test_support::authority::assumed_authority;
use ianua_domain::types::event_type::WorkflowsEvent;
use ianua_domain::types::{
    ActionClass, DeclaredAction, EventType, Human, HumanAccount, IntegrationAccountId, Label,
    Lifetime, ModelProviderId, PersonKey, SealedSecret, Seconds, TenantId, UserId,
};

type Execution = WorkflowExecution<ResolvedTenant>;

fn person(address: &str) -> Human {
    Human::new(
        HumanAccount::User(UserId::new()),
        PersonKey::new(address).unwrap(),
    )
}

fn key(name: &str) -> NodeKey {
    NodeKey::new(name).unwrap()
}

fn field(name: &str) -> FieldName {
    FieldName::new(name).unwrap()
}

fn node(name: &str, kind: NodeKind) -> Node {
    Node::new(
        key(name),
        Label::new("name", name).unwrap(),
        kind,
        Join::All,
    )
}

fn edge(from: &str, port: Port, to: &str) -> Edge {
    Edge::new(key(from), port, key(to))
}

/// The model provider the finance team's agent reasons with.
fn provider() -> ModelProviderId {
    ModelProviderId::from_uuid(uuid::Uuid::from_u128(0x9e0))
}

/// What each person on the team holds: they may run workflows, lend the
/// accounts they connected, and use the team's model provider.
fn held() -> CapabilitySet {
    CapabilitySet::new(
        vec![
            SystemPermission::Workflows(WorkflowAction::Run),
            SystemPermission::Workflows(WorkflowAction::ConnectAccounts),
        ],
        Vec::new(),
    )
    .with_resources(vec![ResourceCapability::use_of_provider(&provider())])
}

/// What `person` holds right now, as [`held`] says.
fn holding(person: &Human) -> ActingAuthority {
    ActingAuthority::assumed(person.clone(), held())
}

/// What the finance team's workflow is made of.
struct Finance {
    ann: Human,
    agent: AgentIdentity<ResolvedTenant>,
    account: IntegrationAccount<ResolvedTenant>,
    payment: OperationSpec,
    workflow: Workflow<ResolvedTenant>,
}

/// Ann's workflow: an agent looks for late invoices, and when it finds
/// one, two people approve paying it before the bank is called.
fn finance() -> Finance {
    let ann = person("ann@corp.test");
    let agent = AgentIdentity::create(
        &agent_control(&ann, &[SystemPermission::Agents(AgentAction::Create)]),
        CreateAgentParams {
            name: Label::new("name", "invoice-checker").unwrap(),
            description: None,
        },
    )
    .unwrap();
    let payment = payment_operation();
    let account = bank_account(&ann);
    let workflow = workflow_for(&ann, &agent, &account, &payment);
    Finance {
        ann,
        agent,
        account,
        payment,
        workflow,
    }
}

/// The bank requires an invoice note and treats every payment as a financial action.
fn payment_operation() -> OperationSpec {
    OperationSpec::new(OperationSpecParams {
        integration: IntegrationKey::new("bank").unwrap(),
        operation: OperationKey::new("pay-invoice").unwrap(),
        inputs: vec![InputSpec::new(field("note"), InputNeed::Required)],
        effect: DeclaredAction::Declared(ActionClass::Financial),
        account: AccountNeed::Account,
        ceiling: DataClassLevel::Confidential,
    })
    .unwrap()
}

/// Ann's bank credential remains available only to her own workflow executions.
fn bank_account(ann: &Human) -> IntegrationAccount<ResolvedTenant> {
    IntegrationAccount::connect(
        ConnectAccountParams {
            id: IntegrationAccountId::new(),
            integration: IntegrationKey::new("bank").unwrap(),
            name: Label::new("name", "Company bank").unwrap(),
            credential: SealedSecret::new("v1.AAECAwQF").unwrap(),
            sharing: AccountSharing::OwnerOnly,
            scope: OperationScope::All,
        },
        &managing(ann),
    )
    .unwrap()
}

/// Publishes the finance graph under Ann's authority against the bank's operation contract.
fn workflow_for(
    ann: &Human,
    agent: &AgentIdentity<ResolvedTenant>,
    account: &IntegrationAccount<ResolvedTenant>,
    payment: &OperationSpec,
) -> Workflow<ResolvedTenant> {
    let graph = finance_graph(agent, account, payment);
    let mut workflow = draft_finance(ann, graph);
    let reviewed = workflow.revision();
    workflow
        .publish(
            &managing(ann),
            reviewed,
            Replaces::Nothing,
            PublishFacts {
                offered: &[as_the_tenant_sees(payment)],
                events: &[],
                sees: &VisibleTo(&[]),
                runnable: &[],
            },
        )
        .unwrap();
    workflow
}

/// Configures the invoice agent's read purpose, one tool and bounded run.
fn invoice_check(agent: &AgentIdentity<ResolvedTenant>) -> AgentRunStep {
    AgentRunStep::new(AgentRunParams {
        agent_id: *agent.id(),
        provider_id: provider(),
        goal: GoalTemplate::new("find the late invoices").unwrap(),
        inputs: Mapping::new(vec![(
            field("invoices"),
            Source::Input(DataPath::parse("trigger").unwrap()),
        )])
        .unwrap(),
        purpose: IntentEnvelope::new([ActionClass::Read]),
        tools: vec![ToolName::new("search_invoices").unwrap()],
        approval_classes: vec![ActionClass::Write],
        max_steps: 10,
        spend_cap: Restriction::Unrestricted,
        ask_past: Restriction::Unrestricted,
        checks: Checks::Nothing,
    })
    .unwrap()
}

/// Selects the payment branch only when the agent's answer contains a late invoice.
fn late_invoice() -> ConditionRule {
    ConditionRule::new(
        Matching::All,
        vec![
            Clause::new(
                DataPath::parse(&format!("check.{ANSWER_FIELD}")).unwrap(),
                Test::Contains("late".to_owned()),
            )
            .unwrap(),
        ],
    )
    .unwrap()
}

/// Requires the financial approval before the bank call, within a one-hour decision window.
fn payment_approval() -> WorkflowApprovalStep {
    WorkflowApprovalStep::new(
        ApprovalAction::new("pay the late invoice").unwrap(),
        DeclaredAction::Declared(ActionClass::Financial),
        Lifetime::seconds(3600).unwrap(),
    )
    .unwrap()
}

/// Sends the agent's answer as the note through the connected bank account.
fn payment_step(
    account: &IntegrationAccount<ResolvedTenant>,
    payment: &OperationSpec,
) -> ActionStep {
    ActionStep::new(
        payment,
        ActionAccount::Account(*account.id()),
        Mapping::new(vec![(
            field("note"),
            Source::Input(DataPath::parse(&format!("check.{ANSWER_FIELD}")).unwrap()),
        )])
        .unwrap(),
    )
    .unwrap()
}

/// Orders invoice checking, the late branch, two approvals and the bank call.
fn finance_graph(
    agent: &AgentIdentity<ResolvedTenant>,
    account: &IntegrationAccount<ResolvedTenant>,
    payment: &OperationSpec,
) -> WorkflowGraph {
    let check = invoice_check(agent);
    let found_one = late_invoice();
    let sign_off = payment_approval();
    let pay = payment_step(account, payment);
    WorkflowGraph::new(
        vec![
            node("check", NodeKind::AgentRun(check)),
            node("found", NodeKind::Condition(found_one)),
            node("sign-off", NodeKind::Approval(sign_off)),
            node("pay", NodeKind::Action(pay)),
        ],
        vec![
            edge("check", Port::Next, "found"),
            edge("found", Port::WhenTrue, "sign-off"),
            edge("sign-off", Port::Next, "pay"),
        ],
    )
    .unwrap()
}

/// Creates Ann's manual finance draft with its one-day execution limit.
fn draft_finance(ann: &Human, graph: WorkflowGraph) -> Workflow<ResolvedTenant> {
    Workflow::create(
        CreateWorkflowParams {
            name: Label::new("name", "Late invoices").unwrap(),
            description: None,
            graph,
            layout: CanvasLayout::default(),
            trigger: Trigger::Manual,
            run_limit: RunLimit::new(Lifetime::seconds(86_400).unwrap()).unwrap(),
            failure_alert: FailureAlert::default(),
        },
        &managing(ann),
    )
    .unwrap()
}

/// `by` acting on agents while holding `system`.
fn agent_control<'a>(by: &'a Human, system: &[SystemPermission]) -> AgentControl<'a> {
    AgentControl::new(assumed_authority(by, TenantId::new(), system, &[]))
}

/// `by` with full control of workflows.
fn managing(by: &Human) -> WorkflowControl<'_> {
    WorkflowControl::new(assumed_authority(
        by,
        TenantId::new(),
        &[SystemPermission::Workflows(WorkflowAction::Manage)],
        &[],
    ))
}

/// Approves the sign-off step as `by`, having been shown the data it lets
/// through.
fn sign_off(execution: &mut Execution, by: &Human) -> Result<Vec<ExecutionRecord>, DomainError> {
    let shown = execution.approval_input(&key("sign-off"))?;
    let approver =
        StepApprover::assumed(managing(by), DataClassLevel::Restricted, Presence::Proven);
    execution.approve(&key("sign-off"), &approver, &shown)
}

/// `spec` as the finance team's tenant treats it: it raised nothing.
fn as_the_tenant_sees(spec: &OperationSpec) -> TenantOperation {
    TenantOperation::of::<ResolvedTenant>(spec.clone(), &[])
}

fn delegation_from(
    delegator: &Human,
    agent: &AgentIdentity<ResolvedTenant>,
) -> Delegation<ResolvedTenant> {
    Delegation::grant(
        GrantDelegationParams {
            granted: CapabilitySet::new(Vec::new(), Vec::new()),
            constraints: DelegationConstraints::new(Seconds::new(600), 1).unwrap(),
            name: None,
        },
        &HeldBy::worked_out::<ResolvedTenant>(
            &agent_control(delegator, &[]),
            &CapabilitySet::new(Vec::new(), Vec::new()),
            &HeldResources::answered(delegator.principal(), Vec::new()),
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

fn run_for(finance: &Finance, acting_for: &Human) -> Execution {
    let params = ManualStartParams {
        resources: HeldResources::answered(acting_for.principal(), held().resources().to_vec()),
        input: FlowData::text("the March invoices").unwrap(),
        exposure: DataClassLevel::Internal,
    };
    Execution::start_by_hand(&finance.workflow, managing(acting_for), params)
        .unwrap()
        .0
}

/// Starts the agent step under Ann's delegation and has the run answer.
fn agent_answers(
    finance: &Finance,
    execution: &mut Execution,
    answer: &str,
) -> (AgentRun<ResolvedTenant>, Vec<ExecutionRecord>) {
    let delegation = delegation_from(&finance.ann, &finance.agent);
    let started = execution
        .start_agent_run(
            &key("check"),
            &RunAuthority::Delegation(&delegation),
            &finance.agent,
            &holding(&finance.ann),
        )
        .unwrap();
    let AgentRunStart::Started(mut run, mut records) = started else {
        panic!("the agent step was refused");
    };
    run.complete(answer).unwrap();
    records.extend(execution.settle_agent_run(&key("check"), &run).unwrap());
    (*run, records)
}

fn pay(finance: &Finance, execution: &mut Execution) -> ActionStart {
    let clearance = ActionClearance::Account(
        finance
            .account
            .grant_use(
                &holding(execution.acting_for()),
                finance.payment.operation(),
                &holding(&finance.ann),
            )
            .unwrap(),
    );
    let acting = holding(execution.acting_for());
    execution
        .begin_action(
            &key("pay"),
            Offer::Current(&as_the_tenant_sees(&finance.payment)),
            &clearance,
            &acting,
        )
        .unwrap()
}

/// The whole way through: the agent works under Ann's delegation, its
/// answer chooses the branch, two colleagues approve, and only then is the
/// bank called, with the agent's answer as the note and Ann's account.
#[test]
fn an_agents_answer_leads_through_two_approvals_to_one_payment() {
    let finance = finance();
    let mut execution = run_for(&finance, &finance.ann);

    let (run, _) = agent_answers(&finance, &mut execution, "invoice 42 is late");
    execution.request_approval(&key("sign-off")).unwrap();
    sign_off(&mut execution, &person("bob@corp.test")).unwrap();
    let not_yet = execution.ready().count();
    sign_off(&mut execution, &person("cid@corp.test")).unwrap();
    let ActionStart::Call(call, _) = pay(&finance, &mut execution) else {
        panic!("the payment was not made");
    };
    execution
        .settle_action(
            &key("pay"),
            call.call_id,
            ActionOutcome::Succeeded {
                output: FlowData::text("paid").unwrap(),
                exposure: DataClassLevel::Confidential,
            },
        )
        .unwrap();

    assert_agent_authority(&run);
    assert_eq!(not_yet, 0);
    assert_payment(&finance, &call);
    assert_eq!(
        execution.status(),
        ExecutionStatus::Ended(ExecutionEnd::Succeeded)
    );
}

/// Checks the agent received only the workflow's tool, purpose, approvals and execution limits.
fn assert_agent_authority(run: &AgentRun<ResolvedTenant>) {
    assert_eq!(
        run.granted_tools(),
        &[ToolName::new("search_invoices").unwrap()]
    );
    assert!(matches!(run.delegation_id(), ActingUnder::Delegation(_)));
    assert_eq!(run.max_steps(), 10);
    assert_eq!(run.approval_classes(), &[ActionClass::Write]);
    assert_eq!(run.purpose(), &IntentEnvelope::new([ActionClass::Read]));
    assert_eq!(run.exposure(), DataClassLevel::Internal);
}

/// Checks the bank call retained Ann's account, financial classification and agent-supplied note.
fn assert_payment(finance: &Finance, call: &ActionCall) {
    assert_eq!(call.account, ActionAccount::Account(*finance.account.id()));
    assert_eq!(
        call.effect,
        DeclaredAction::Declared(ActionClass::Financial)
    );
    assert_eq!(
        call.arguments
            .at(&DataPath::parse("note").unwrap())
            .cloned(),
        Some(FlowData::text("invoice 42 is late").unwrap())
    );
}

/// When the agent finds nothing, the branch after it is skipped: nobody is
/// asked to approve and the bank is never called.
#[test]
fn an_agent_finding_nothing_skips_the_approval_and_the_payment() {
    let finance = finance();
    let mut execution = run_for(&finance, &finance.ann);

    agent_answers(&finance, &mut execution, "every invoice was paid on time");

    assert_eq!(execution.step(&key("sign-off")), Some(&StepState::Skipped));
    assert_eq!(execution.step(&key("pay")), Some(&StepState::Skipped));
    assert_eq!(
        execution.status(),
        ExecutionStatus::Ended(ExecutionEnd::Succeeded)
    );
}

/// The agent acts for the person the execution acts for: a delegation Bob
/// holds for the same agent does not back a run started for Ann.
#[test]
fn the_agent_acts_only_under_the_acting_persons_own_delegation() {
    let finance = finance();
    let mut execution = run_for(&finance, &finance.ann);
    let bobs = delegation_from(&person("bob@corp.test"), &finance.agent);

    let started = execution
        .start_agent_run(
            &key("check"),
            &RunAuthority::Delegation(&bobs),
            &finance.agent,
            &holding(&finance.ann),
        )
        .unwrap();

    assert!(matches!(started, AgentRunStart::Refused(_)));
    assert_eq!(
        execution.status(),
        ExecutionStatus::Ended(ExecutionEnd::Failed)
    );
    assert_eq!(execution.step(&key("pay")), Some(&StepState::Waiting));
}

/// An agent suspended after the workflow was published does not run in
/// it, and nothing after its step happens.
#[test]
fn a_suspended_agent_stops_the_workflow_before_anything_is_paid() {
    let mut finance = finance();
    let delegation = delegation_from(&finance.ann, &finance.agent);
    finance.agent.suspend(SuspendedBy::Monitor).unwrap();
    let mut execution = run_for(&finance, &finance.ann);

    let started = execution
        .start_agent_run(
            &key("check"),
            &RunAuthority::Delegation(&delegation),
            &finance.agent,
            &holding(&finance.ann),
        )
        .unwrap();

    assert!(matches!(started, AgentRunStart::Refused(_)));
    assert_eq!(execution.ready().count(), 0);
}

/// The agent's answer reaches the approvers, but it cannot approve for
/// them, and neither can Ann, for whom the workflow runs.
#[test]
fn nobody_the_workflow_acts_for_can_approve_its_payment() {
    let finance = finance();
    let mut execution = run_for(&finance, &finance.ann);
    agent_answers(&finance, &mut execution, "invoice 42 is late");
    execution.request_approval(&key("sign-off")).unwrap();
    let ann_elsewhere = Human::new(
        HumanAccount::User(UserId::new()),
        PersonKey::new("ann@corp.test").unwrap(),
    );

    let by_ann = sign_off(&mut execution, &ann_elsewhere);

    assert!(by_ann.is_err());
    assert_eq!(execution.ready().count(), 0);
}

/// Bob may start Ann's workflow by hand, but Ann's bank account is kept to
/// her: leave for her does not clear his payment, and he cannot get his
/// own.
#[test]
fn an_account_kept_to_its_owner_does_not_pay_for_another_persons_run() {
    let finance = finance();
    let bob = person("bob@corp.test");
    let mut execution = run_for(&finance, &bob);
    bob_finishes_check(&finance, &mut execution, &bob);
    execution.request_approval(&key("sign-off")).unwrap();
    sign_off(&mut execution, &person("dee@corp.test")).unwrap();
    sign_off(&mut execution, &person("cid@corp.test")).unwrap();
    let anns_leave = anns_bank_permission(&finance);

    let bobs_own = finance.account.grant_use(
        &holding(&bob),
        finance.payment.operation(),
        &holding(&finance.ann),
    );
    let started = execution
        .begin_action(
            &key("pay"),
            Offer::Current(&as_the_tenant_sees(&finance.payment)),
            &anns_leave,
            &holding(&bob),
        )
        .unwrap();

    assert!(bobs_own.is_err());
    assert!(matches!(started, ActionStart::Stopped(_)));
}

/// Obtains Ann's own bank permission before trying to use it for Bob's execution.
fn anns_bank_permission(finance: &Finance) -> ActionClearance<ResolvedTenant> {
    ActionClearance::Account(
        finance
            .account
            .grant_use(
                &holding(&finance.ann),
                finance.payment.operation(),
                &holding(&finance.ann),
            )
            .unwrap(),
    )
}

/// Completes Bob's agent step under his own delegation before colleagues approve the payment.
fn bob_finishes_check(finance: &Finance, execution: &mut Execution, bob: &Human) {
    let delegation = delegation_from(bob, &finance.agent);
    let AgentRunStart::Started(mut run, _) = execution
        .start_agent_run(
            &key("check"),
            &RunAuthority::Delegation(&delegation),
            &finance.agent,
            &holding(bob),
        )
        .unwrap()
    else {
        panic!("Bob's agent step was refused");
    };
    run.complete("invoice 42 is late").unwrap();
    execution.settle_agent_run(&key("check"), &run).unwrap();
}

/// Every step of a run reaches the audit trail, in order.
#[test]
fn a_whole_run_is_audited_step_by_step() {
    let finance = finance();
    let mut execution = run_for(&finance, &finance.ann);

    let (_, records) = agent_answers(&finance, &mut execution, "every invoice was paid on time");
    let events = execution_events(TenantId::new(), &execution, records);

    let kinds: Vec<EventType> = events.iter().map(DomainEvent::event_type).collect();
    assert_eq!(
        kinds,
        vec![
            EventType::from(WorkflowsEvent::StepStarted),
            WorkflowsEvent::StepSucceeded.into(),
            WorkflowsEvent::StepSucceeded.into(),
            WorkflowsEvent::StepSkipped.into(),
            WorkflowsEvent::StepSkipped.into(),
            WorkflowsEvent::ExecutionEnded.into(),
        ]
    );
}

/// The agent run's records name the step it belongs to, so the audit
/// trail says which step each agent ran in.
#[test]
fn the_agent_steps_records_name_its_step() {
    let finance = finance();
    let mut execution = run_for(&finance, &finance.ann);

    let (_, records) = agent_answers(&finance, &mut execution, "invoice 42 is late");

    assert!(matches!(
        records.first(),
        Some(ExecutionRecord::Step {
            key: step,
            happened: StepRecord::Started,
        }) if *step == key("check")
    ));
}
