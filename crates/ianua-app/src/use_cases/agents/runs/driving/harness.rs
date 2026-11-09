//! The world the run tests share: a scripted model, seeded stores, runs the
//! test caller started, and a worker driving them over one set of ports.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::agents::authority::capability::{
    Relation, ResourceCapability, ResourceRef,
};
use ianua_domain::domains::agents::authority::delegation::Delegation;
use ianua_domain::domains::agents::authority::intent::IntentEnvelope;
use ianua_domain::domains::agents::execution::chat::{
    AnswerEnd, ChatMessage, Completion, CompletionRequest,
};
use ianua_domain::domains::agents::execution::run::{AgentRun, RunGoal, StartRunParams};
use ianua_domain::domains::agents::execution::tool::{AgentTool, ToolMethod, ToolName};
use ianua_domain::domains::agents::execution::usage::ModelUsage;
use ianua_domain::domains::agents::identity::agent::AgentIdentity;
use ianua_domain::domains::agents::oversight::approval::ApprovalRequest;
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::events::chain::EventOrigin;
use ianua_domain::shared::model::restriction::Restriction;
use ianua_domain::types::{ActionClass, AgentId, AgentRunId, ModelProviderId, PrincipalRef};

use crate::context::CallerIdentity;
use crate::error::AppError;
use crate::ports::TenantScoped;
use crate::ports::agents::{
    AgentStore, ApprovalStore, DelegationStore, ModelClient, ModelFailure, ModelProviderStore,
    ModelTarget, RelationshipResolver, RunStore, ToolStore,
};
use crate::services::account_now::{AccountsNow, AccountsNowPorts};
use crate::tenancy::ScopedTenant;
use crate::test_support::agents::{
    FakeAgentStore, FakeApprovalStore, FakeDelegationStore, FakeModelProviderStore, FakeRunControl,
    FakeRunStore, FakeTaskTokenIssuer, FakeToolStore, RecordingToolInvoker, agent_owned_by,
    caller_person, delegation_from, provider_cleared_for, run_by, tool_at,
};
use crate::test_support::authorization::FakeAccessRecordStore;
use crate::test_support::identity::FakeUserStore;
use crate::test_support::{
    FakeAuditLabelResolver, FakeEventDispatcher, RecordingUnitOfWork, block_on, test_auditor,
    test_ctx,
};
use crate::use_case::Command as _;
use crate::use_cases::agents::runs::{DrivePorts, DriveUseCase, RunCalls, RunPeople, RunStores};

/// The messages the model was shown, one conversation per completion.
pub(in crate::use_cases::agents::runs) type Transcript = Arc<Mutex<Vec<Vec<ChatMessage>>>>;

/// What happens while the model answers, such as a person pressing stop.
pub(in crate::use_cases::agents::runs) type DuringCall = Box<dyn Fn() + Send + Sync>;

/// How a scripted model's answers end.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Answering {
    /// Each answer is finished.
    Finishing,
    /// Each answer is cut off at the cap.
    CuttingOff,
    /// The provider bills each call, and the model declines to answer.
    Declining,
}

/// A model that answers with the replies a test scripted, in order, and
/// "done" once they run out.
pub(in crate::use_cases::agents::runs) struct ScriptedModel {
    replies: Mutex<VecDeque<String>>,
    seen: Transcript,
    during_call: Option<DuringCall>,
    usage: ModelUsage,
    answering: Answering,
}

impl ScriptedModel {
    /// A model answering `replies` in order, reporting no usage.
    pub(in crate::use_cases::agents::runs) fn new(replies: &[&str]) -> Self {
        Self {
            replies: Mutex::new(replies.iter().map(|s| (*s).to_owned()).collect()),
            seen: Transcript::default(),
            during_call: None,
            usage: ModelUsage::Unreported,
            answering: Answering::Finishing,
        }
    }

    /// The same model, every answer cut off at the cap.
    pub(in crate::use_cases::agents::runs) fn cut_off(mut self) -> Self {
        self.answering = Answering::CuttingOff;
        self
    }

    /// The same model, declining every call its provider bills.
    pub(in crate::use_cases::agents::runs) fn declining(mut self) -> Self {
        self.answering = Answering::Declining;
        self
    }

    /// The same model, doing `during` each time it is asked.
    pub(in crate::use_cases::agents::runs) fn while_answering(
        mut self,
        during: DuringCall,
    ) -> Self {
        self.during_call = Some(during);
        self
    }

    /// The same model, reporting `usage` with every answer.
    pub(in crate::use_cases::agents::runs) fn reporting(mut self, usage: ModelUsage) -> Self {
        self.usage = usage;
        self
    }

    /// What it was shown, as it is shown.
    pub(in crate::use_cases::agents::runs) fn transcript(&self) -> Transcript {
        self.seen.clone()
    }
}

#[async_trait]
impl ModelClient for ScriptedModel {
    async fn complete(
        &self,
        _: &ModelTarget,
        request: &CompletionRequest,
    ) -> Result<Completion, ModelFailure> {
        self.seen.lock().unwrap().push(request.messages.clone());
        if let Some(during) = &self.during_call {
            during();
        }
        let content = self
            .replies
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_else(|| "done".to_owned());
        let ended = match self.answering {
            Answering::Finishing => AnswerEnd::Finished,
            Answering::CuttingOff => AnswerEnd::CutOff,
            Answering::Declining => {
                return Err(ModelFailure::billed(
                    self.usage,
                    DomainError::infra_msg("the model declined to answer"),
                ));
            }
        };
        Ok(Completion {
            content,
            usage: self.usage,
            ended,
        })
    }
}

/// A relationship graph that gives everyone use of everything asked about.
pub(in crate::use_cases::agents::runs) struct HoldsUseOfEverything;

impl TenantScoped for HoldsUseOfEverything {}

#[async_trait]
impl RelationshipResolver for HoldsUseOfEverything {
    async fn check(
        &self,
        _: &ScopedTenant,
        _: &PrincipalRef,
        _: &Relation,
        _: &ResourceRef,
    ) -> Result<bool, DomainError> {
        Ok(true)
    }

    async fn held_subset(
        &self,
        _: &ScopedTenant,
        _: &PrincipalRef,
        wanted: &[ResourceCapability],
    ) -> Result<Vec<ResourceCapability>, DomainError> {
        Ok(wanted.to_vec())
    }
}

/// Whether a run acts under a delegation of the test caller's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::use_cases::agents::runs) enum Delegated {
    /// It does, and may call the tools it is given.
    Yes,
    /// It acts under none, and may call no tool.
    No,
}

/// A run the test caller started, with its agent.
pub(in crate::use_cases::agents::runs) struct Started {
    /// The execution to advance through the test harness.
    pub(in crate::use_cases::agents::runs) run: AgentRunId,
    /// The identity used to authorize the test execution.
    pub(in crate::use_cases::agents::runs) agent: AgentIdentity<ResolvedTenant>,
    /// Its delegation, when it has one.
    pub(in crate::use_cases::agents::runs) delegation: Option<Delegation<ResolvedTenant>>,
}

/// Everything a driven run touches, kept in memory.
pub(in crate::use_cases::agents::runs) struct Harness {
    pub(in crate::use_cases::agents::runs) providers: Arc<FakeModelProviderStore>,
    pub(in crate::use_cases::agents::runs) tools: Arc<FakeToolStore>,
    pub(in crate::use_cases::agents::runs) runs: Arc<FakeRunStore>,
    pub(in crate::use_cases::agents::runs) agents: Arc<FakeAgentStore>,
    pub(in crate::use_cases::agents::runs) delegations: Arc<FakeDelegationStore>,
    pub(in crate::use_cases::agents::runs) approvals: Arc<FakeApprovalStore>,
    pub(in crate::use_cases::agents::runs) invoker: Arc<RecordingToolInvoker>,
    pub(in crate::use_cases::agents::runs) control: Arc<FakeRunControl>,
    pub(in crate::use_cases::agents::runs) unit: Arc<RecordingUnitOfWork>,
    pub(in crate::use_cases::agents::runs) users: Arc<FakeUserStore>,
    pub(in crate::use_cases::agents::runs) graph: Arc<dyn RelationshipResolver>,
    pub(in crate::use_cases::agents::runs) access: Arc<FakeAccessRecordStore>,
    pub(in crate::use_cases::agents::runs) provider: ModelProviderId,
    pub(in crate::use_cases::agents::runs) events: Arc<FakeEventDispatcher>,
}

/// A world whose tools all answer `reply`, with a provider cleared for
/// restricted data and the test caller stored as a user.
pub(in crate::use_cases::agents::runs) fn harness(reply: &str) -> Harness {
    let providers = Arc::new(FakeModelProviderStore::empty());
    let provider = provider_cleared_for(DataClassLevel::Restricted);
    block_on(providers.save(&tenant(), &provider)).unwrap();
    Harness {
        provider: *provider.id(),
        providers,
        tools: Arc::new(FakeToolStore::empty()),
        runs: Arc::new(FakeRunStore::empty()),
        agents: Arc::new(FakeAgentStore::empty()),
        delegations: Arc::new(FakeDelegationStore::empty()),
        approvals: Arc::new(FakeApprovalStore::empty()),
        invoker: Arc::new(RecordingToolInvoker {
            reply: reply.to_owned(),
            ..Default::default()
        }),
        control: Arc::new(FakeRunControl::empty()),
        unit: Arc::new(RecordingUnitOfWork::default()),
        users: Arc::new(caller_as_user()),
        graph: Arc::new(HoldsUseOfEverything),
        access: Arc::new(FakeAccessRecordStore::empty()),
        events: Arc::new(FakeEventDispatcher::new()),
    }
}

/// The test tenant.
pub(in crate::use_cases::agents::runs) fn tenant() -> ScopedTenant {
    test_ctx().tenant()
}

/// A user store holding the test caller.
fn caller_as_user() -> FakeUserStore {
    let caller = test_ctx();
    let CallerIdentity::TenantUser(user) = caller.identity() else {
        return FakeUserStore::empty();
    };
    FakeUserStore::with_user(*user, "caller@example.test")
}

impl Harness {
    /// The ports a worker drives runs over, reasoning with `model`.
    pub(in crate::use_cases::agents::runs) fn ports(&self, model: ScriptedModel) -> DrivePorts {
        DrivePorts {
            stores: self.stores(),
            people: RunPeople {
                accounts_now: Arc::new(AccountsNow::new(AccountsNowPorts {
                    access_records: self.access.clone(),
                    users: self.users.clone(),
                    relationships: self.graph.clone(),
                    ..AccountsNowPorts::fakes()
                })),
                user_store: self.users.clone(),
                ..RunPeople::fakes()
            },
            calls: RunCalls {
                task_token_issuer: Arc::new(FakeTaskTokenIssuer),
                model_client: Arc::new(model),
                tool_invoker: self.invoker.clone(),
                ..RunCalls::fakes()
            },
            run_cancellation: self.control.clone(),
            run_lease: self.control.clone(),
            audit_label_resolver: Arc::new(FakeAuditLabelResolver::new()),
            unit_of_work: self.unit.clone(),
            ..DrivePorts::fakes()
        }
    }

    /// The worker reads and persists run state through the harness's shared stores.
    fn stores(&self) -> RunStores {
        RunStores {
            run_store: self.runs.clone(),
            agent_store: self.agents.clone(),
            delegation_store: self.delegations.clone(),
            tool_store: self.tools.clone(),
            provider_store: self.providers.clone(),
            approval_store: self.approvals.clone(),
        }
    }

    /// Registers `name`, calling `method` on `path`, for internal data.
    pub(in crate::use_cases::agents::runs) fn tool(
        &self,
        name: &str,
        method: ToolMethod,
        path: &str,
    ) {
        self.register_classified_tool(name, method, path, DataClassLevel::Internal);
    }

    /// Registers `name`, calling `method` on `path`, cleared for
    /// `clearance`.
    pub(in crate::use_cases::agents::runs) fn register_classified_tool(
        &self,
        name: &str,
        method: ToolMethod,
        path: &str,
        clearance: DataClassLevel,
    ) {
        self.save_tool(&tool_at(name, method, path, clearance));
    }

    /// Keeps `tool` as registered.
    pub(in crate::use_cases::agents::runs) fn save_tool(&self, tool: &AgentTool<ResolvedTenant>) {
        block_on(self.tools.save(&tenant(), tool)).unwrap();
    }

    /// The names of every tool registered so far.
    pub(in crate::use_cases::agents::runs) fn tool_names(&self) -> Vec<ToolName> {
        self.tools
            .all()
            .iter()
            .map(|tool| tool.name().clone())
            .collect()
    }

    /// What a run asks for: its goal, `purpose`, every registered tool,
    /// `max_steps`, and approval for deletes.
    pub(in crate::use_cases::agents::runs) fn plan(
        &self,
        purpose: &[ActionClass],
        max_steps: u32,
    ) -> StartRunParams {
        StartRunParams {
            provider_id: self.provider,
            goal: RunGoal::new("do the thing").unwrap(),
            purpose: IntentEnvelope::new(purpose.iter().copied()),
            granted_tools: self.tool_names(),
            approval_classes: vec![ActionClass::Delete],
            max_steps,
            spend_limit: Restriction::Unrestricted,
            ask_past: Restriction::Unrestricted,
            exposure: DataClassLevel::Public,
            origin: EventOrigin::Outside,
        }
    }

    /// A run the test caller started of an agent of theirs, as `params`
    /// asks, under a delegation of theirs when `delegated` says so.
    pub(in crate::use_cases::agents::runs) fn start(
        &self,
        params: StartRunParams,
        delegated: Delegated,
    ) -> Started {
        let agent = agent_owned_by(AgentId::new(), caller_person());
        block_on(self.agents.save(&tenant(), &agent)).unwrap();
        let delegation = self.delegation_for(&agent, delegated);
        let run = run_by(&caller_person(), &agent, delegation.as_ref(), params);
        self.save_run(&run);
        Started {
            run: *run.id(),
            agent,
            delegation,
        }
    }

    /// The test caller's delegation to `agent`, kept, when `delegated`
    /// asks for one.
    fn delegation_for(
        &self,
        agent: &AgentIdentity<ResolvedTenant>,
        delegated: Delegated,
    ) -> Option<Delegation<ResolvedTenant>> {
        if delegated == Delegated::No {
            return None;
        }
        let delegation = delegation_from(&caller_person(), *agent.id());
        block_on(self.delegations.save(&tenant(), &delegation)).unwrap();
        Some(delegation)
    }

    /// Keeps `run` as it stands.
    pub(in crate::use_cases::agents::runs) fn save_run(&self, run: &AgentRun<ResolvedTenant>) {
        block_on(self.runs.save(&tenant(), run)).unwrap();
    }

    /// The run with `id`, as stored now.
    pub(in crate::use_cases::agents::runs) fn stored_run(
        &self,
        id: &AgentRunId,
    ) -> AgentRun<ResolvedTenant> {
        block_on(self.runs.find_by_id(&tenant(), id))
            .unwrap()
            .unwrap()
    }

    /// Drives the run with `id` once, reasoning with `model`.
    pub(in crate::use_cases::agents::runs) fn drive(
        &self,
        model: ScriptedModel,
        id: &AgentRunId,
    ) -> Result<(), AppError> {
        self.drive_with(self.ports(model), id)
    }

    /// Drives the run with `id` once over `ports`.
    pub(in crate::use_cases::agents::runs) fn drive_with(
        &self,
        ports: DrivePorts,
        id: &AgentRunId,
    ) -> Result<(), AppError> {
        let use_case = DriveUseCase::new(ports, time::Duration::days(1));
        let auditor = test_auditor(self.events.clone());
        block_on(use_case.execute(&tenant(), &auditor, *id))
    }

    /// Starts a run as `params` asks, drives it with `model`, and gives
    /// back how it was left.
    pub(in crate::use_cases::agents::runs) fn run(
        &self,
        model: ScriptedModel,
        params: StartRunParams,
    ) -> AgentRun<ResolvedTenant> {
        let started = self.start(params, Delegated::Yes);
        self.drive(model, &started.run).unwrap();
        self.stored_run(&started.run)
    }

    /// The approval requests raised for `agent`.
    pub(in crate::use_cases::agents::runs) fn raised(
        &self,
        agent: &AgentId,
    ) -> Vec<ApprovalRequest<ResolvedTenant>> {
        block_on(self.approvals.list_for_agent(&tenant(), agent, None)).unwrap()
    }

    /// The names of the events recorded so far, in order.
    pub(in crate::use_cases::agents::runs) fn recorded(&self) -> Vec<String> {
        self.events.records.lock().unwrap().clone()
    }

    /// The tools invoked so far, in order.
    pub(in crate::use_cases::agents::runs) fn invoked(&self) -> Vec<String> {
        self.invoker.calls.lock().unwrap().clone()
    }
}

/// The tool every order test reads with: `GET /orders/{id}`.
pub(in crate::use_cases::agents::runs) fn get_order(h: &Harness) {
    h.tool("get_order", ToolMethod::Get, "/orders/{id}");
}

/// A call to `tool` with `arguments`, as the model writes one.
pub(in crate::use_cases::agents::runs) fn call(tool: &str, arguments: &str) -> String {
    format!(r#"{{"tool": "{tool}", "arguments": {arguments}}}"#)
}
