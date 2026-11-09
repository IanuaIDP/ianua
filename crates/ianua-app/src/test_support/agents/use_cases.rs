//! What the agent use cases' tests share beyond the stores: the person the
//! test caller acts as, and agents they or someone else own.

use std::sync::Arc;

use ianua_domain::domains::agents::authority::capability::{
    CapabilitySet, DelegationConstraints, Relation, ResourceCapability, ResourceRef,
};
use ianua_domain::domains::agents::authority::delegation::{
    Delegation, DelegationRenewal, DelegationRow, DelegationStatus, Lineage,
};
use ianua_domain::domains::agents::authority::intent::IntentEnvelope;
use ianua_domain::domains::agents::execution::model_provider::{
    LastTest, ModelEndpoint, ModelName, ModelProvider, ModelProviderKind, ModelProviderRow,
    ModelProviderStatus, ProviderEmbeddings, ProviderKey,
};
use ianua_domain::domains::agents::execution::run::{
    AgentRun, ResolvedCall, RunGoal, RunStarter, StartRunParams, ToolCall,
};
use ianua_domain::domains::agents::execution::tool::{
    AgentTool, AgentToolRow, PathValue, PathValues, ToolDescription, ToolMethod, ToolName,
    ToolPath, ToolSchema, ToolStatus,
};
use ianua_domain::domains::agents::execution::usage::ModelPricing;
use ianua_domain::domains::agents::identity::agent::{
    AgentIdentity, AgentIdentityRow, AgentProof, Containment, OwnershipOffer,
};
use ianua_domain::domains::agents::identity::attestation::{
    AttestationMethod, AttestationPolicy, AttestedOrigin,
};
use ianua_domain::domains::agents::identity::credential::{
    AgentCredential, AgentCredentialRow, CredentialOrigin,
};
use ianua_domain::domains::agents::identity::status::AgentStatus;
use ianua_domain::domains::agents::oversight::approval::{
    ActionParties, ApprovalAction, ApprovalOrigin, ApprovalRequest, RequestApprovalParams,
    RunOrigin,
};
use ianua_domain::domains::authorization::authority::TenantAuthority;
use ianua_domain::domains::crypto::key_status::KeyState;
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::clock;
use ianua_domain::shared::events::chain::EventOrigin;
use ianua_domain::shared::model::restriction::Restriction;
use ianua_domain::types::{
    ActionClass, AgentCredentialId, AgentId, AgentToolId, DeclaredAction, DelegationId, Human,
    HumanAccount, KeyId, Label, ModelProviderId, PersonKey, PrincipalRef, RouteId, Seconds, UserId,
};

use crate::acting::agent::AgentActingPorts;
use crate::context::{AgentAssertion, CallerIdentity};
use crate::ports::agents::{AgentCredentialStore, AgentStore};
use crate::test_support::agents::{
    FakeAgentCredentialStore, FakeAgentStore, FakeAssertionVerifier, FakeReplayGuard, enrolled_key,
};
use crate::test_support::{block_on, test_ctx};
use crate::use_cases::agents::approvals::{DenyActionPorts, DenyActionUseCase};
use crate::use_cases::agents::delegation::{DescribeDelegations, DescribeDelegationsPorts};
use crate::use_cases::agents::runs::StepLimits;

/// The address the fake authorities sign every test caller in with.
const CALLER_ADDRESS: &str = "caller@example.test";

/// The person [`test_ctx`] acts as when the fake authorities answer for it.
///
/// # Panics
///
/// - Never: the test caller is a tenant user with a valid address.
#[must_use]
pub fn caller_person() -> Human {
    let caller = test_ctx();
    let CallerIdentity::TenantUser(user) = caller.identity() else {
        panic!("the test caller is a tenant user");
    };
    Human::new(
        HumanAccount::User(*user),
        PersonKey::new(CALLER_ADDRESS).expect("the caller address is valid"),
    )
}

/// A store holding one active agent with `id`, owned by the test caller.
#[must_use]
pub fn callers_agent(id: AgentId) -> FakeAgentStore {
    let store = FakeAgentStore::empty();
    store.add_owned_by(id, caller_person());
    store
}

/// The key id of the credential [`signing_in`] enrols.
const SIGNING_KID: &str = "agent-key";

/// What lets `agent`, kept in `agents`, sign in as itself: an active key
/// enrolled for it, a verifier accepting its assertions and a guard that
/// has seen none before, with an assertion to present.
///
/// # Panics
///
/// - Never: the key id and credential row are valid.
#[must_use]
pub fn signing_in(
    agents: Arc<dyn AgentStore>,
    agent: AgentId,
) -> (AgentActingPorts, AgentAssertion) {
    let credentials = FakeAgentCredentialStore::empty();
    block_on(credentials.save(&test_ctx().tenant(), &signing_key_of(agent)))
        .expect("the fake store keeps every credential");
    let ports = AgentActingPorts {
        agent_store: agents,
        credential_store: Arc::new(credentials),
        verifier: Arc::new(FakeAssertionVerifier::accepting(SIGNING_KID, agent)),
        replay_guard: Arc::new(FakeReplayGuard),
    };
    let assertion = AgentAssertion {
        agent_id: agent,
        assertion: "signed.assertion".to_owned(),
    };
    (ports, assertion)
}

/// The stored row of an active agent with `id`, owned by `owner`, proving
/// itself with an enrolled key. A test changes the fields it is about and
/// reconstitutes it.
///
/// # Panics
///
/// - Never: the name is a valid label.
#[must_use]
pub fn agent_row(id: AgentId, owner: Human) -> AgentIdentityRow {
    let now = clock::now();
    AgentIdentityRow {
        id,
        name: Label::new("agent_name", "ledger-bot").expect("the test name is valid"),
        description: None,
        owner,
        offer: OwnershipOffer::Unoffered,
        status: AgentStatus::Active,
        proof: AgentProof::EnrolledKey,
        containment: Containment::Free,
        last_attested_at: None,
        created_at: now,
        updated_at: now,
    }
}

/// The stored row of an active key with `kid`, enrolled by hand for
/// `agent` a moment ago and living a day. A test changes the fields it is
/// about and reconstitutes it.
///
/// # Panics
///
/// - Never: the test key ids are valid.
#[must_use]
pub fn key_row(agent: AgentId, kid: &str) -> AgentCredentialRow {
    let now = clock::now();
    let key = enrolled_key();
    AgentCredentialRow {
        id: AgentCredentialId::new(),
        agent_id: agent,
        kid: KeyId::new(kid).expect("the test key id is valid"),
        algorithm: key.algorithm,
        public_key: key.public_key,
        state: KeyState::Active,
        created_at: now,
        expires_at: now + time::Duration::days(1),
        origin: CredentialOrigin::Enrolled,
        updated_at: now,
    }
}

/// An active key enrolled for `agent`, as storage would read it back.
fn signing_key_of(agent: AgentId) -> AgentCredential<ResolvedTenant> {
    let now = clock::now();
    let key = enrolled_key();
    AgentCredential::reconstitute(AgentCredentialRow {
        id: AgentCredentialId::new(),
        agent_id: agent,
        kid: KeyId::new(SIGNING_KID).expect("the test key id is valid"),
        algorithm: key.algorithm,
        public_key: key.public_key,
        state: KeyState::Active,
        created_at: now,
        expires_at: now + time::Duration::days(1),
        origin: CredentialOrigin::Enrolled,
        updated_at: now,
    })
    .expect("a key enrolled just now is a consistent row")
}

impl crate::test_support::Fake for Arc<DescribeDelegations> {
    fn fake() -> Self {
        Arc::new(DescribeDelegations::new(DescribeDelegationsPorts::fakes()))
    }
}

/// How many steps runs get in tests: eight when they ask for none, twenty
/// at most.
#[must_use]
pub fn step_limits() -> StepLimits {
    StepLimits {
        default: 8,
        max: 20,
    }
}

/// A person other than the test caller, signing in with `address` through
/// an account of their own.
///
/// # Panics
///
/// - When `address` is not a valid address.
#[must_use]
pub fn someone(address: &str) -> Human {
    Human::new(
        HumanAccount::User(UserId::new()),
        PersonKey::new(address).expect("the test address is valid"),
    )
}

/// An active agent with `id`, owned by `owner`, as storage would read it
/// back.
///
/// # Panics
///
/// - Never: [`agent_row`] is a consistent row.
#[must_use]
pub fn agent_owned_by(id: AgentId, owner: Human) -> AgentIdentity<ResolvedTenant> {
    AgentIdentity::reconstitute(agent_row(id, owner)).expect("the test agent row is consistent")
}

/// The stored row of a delegation `delegator` granted `agent` a moment
/// ago: nothing but itself, for ten minutes, passed on at most one level.
/// A test changes the fields it is about and reconstitutes it.
///
/// # Panics
///
/// - Never: ten minutes and one level are within bounds.
#[must_use]
pub fn delegation_row(agent: AgentId, delegator: PrincipalRef) -> DelegationRow {
    let now = clock::now();
    let lifetime = Seconds::new(600);
    DelegationRow {
        id: DelegationId::new(),
        delegator,
        delegate: agent,
        granted: CapabilitySet::empty(),
        constraints: DelegationConstraints::new(lifetime, 1)
            .expect("ten minutes and one level are within bounds"),
        lineage: Lineage::Root,
        depth: 0,
        status: DelegationStatus::Active,
        issued_at: now,
        expires_at: now + lifetime.duration(),
        renewed: DelegationRenewal::NotRenewed,
        updated_at: now,
        name: None,
    }
}

/// A live delegation `delegator` granted `agent`, as storage would read it
/// back.
///
/// # Panics
///
/// - Never: [`delegation_row`] is a consistent row.
#[must_use]
pub fn delegation_from(delegator: &Human, agent: AgentId) -> Delegation<ResolvedTenant> {
    Delegation::reconstitute(delegation_row(agent, delegator.principal()))
        .expect("a fresh root grant is a consistent row")
}

/// The order tools a paused run is given: `update_order` posts to
/// `/orders/{id}`, a write, and `delete_order` deletes there, high risk.
const ORDER_TOOLS: [&str; 2] = ["update_order", "delete_order"];

/// A run `starter` started of `agent` under `delegation`, given the order
/// tools and asked to have its writes and deletes approved.
///
/// # Panics
///
/// - When `delegation` is not `starter`'s live delegation to `agent`.
#[must_use]
pub fn run_started_by(
    starter: &Human,
    agent: &AgentIdentity<ResolvedTenant>,
    delegation: &Delegation<ResolvedTenant>,
) -> AgentRun<ResolvedTenant> {
    let authority = TenantAuthority::assumed(starter.clone(), test_ctx().tenant_id(), &[], &[]);
    let params = StartRunParams {
        provider_id: ModelProviderId::new(),
        goal: RunGoal::new("tidy order 1").expect("the goal is valid"),
        purpose: IntentEnvelope::new([ActionClass::Read, ActionClass::Write, ActionClass::Delete]),
        granted_tools: ORDER_TOOLS
            .map(|name| ToolName::new(name).expect("the tool name is valid"))
            .to_vec(),
        approval_classes: vec![ActionClass::Write, ActionClass::Delete],
        max_steps: 5,
        spend_limit: Restriction::Unrestricted,
        ask_past: Restriction::Unrestricted,
        exposure: DataClassLevel::Public,
        origin: EventOrigin::Outside,
    };
    AgentRun::start(RunStarter::person(&authority), params, delegation, agent)
        .expect("the starter's own delegation backs the run")
}

/// The order tool `name`, one of `update_order` (a write) and
/// `delete_order` (a delete), on `/orders/{id}` over public data.
///
/// # Panics
///
/// - When `name` is neither.
#[must_use]
pub fn order_tool(name: &str) -> AgentTool<ResolvedTenant> {
    let method = match name {
        "update_order" => ToolMethod::Post,
        "delete_order" => ToolMethod::Delete,
        other => panic!("{other} is not an order tool"),
    };
    tool_at(name, method, "/orders/{id}", DataClassLevel::Public)
}

/// [`run_started_by`], paused on calling `tool` for order 1 until a person
/// decides.
///
/// # Panics
///
/// - When `delegation` is not `starter`'s live delegation to `agent`, or
///   `tool` is not an [`order_tool`].
#[must_use]
pub fn paused_run(
    starter: &Human,
    agent: &AgentIdentity<ResolvedTenant>,
    delegation: &Delegation<ResolvedTenant>,
    tool: &AgentTool<ResolvedTenant>,
) -> AgentRun<ResolvedTenant> {
    let mut run = run_started_by(starter, agent, delegation);
    let values = PathValues::new().with("id", PathValue::new("1").expect("the value is valid"));
    let call = ToolCall::new(tool.name().as_str(), "{\"id\":1}").expect("the call is valid");
    let resolved =
        ResolvedCall::resolve(call, tool, &values).expect("the call reaches the tool's path");
    run.await_approval(resolved, agent)
        .expect("a running run pauses on a call it must have approved");
    run
}

/// The approval request `run`, paused on `tool` and started by `starter`,
/// raised for the call it holds, with `agent`'s owner and `starter` behind
/// it.
///
/// # Panics
///
/// - When `run` is not paused.
#[must_use]
pub fn raised_approval(
    run: &AgentRun<ResolvedTenant>,
    agent: &AgentIdentity<ResolvedTenant>,
    starter: &Human,
    tool: &AgentTool<ResolvedTenant>,
) -> ApprovalRequest<ResolvedTenant> {
    let origin = RunOrigin::of(run).expect("the run is paused");
    let class = origin.class();
    ApprovalRequest::request(RequestApprovalParams {
        agent_id: *run.agent_id(),
        delegation_id: *run.delegation_id(),
        origin: ApprovalOrigin::Run(origin),
        parties: ActionParties::from_stored(agent.owner().clone(), vec![starter.clone()]),
        action_class: DeclaredAction::Declared(class),
        action: ApprovalAction::for_call(tool.method().into(), "/orders/1")
            .expect("the action is valid"),
        ttl_seconds: Seconds::new(900),
    })
    .expect("a paused run raises a request for the call it holds")
}

impl crate::test_support::Fake for Arc<DenyActionUseCase> {
    fn fake() -> Self {
        Arc::new(DenyActionUseCase::new(DenyActionPorts::fakes()))
    }
}

/// An active tool `name` calling `method` on `path`, cleared for
/// `clearance`, as storage would read it back.
///
/// # Panics
///
/// - When `name` or `path` is not valid.
#[must_use]
pub fn tool_at(
    name: &str,
    method: ToolMethod,
    path: &str,
    clearance: DataClassLevel,
) -> AgentTool<ResolvedTenant> {
    let now = clock::now();
    AgentTool::reconstitute(AgentToolRow {
        id: AgentToolId::new(),
        name: ToolName::new(name).expect("the tool name is valid"),
        description: ToolDescription::new("a tool").expect("the description is valid"),
        schema: ToolSchema::new(r#"{"type":"object"}"#).expect("the schema is valid"),
        method,
        path: ToolPath::new(path).expect("the path is valid"),
        route_id: RouteId::new(),
        declared_action: DeclaredAction::Undeclared,
        action_class: ActionClass::for_route(method.into(), path, DeclaredAction::Undeclared),
        classification: clearance,
        status: ToolStatus::Active,
        created_at: now,
        updated_at: now,
    })
    .expect("a tool registered just now is a consistent row")
}

/// An active, keyless self-hosted model provider cleared for `clearance`,
/// as storage would read it back.
///
/// # Panics
///
/// - Never: every part of the row is valid.
#[must_use]
pub fn provider_cleared_for(clearance: DataClassLevel) -> ModelProvider<ResolvedTenant> {
    let now = clock::now();
    ModelProvider::reconstitute(ModelProviderRow {
        id: ModelProviderId::new(),
        name: Label::new("name", "prod").expect("the provider name is valid"),
        kind: ModelProviderKind::SelfHosted,
        endpoint: ModelEndpoint::new("http://m.svc:8000/v1").expect("the endpoint is valid"),
        model: ModelName::new("deepseek-chat").expect("the model name is valid"),
        pricing: ModelPricing::Unpriced,
        credential_ref: ProviderKey::Keyless,
        clearance,
        embeddings: ProviderEmbeddings::Off,
        status: ModelProviderStatus::Active,
        last_test: LastTest::NotYet,
        created_at: now,
        updated_at: now,
    })
    .expect("a provider connected just now is a consistent row")
}

/// A run of `agent` started by `starter` as `params` asks: under
/// `delegation` when there is one, and calling no tool otherwise.
///
/// # Panics
///
/// - When the domain refuses to start the run.
#[must_use]
pub fn run_by(
    starter: &Human,
    agent: &AgentIdentity<ResolvedTenant>,
    delegation: Option<&Delegation<ResolvedTenant>>,
    params: StartRunParams,
) -> AgentRun<ResolvedTenant> {
    let authority = TenantAuthority::assumed(starter.clone(), test_ctx().tenant_id(), &[], &[]);
    let starter = RunStarter::person(&authority);
    let started = match delegation {
        Some(delegation) => AgentRun::start(starter, params, delegation, agent),
        None => AgentRun::start_without_tools(starter, params, agent),
    };
    started.expect("the test starts a run the domain accepts")
}

/// A SPIFFE attestation policy trusting `spiffe://cluster`, for an hour.
///
/// # Panics
///
/// - Never: the policy is well formed.
#[must_use]
pub fn spiffe_policy() -> AttestationPolicy {
    AttestationPolicy::new(
        vec![AttestationMethod::Spiffe],
        Seconds::new(3600),
        vec![AttestedOrigin::new("spiffe://cluster").expect("the origin is valid")],
    )
    .expect("the policy is valid")
}

/// The capability `relation` on `object`.
///
/// # Panics
///
/// - When either is not valid.
#[must_use]
pub fn resource_cap(relation: &str, object: &str) -> ResourceCapability {
    ResourceCapability::new(
        Relation::new(relation).expect("the relation is valid"),
        ResourceRef::new(object).expect("the object is valid"),
    )
}
