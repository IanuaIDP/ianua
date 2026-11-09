//! Rows of the agent run, oversight and model stores: model providers,
//! tools, runs and their steps, review assignments and approval requests,
//! and the agents and routes they point at, saved through their stores.

use std::sync::Arc;

use ianua_app::ports::agents::RunStore;
use ianua_app::ports::identity::UserStore;
use ianua_app::ports::routing::{RouteStore, ServiceStore};
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::agents::authority::capability::ActionApproval;
use ianua_domain::domains::agents::authority::delegation::ActingUnder;
use ianua_domain::domains::agents::authority::intent::IntentEnvelope;
use ianua_domain::domains::agents::execution::model_provider::{
    LastTest, ModelEndpoint, ModelName, ModelProviderKind, ModelProviderRow, ModelProviderStatus,
    ProviderEmbeddings, ProviderKey,
};
use ianua_domain::domains::agents::execution::run::{
    AgentRun, AgentRunRow, NextCall, PendingCall, PendingCallRef, RunCheck, RunGoal, RunState,
    RunStep, SpendCheck, ToolCall,
};
use ianua_domain::domains::agents::execution::tool::{
    AgentToolRow, ToolDescription, ToolMethod, ToolName, ToolPath, ToolSchema, ToolStatus,
};
use ianua_domain::domains::agents::execution::usage::{ModelPricing, ModelTokens, Spend};
use ianua_domain::domains::agents::oversight::approval::{
    ActionParties, ApprovalAction, ApprovalRequestRow, ApprovalState, FirstOfTwo,
    StoredApprovalOrigin, StoredRunOrigin,
};
use ianua_domain::domains::agents::oversight::review::ReviewAssignmentRow;
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::domains::identity::account::user::User;
use ianua_domain::domains::routing::route::Route;
use ianua_domain::domains::routing::service::Service;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::config::DomainLimits;
use ianua_domain::shared::events::chain::EventOrigin;
use ianua_domain::shared::model::restriction::Restriction;
use ianua_domain::types::{
    ActionClass, AgentId, AgentRunId, AgentToolId, ApprovalId, DeclaredAction, DelegationId,
    Ending, HttpMethod, Human, Initiator, Label, ModelProviderId, PrincipalRef, ReviewAssignmentId,
    RouteId, SealedSecret, UserId,
};
use serde_json::json;

use crate::postgres::Databases;
use crate::postgres::agents::PgRunStore;
use crate::postgres::identity::PgUserStore;
use crate::postgres::routing::{PgRouteStore, PgServiceStore};
use crate::test_support::rows::agents::saved_agent;
use crate::test_support::rows::at;
use crate::test_support::rows::authorization::human;
use crate::test_support::rows::identity::user_row;
use crate::test_support::rows::routing::{route_row, service_row};

/// The path every test tool calls.
const TOOL_PATH: &str = "/api/orders/{id}";

/// A person of `tenant`, saved through the user store with an address of
/// their own.
///
/// # Panics
///
/// When the user cannot be saved, which is a broken test database.
pub async fn saved_person(databases: &Arc<Databases>, tenant: &ScopedTenant) -> Human {
    let address = format!("u{}@acme.example", UserId::new().as_uuid().simple());
    let user = User::reconstitute(user_row(&address)).expect("a valid user");
    PgUserStore::new(Arc::clone(databases), DomainLimits::default())
        .save(tenant, &user)
        .await
        .expect("the user is saved");
    human(*user.id(), &address)
}

/// An active agent of `tenant` with a name of its own, saved through its
/// store, as the rows that name an agent point at one the tenant keeps.
///
/// # Panics
///
/// When the agent cannot be saved, which is a broken test database.
pub async fn another_agent(databases: &Arc<Databases>, tenant: &ScopedTenant) -> AgentId {
    let name = format!("agent-{}", AgentId::new().as_uuid().simple());
    saved_agent(databases, tenant, &name).await
}

/// An active route of `tenant` to a service of its own, both saved through
/// their stores, for tools to call through.
///
/// # Panics
///
/// When either cannot be saved, which is a broken test database.
pub async fn saved_route(databases: &Arc<Databases>, tenant: &ScopedTenant) -> RouteId {
    let service: Service<ResolvedTenant> =
        Service::reconstitute(service_row("orders-api")).expect("a valid service");
    PgServiceStore::new(Arc::clone(databases))
        .save(tenant, &service)
        .await
        .expect("the service is saved");
    let route: Route<ResolvedTenant> =
        Route::reconstitute(route_row(*service.id(), "orders")).expect("a valid route");
    PgRouteStore::new(Arc::clone(databases))
        .save(tenant, &route)
        .await
        .expect("the route is saved");
    *route.id()
}

/// A run of a new agent of `tenant`, the agent and the run both saved
/// through their stores.
///
/// # Panics
///
/// When either cannot be saved, which is a broken test database.
pub async fn saved_run(
    databases: &Arc<Databases>,
    tenant: &ScopedTenant,
) -> AgentRun<ResolvedTenant> {
    let agent = another_agent(databases, tenant).await;
    let run = AgentRun::reconstitute(run_row(agent)).expect("a valid run");
    PgRunStore::new(Arc::clone(databases))
        .save(tenant, &run)
        .await
        .expect("the run is saved");
    run
}

/// An active OpenAI provider named `name`, priced, cleared for internal
/// data, with a sealed key, never tested.
///
/// # Panics
///
/// When `name` is not a valid label, which is a mistake in the test.
#[must_use]
pub fn provider_row(name: &str) -> ModelProviderRow {
    ModelProviderRow {
        id: ModelProviderId::new(),
        name: Label::new("name", name).expect("a valid name"),
        kind: ModelProviderKind::OpenAi,
        endpoint: ModelEndpoint::new("https://api.openai.com/v1").expect("a valid endpoint"),
        model: ModelName::new("gpt-4o-mini").expect("a valid model"),
        pricing: ModelPricing::PerMillionTokens {
            input: Spend::from_micros(3_000_000),
            output: Spend::from_micros(15_000_000),
        },
        credential_ref: ProviderKey::Sealed(
            SealedSecret::new("v1.c2VhbGVkLWtleQ").expect("a sealed form"),
        ),
        clearance: DataClassLevel::Internal,
        embeddings: ProviderEmbeddings::Off,
        status: ModelProviderStatus::Active,
        last_test: LastTest::NotYet,
        created_at: at(0),
        updated_at: at(0),
    }
}

/// An active tool named `name` reading `GET /api/orders/{id}` through
/// `route`, which declares no class and serves internal data.
///
/// # Panics
///
/// When `name` is not a valid tool name, which is a mistake in the test.
#[must_use]
pub fn tool_row(route: RouteId, name: &str) -> AgentToolRow {
    let method = ToolMethod::Get;
    AgentToolRow {
        id: AgentToolId::new(),
        name: ToolName::new(name).expect("a valid tool name"),
        description: ToolDescription::new("Reads one order").expect("a valid description"),
        schema: ToolSchema::new(r#"{"type":"object"}"#).expect("a valid schema"),
        method,
        path: ToolPath::new(TOOL_PATH).expect("a valid path"),
        route_id: route,
        declared_action: DeclaredAction::Undeclared,
        action_class: ActionClass::for_route(
            HttpMethod::from(method),
            TOOL_PATH,
            DeclaredAction::Undeclared,
        ),
        classification: DataClassLevel::Internal,
        status: ToolStatus::Active,
        created_at: at(0),
        updated_at: at(0),
    }
}

/// A running run of `agent` that has taken no step yet, started by Ann
/// outside any workflow at the fixed moment and last changed ten seconds
/// later, under no delegation, with a step limit and a spend limit, asking
/// a person past half of it.
///
/// # Panics
///
/// Never: every value is valid.
#[must_use]
pub fn run_row(agent: AgentId) -> AgentRunRow {
    AgentRunRow {
        id: AgentRunId::new(),
        agent_id: agent,
        provider_id: ModelProviderId::new(),
        goal: RunGoal::new("Total the open orders").expect("a valid goal"),
        purpose: IntentEnvelope::new([ActionClass::Read, ActionClass::Delete]),
        granted_tools: vec![ToolName::new("get_order").expect("a valid tool name")],
        approval_classes: vec![ActionClass::Delete],
        approval: ActionApproval::NotRequired,
        delegation_id: ActingUnder::NoDelegation,
        max_steps: 5,
        spend_limit: Restriction::To(Spend::from_micros(1_000_000)),
        spend_check: SpendCheck::AskAt(Spend::from_micros(500_000)),
        usage: ModelTokens::new(120, 30),
        spent: Spend::from_micros(500),
        started_by: Initiator::Human(human(UserId::new(), "ann@acme.example")),
        exposure: DataClassLevel::Internal,
        origin: EventOrigin::Outside,
        steps: Vec::new(),
        state: RunState::Running(NextCall::Model),
        check: RunCheck::Unchecked,
        created_at: at(0),
        updated_at: at(10),
    }
}

/// Step `seq` of a run, recorded `seconds` after the fixed moment: a call
/// to `get_order` that ran and read internal data.
///
/// # Panics
///
/// Never: the step is one the domain reads.
#[must_use]
pub fn tool_step(seq: u32, seconds: i64) -> RunStep {
    serde_json::from_value(json!({
        "seq": seq,
        "tool": "get_order",
        "arguments": "{\"id\":1}",
        "outcome": {"Allowed": "{\"total\":1}"},
        "read": "Internal",
        "at": at(seconds),
    }))
    .expect("a step the domain reads")
}

/// The call to `delete_order` a run holds at step `at_step`, waiting for a
/// person.
///
/// # Panics
///
/// Never: the call is one the domain reads.
#[must_use]
pub fn held_call(at_step: u32) -> PendingCall {
    serde_json::from_value(json!({
        "tool": "delete_order",
        "arguments": "{\"id\":1}",
        "class": "Delete",
        "at_step": at_step,
        "approved": "Awaiting",
    }))
    .expect("a held call the domain reads")
}

/// Ann's assignment, made at the fixed moment, of `reviewer` to review
/// `reviewed`, still standing.
#[must_use]
pub fn review_row(reviewer: AgentId, reviewed: AgentId) -> ReviewAssignmentRow {
    ReviewAssignmentRow {
        id: ReviewAssignmentId::new(),
        reviewer,
        reviewed,
        assigned_by: PrincipalRef::User(UserId::new()),
        assigned_at: at(0),
        ending: Ending::Ongoing,
    }
}

/// A pending request, opened by hand by Cid at the fixed moment and open
/// for ten minutes, to read order 1 for `agent`, owned by `owner`, under
/// no delegation.
///
/// # Panics
///
/// Never: every value is valid.
#[must_use]
pub fn opened_approval_row(agent: AgentId, owner: Human) -> ApprovalRequestRow {
    ApprovalRequestRow {
        id: ApprovalId::new(),
        agent_id: agent,
        delegation_id: ActingUnder::NoDelegation,
        origin: StoredApprovalOrigin::Opened(Initiator::Human(human(
            UserId::new(),
            "cid@acme.example",
        ))),
        parties: ActionParties::from_stored(owner, Vec::new()),
        action_class: DeclaredAction::Declared(ActionClass::Read),
        action: ApprovalAction::new("GET /orders/1").expect("a valid action"),
        state: ApprovalState::Pending(FirstOfTwo::NotGiven),
        created_at: at(0),
        expires_at: at(600),
        updated_at: at(0),
    }
}

/// The same request, made under `delegation`, which Dan granted.
#[must_use]
pub fn delegated_approval_row(
    agent: AgentId,
    owner: Human,
    delegation: DelegationId,
) -> ApprovalRequestRow {
    ApprovalRequestRow {
        delegation_id: ActingUnder::Delegation(delegation),
        parties: ActionParties::from_stored(
            owner.clone(),
            vec![human(UserId::new(), "dan@acme.example")],
        ),
        ..opened_approval_row(agent, owner)
    }
}

/// A pending request raised by `run`, paused on deleting order 1 at its
/// first step, its agent owned by `owner`.
///
/// # Panics
///
/// Never: every value is valid.
#[must_use]
pub fn run_approval_row(run: &AgentRun<ResolvedTenant>, owner: Human) -> ApprovalRequestRow {
    let call = ToolCall::new("delete_order", "{\"id\":1}").expect("a valid call");
    ApprovalRequestRow {
        origin: StoredApprovalOrigin::Run(StoredRunOrigin {
            run_id: *run.id(),
            agent_id: *run.agent_id(),
            started_by: run.started_by().clone(),
            pending_call: PendingCallRef::new(call, 1),
            exposure: run.exposure(),
            chain: run.origin(),
        }),
        action_class: DeclaredAction::Declared(ActionClass::Delete),
        action: ApprovalAction::new("DELETE /orders/1").expect("a valid action"),
        ..opened_approval_row(*run.agent_id(), owner)
    }
}
