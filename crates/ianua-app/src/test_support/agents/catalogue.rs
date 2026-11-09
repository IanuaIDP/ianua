//! What a tenant offers its agents, built as tests need it: the routes a
//! tool calls, registered tools, connected model providers and proposed
//! task templates, each made by a person with the right to.

use ianua_domain::domains::agents::authority::capability::{ActionApproval, CapabilitySet};
use ianua_domain::domains::agents::authority::intent::{
    IntentDigest, IntentEnvelope, IntentStatement,
};
use ianua_domain::domains::agents::authority::task_template::{
    ProposeTaskTemplateParams, TaskTemplate, TemplateLimits,
};
use ianua_domain::domains::agents::execution::model_provider::{
    CreateModelProviderParams, ModelEndpoint, ModelName, ModelProvider, ModelProviderKind,
    ProviderEmbeddings, ProviderKey,
};
use ianua_domain::domains::agents::execution::tool::{
    AgentTool, RegisterToolParams, ToolDescription, ToolMethod, ToolName, ToolPath, ToolSchema,
};
use ianua_domain::domains::agents::execution::usage::ModelPricing;
use ianua_domain::domains::agents::identity::control::AgentControl;
use ianua_domain::domains::authorization::authority::TenantAuthority;
use ianua_domain::domains::authorization::permission::{
    AgentAction, RoutingAction, SystemPermission,
};
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::domains::routing::matching::host::RouteHosts;
use ianua_domain::domains::routing::matching::parameter::RouteReach;
use ianua_domain::domains::routing::matching::path_rewrite::PathRewrite;
use ianua_domain::domains::routing::matching::request_match::RouteConditions;
use ianua_domain::domains::routing::policy::RoutePolicy;
use ianua_domain::domains::routing::route::{AttackMode, Route, RouteRow, WorkflowUse};
use ianua_domain::domains::routing::route_status::RouteStatus;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::clock;
use ianua_domain::shared::model::restriction::Restriction;
use ianua_domain::types::{
    ActionClass, DeclaredAction, Human, HumanAccount, Label, ModelProviderId, PersonKey,
    PipelineId, RouteId, Seconds, ServiceId, UrlPath, UserId,
};

use crate::ports::agents::{ModelProviderStore, TaskTemplateStore, ToolStore};
use crate::test_support::agents::{FakeModelProviderStore, FakeTaskTemplateStore, FakeToolStore};
use crate::test_support::{block_on, test_ctx};

/// What someone allowed to manage agents holds.
const MANAGE_AGENTS: [SystemPermission; 1] = [SystemPermission::Agents(AgentAction::Manage)];

/// Bob, a person other than the test caller, through an account of his own.
///
/// # Panics
///
/// - Never: the address is valid.
#[must_use]
pub fn someone_else() -> Human {
    Human::new(
        HumanAccount::User(UserId::new()),
        PersonKey::new("bob@example.test").expect("the address is valid"),
    )
}

/// `who`, allowed to manage agents in the test tenant.
#[must_use]
pub fn agent_manager(who: Human) -> TenantAuthority {
    TenantAuthority::assumed(who, test_ctx().tenant_id(), &MANAGE_AGENTS, &[])
}

/// An active route on `path` for every method, declaring `declared` and
/// serving `data_class`, as storage would read it back.
///
/// # Panics
///
/// - Never: the name and path are valid and the row consistent.
#[must_use]
pub fn tool_route(
    path: &str,
    declared: DeclaredAction,
    data_class: DataClassLevel,
) -> Route<ResolvedTenant> {
    let now = clock::now();
    Route::reconstitute(RouteRow {
        id: RouteId::new(),
        name: Label::new("name", "Orders API").expect("the name is valid"),
        path_pattern: UrlPath::new(path).expect("the path is valid"),
        methods: Vec::new(),
        service_id: ServiceId::new(),
        policy: RoutePolicy::Public,
        hosts: RouteHosts::Any,
        conditions: RouteConditions::default(),
        pipeline_id: PipelineId::new(),
        path_rewrite: PathRewrite::Keep,
        status: RouteStatus::Active,
        priority: 1,
        data_class,
        action_class: declared,
        reach: RouteReach::Fixed,
        parameter_rules: Vec::new(),
        workflow_use: WorkflowUse::Closed,
        attack_mode: AttackMode::Off,
        created_at: now,
        updated_at: now,
    })
    .expect("a fresh route is a consistent row")
}

/// The tool `name` on `method` and `path`, registered by an agent manager
/// over `route`.
///
/// # Panics
///
/// - Never with a route serving `method` and `path`.
#[must_use]
pub fn tool_over(
    name: &str,
    method: ToolMethod,
    path: &str,
    route: &Route<ResolvedTenant>,
) -> AgentTool<ResolvedTenant> {
    let manager = agent_manager(someone_else());
    AgentTool::register(
        RegisterToolParams {
            name: ToolName::new(name).expect("the tool name is valid"),
            description: ToolDescription::new("A tool").expect("the description is valid"),
            schema: ToolSchema::new(r#"{"type":"object"}"#).expect("the schema is valid"),
            method,
            path: ToolPath::new(path).expect("the path is valid"),
        },
        route,
        &AgentControl::new(&manager),
    )
    .expect("an agent manager registers a tool its route serves")
}

/// The active tool `name` on `GET /orders/{id}`, over an internal route
/// that declares nothing.
#[must_use]
pub fn registered_tool(name: &str) -> AgentTool<ResolvedTenant> {
    let path = "/orders/{id}";
    let route = tool_route(path, DeclaredAction::Undeclared, DataClassLevel::Internal);
    tool_over(name, ToolMethod::Get, path, &route)
}

/// The same tool, disabled by an agent manager.
///
/// # Panics
///
/// - Never with an active tool.
#[must_use]
pub fn disabled_tool(mut tool: AgentTool<ResolvedTenant>) -> AgentTool<ResolvedTenant> {
    let manager = agent_manager(someone_else());
    tool.disable(&AgentControl::new(&manager))
        .expect("an agent manager disables an active tool");
    tool
}

/// The active, keyless, self-hosted provider `name`, cleared for internal
/// data, connected by an agent manager.
///
/// # Panics
///
/// - Never: the values are valid and the manager may connect it.
#[must_use]
pub fn connected_provider(name: &str) -> ModelProvider<ResolvedTenant> {
    let manager = agent_manager(someone_else());
    ModelProvider::create(
        &AgentControl::new(&manager),
        CreateModelProviderParams {
            id: ModelProviderId::new(),
            name: Label::new("name", name).expect("the name is valid"),
            kind: ModelProviderKind::SelfHosted,
            endpoint: ModelEndpoint::new("http://deepseek.models.svc:8000/v1")
                .expect("the endpoint is valid"),
            model: ModelName::new("deepseek-chat").expect("the model is valid"),
            pricing: ModelPricing::Unpriced,
            credential_ref: ProviderKey::Keyless,
            clearance: DataClassLevel::Internal,
        },
    )
    .expect("an agent manager connects a provider")
}

/// The same provider offering OpenAI's `text-embedding-3-small` beside
/// its chat model, as an agent manager set it.
///
/// # Panics
///
/// - Never with a self-hosted or OpenAI provider.
#[must_use]
pub fn embedding_provider(
    mut provider: ModelProvider<ResolvedTenant>,
) -> ModelProvider<ResolvedTenant> {
    let manager = agent_manager(someone_else());
    provider
        .offer_embeddings(
            &AgentControl::new(&manager),
            ProviderEmbeddings::Model(
                ModelName::new("text-embedding-3-small").expect("the model is valid"),
            ),
        )
        .expect("an agent manager offers an embedding model");
    provider
}

/// The same provider, disabled by an agent manager.
///
/// # Panics
///
/// - Never with an active provider.
#[must_use]
pub fn disabled_provider(
    mut provider: ModelProvider<ResolvedTenant>,
) -> ModelProvider<ResolvedTenant> {
    let manager = agent_manager(someone_else());
    provider
        .disable(&AgentControl::new(&manager))
        .expect("an agent manager disables an active provider");
    provider
}

/// What a template for reading the monthly reports fills in: route views,
/// reads only, for ten minutes, never passed on.
///
/// # Panics
///
/// - Never: the values are valid.
#[must_use]
pub fn report_template_params() -> ProposeTaskTemplateParams {
    ProposeTaskTemplateParams {
        name: Label::new("name", "monthly reports").expect("the name is valid"),
        purpose: IntentStatement::new("read the monthly reports").expect("the purpose is valid"),
        digest: IntentDigest::new([0; 32]),
        ceiling: CapabilitySet::new(vec![SystemPermission::Routing(RoutingAction::View)], vec![]),
        classes: IntentEnvelope::new([ActionClass::Read]),
        limits: TemplateLimits {
            max_ttl_seconds: Seconds::new(600),
            max_depth: 0,
            max_data_class: DataClassLevel::Internal,
            resource_scope: Restriction::Unrestricted,
            budget: Restriction::Unrestricted,
            approval: ActionApproval::NotRequired,
        },
    }
}

/// The monthly reports template, proposed by `proposer`.
///
/// # Panics
///
/// - Never: the template is a valid proposal.
#[must_use]
pub fn template_proposed_by(proposer: Human) -> TaskTemplate<ResolvedTenant> {
    let authority = TenantAuthority::assumed(proposer, test_ctx().tenant_id(), &[], &[]);
    TaskTemplate::propose(&AgentControl::new(&authority), report_template_params())
        .expect("the monthly reports template is a valid proposal")
}

/// A tool store keeping `tools` in the test tenant.
///
/// # Panics
///
/// - Never: the fake store keeps every tool.
#[must_use]
pub fn tools_holding(tools: impl IntoIterator<Item = AgentTool<ResolvedTenant>>) -> FakeToolStore {
    let store = FakeToolStore::empty();
    for tool in tools {
        block_on(store.save(&test_ctx().tenant(), &tool)).expect("the fake store keeps it");
    }
    store
}

/// A provider store keeping `providers` in the test tenant.
///
/// # Panics
///
/// - Never: the fake store keeps every provider.
#[must_use]
pub fn providers_holding(
    providers: impl IntoIterator<Item = ModelProvider<ResolvedTenant>>,
) -> FakeModelProviderStore {
    let store = FakeModelProviderStore::empty();
    for provider in providers {
        block_on(store.save(&test_ctx().tenant(), &provider)).expect("the fake store keeps it");
    }
    store
}

/// A template store keeping `templates` in the test tenant.
///
/// # Panics
///
/// - Never: the fake store keeps every template.
#[must_use]
pub fn templates_holding(
    templates: impl IntoIterator<Item = TaskTemplate<ResolvedTenant>>,
) -> FakeTaskTemplateStore {
    let store = FakeTaskTemplateStore::default();
    for template in templates {
        block_on(store.save(&test_ctx().tenant(), &template)).expect("the fake store keeps it");
    }
    store
}
