//! Tools, routes and agent managers for the tests of tools and runs.

use crate::domains::agents::execution::tool::{
    AgentTool, RegisterToolParams, ToolDescription, ToolMethod, ToolName, ToolPath, ToolSchema,
};
use crate::domains::agents::identity::control::AgentControl;
use crate::domains::authorization::permission::SystemPermission;
use crate::domains::data_classification::level::DataClassLevel;
use crate::domains::routing::matching::host::RouteHosts;
use crate::domains::routing::matching::parameter::RouteReach;
use crate::domains::routing::matching::path_rewrite::PathRewrite;
use crate::domains::routing::matching::request_match::RouteConditions;
use crate::domains::routing::policy::RoutePolicy;
use crate::domains::routing::route::{AttackMode, Route, RouteRow, WorkflowUse};
use crate::domains::routing::route_status::RouteStatus;
use crate::isolation::scope::ResolvedTenant;
use crate::test_support::authority::assumed_authority;
use crate::types::{
    DeclaredAction, Human, HumanAccount, Label, PersonKey, PipelineId, RouteId, ServiceId,
    TenantId, UrlPath, UserId,
};

/// What someone allowed to manage agents holds.
pub(crate) const MANAGE: [SystemPermission; 1] = [SystemPermission::ManageAgents];

/// The person reached at `address`, through an account of their own.
pub(crate) fn person(address: &str) -> Human {
    Human::new(
        HumanAccount::User(UserId::new()),
        PersonKey::new(address).unwrap(),
    )
}

/// `by`, holding `system`.
pub(crate) fn holding<'a>(by: &'a Human, system: &'a [SystemPermission]) -> AgentControl<'a> {
    AgentControl::new(assumed_authority(by, TenantId::new(), system, &[]))
}

/// An active route on `pattern` for every method, declaring `declared` and
/// serving `data_class`.
pub(crate) fn route(
    pattern: &str,
    declared: DeclaredAction,
    data_class: DataClassLevel,
) -> Route<ResolvedTenant> {
    let now = crate::shared::clock::now();
    Route::reconstitute(RouteRow {
        id: RouteId::new(),
        name: Label::new("name", "Orders API").unwrap(),
        path_pattern: UrlPath::new(pattern).unwrap(),
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
    .unwrap()
}

/// The tool `name` on `method` and `path`, registered by Bob, an agent
/// manager, over a route on the same path declaring `declared` and serving
/// `data_class`.
pub(crate) fn registered(
    name: &str,
    method: ToolMethod,
    path: &str,
    declared: DeclaredAction,
    data_class: DataClassLevel,
) -> AgentTool<ResolvedTenant> {
    let bob = person("bob@corp.test");
    AgentTool::register(
        RegisterToolParams {
            name: ToolName::new(name).unwrap(),
            description: ToolDescription::new("A tool").unwrap(),
            schema: ToolSchema::new(r#"{"type":"object"}"#).unwrap(),
            method,
            path: ToolPath::new(path).unwrap(),
        },
        &route(path, declared, data_class),
        &holding(&bob, &MANAGE),
    )
    .unwrap()
}
