//! Register tool: add an API agents may call, over one of the tenant's
//! routes.
//!
//! A tool binds a model-facing name, description and input schema to a
//! method and path the route serves. It takes its action class and data
//! class from the route, so a tool cannot pass a payment endpoint off as a
//! public read. Only someone allowed to manage agents registers one.
//!
//! The person who registers a tool is given use of it; a run started by
//! anyone else is offered it only once that use is shared with them.

use std::sync::Arc;

use ianua_domain::domains::agents::authority::capability::ResourceCapability;
use ianua_domain::domains::agents::execution::tool::{
    AgentTool, RegisterToolParams, ToolDescription, ToolMethod, ToolName, ToolPath, ToolSchema,
};
use ianua_domain::domains::agents::identity::control::AgentControl;
use ianua_domain::domains::authorization::authority::TenantAuthority;
use ianua_domain::domains::authorization::permission::{AgentAction, SystemPermission};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{AgentToolId, RouteId};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::agents::{ResourceGrantStore, ToolStore};
use crate::ports::limits::{LimitEnforcer, ResourceKind};
use crate::ports::routing::RouteStore;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::agents::delegation::resources::usage::grant_use_to_creator;
use crate::use_cases::routing::lookup::existing_route;

/// What a tool calls, and what the model is told about it.
pub struct RegisterRequest {
    /// The name the model calls.
    pub name: ToolName,
    /// The model-facing description.
    pub description: ToolDescription,
    /// The input JSON schema.
    pub schema: ToolSchema,
    /// The HTTP method the call uses.
    pub method: ToolMethod,
    /// The URL path template.
    pub path: ToolPath,
    /// The route that serves the call, whose classes the tool takes.
    pub route_id: RouteId,
}

/// The ports [`RegisterUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RegisterPorts {
    /// Enforces the tenant's plan limit on tools.
    pub limit_enforcer: Arc<dyn LimitEnforcer>,
    /// Keeps the tool.
    pub tool_store: Arc<dyn ToolStore>,
    /// Loads the route the tool calls.
    pub route_store: Arc<dyn RouteStore>,
    /// Gives the registering person use of the tool.
    pub resource_grants: Arc<dyn ResourceGrantStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Registers a tool in the caller's tenant.
pub struct RegisterUseCase {
    ports: RegisterPorts,
}

impl RegisterUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: RegisterPorts) -> Self {
        Self { ports }
    }
}

impl Command for RegisterUseCase {
    type Caller = CallerContext;
    type Input = RegisterRequest;
    type Output = Result<AgentToolId, AppError>;

    /// Registers the tool `req` describes and returns its id.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not manage agents, or the
    ///   plan's tool limit is reached.
    /// - `AppError::NotFound` when the tenant has no such route.
    /// - `AppError::Domain` when the route does not serve the tool's method
    ///   and path.
    /// - `AppError::Internal` on persistence or audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        req: RegisterRequest,
    ) -> Result<AgentToolId, AppError> {
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        self.ports
            .limit_enforcer
            .check_tenant_limit(ctx.plan_limits(), &tenant, ResourceKind::AgentTools)
            .await
            .map_err(AppError::from_domain)?;
        let mut tool = registered(&self.ports, &tenant, &authority, req).await?;
        self.ports
            .tool_store
            .save(&tenant, &tool)
            .await
            .or_internal()?;
        grant_use_to_creator(
            self.ports.resource_grants.as_ref(),
            &tenant,
            &authority,
            &ResourceCapability::use_of_tool(tool.id()),
        )
        .await?;
        auditor
            .dispatch_by(&ctx.actor(), tool.take_events(&tenant))
            .await
            .or_internal()?;
        Ok(*tool.id())
    }
}

/// The tool `req` describes, registered over its route by the person
/// `authority` names. The right to manage agents is checked before the
/// route is read, so a route id tells someone without it nothing.
async fn registered(
    ports: &RegisterPorts,
    tenant: &ScopedTenant,
    authority: &TenantAuthority,
    req: RegisterRequest,
) -> Result<AgentTool<ResolvedTenant>, AppError> {
    authority
        .ensure_holds(SystemPermission::Agents(AgentAction::Manage))
        .map_err(AppError::from_domain)?;
    let route = existing_route(ports.route_store.as_ref(), tenant, &req.route_id).await?;
    let params = RegisterToolParams {
        name: req.name,
        description: req.description,
        schema: req.schema,
        method: req.method,
        path: req.path,
    };
    AgentTool::register(params, &route, &AgentControl::new(authority))
        .map_err(AppError::from_domain)
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{AgentAction, SystemPermission};
    use ianua_domain::domains::data_classification::level::DataClassLevel;
    use ianua_domain::domains::routing::route::Route;
    use ianua_domain::types::{ActionClass, DeclaredAction};

    use super::*;
    use crate::ports::agents::RelationshipResolver;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::agents::{
        FakeResourceGraph, FakeToolStore, caller_person, tool_route,
    };
    use crate::test_support::routing::FakeRouteStore;
    use crate::test_support::{
        FakeEventDispatcher, RejectingLimitEnforcer, block_on, test_auditor, test_ctx,
    };

    /// The tenant's routes and tools, and what a registration wrote.
    struct Tenant {
        routes: Arc<FakeRouteStore>,
        tools: Arc<FakeToolStore>,
        grants: Arc<FakeResourceGraph>,
        sink: Arc<FakeEventDispatcher>,
    }

    impl Tenant {
        fn with(route: &Route<ResolvedTenant>) -> Self {
            let routes = Arc::new(FakeRouteStore::empty());
            block_on(routes.save(&test_ctx().tenant(), route)).unwrap();
            Self {
                routes,
                tools: Arc::new(FakeToolStore::empty()),
                grants: Arc::new(FakeResourceGraph::empty()),
                sink: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn ports(&self) -> RegisterPorts {
            RegisterPorts {
                tool_store: self.tools.clone(),
                route_store: self.routes.clone(),
                resource_grants: self.grants.clone(),
                ..RegisterPorts::fakes()
            }
        }

        fn register(
            &self,
            ports: RegisterPorts,
            req: RegisterRequest,
        ) -> Result<AgentToolId, AppError> {
            block_on(RegisterUseCase::new(ports).execute(
                &test_ctx(),
                &test_auditor(self.sink.clone()),
                req,
            ))
        }
    }

    fn request(method: ToolMethod, path: &str, route: &Route<ResolvedTenant>) -> RegisterRequest {
        RegisterRequest {
            name: ToolName::new("get_order").unwrap(),
            description: ToolDescription::new("Fetch an order by id").unwrap(),
            schema: ToolSchema::new(r#"{"type":"object"}"#).unwrap(),
            method,
            path: ToolPath::new(path).unwrap(),
            route_id: *route.id(),
        }
    }

    fn orders_route() -> Route<ResolvedTenant> {
        tool_route(
            "/orders/{id}",
            DeclaredAction::Undeclared,
            DataClassLevel::Confidential,
        )
    }

    /// Ann registers `DELETE /orders/{id}` over the confidential orders
    /// route. The tool is kept as a delete of confidential data, and the
    /// registration is recorded.
    #[test]
    fn a_tool_takes_its_classes_from_its_route() {
        let route = orders_route();
        let tenant = Tenant::with(&route);

        let id = tenant
            .register(
                tenant.ports(),
                request(ToolMethod::Delete, "/orders/{id}", &route),
            )
            .unwrap();

        let stored = block_on(tenant.tools.find_by_id(&test_ctx().tenant(), &id))
            .unwrap()
            .unwrap();
        assert_eq!(stored.action_class(), ActionClass::Delete);
        assert_eq!(stored.classification(), DataClassLevel::Confidential);
        assert_eq!(
            tenant.sink.records.lock().unwrap().as_slice(),
            ["agents.tool_registered"]
        );
    }

    /// Ann registers a tool. She is given use of it, so her runs may call
    /// it before anyone shares it with her.
    #[test]
    fn the_person_who_registers_a_tool_is_given_use_of_it() {
        let route = orders_route();
        let tenant = Tenant::with(&route);

        let id = tenant
            .register(
                tenant.ports(),
                request(ToolMethod::Get, "/orders/{id}", &route),
            )
            .unwrap();

        let held = block_on(tenant.grants.held_subset(
            &test_ctx().tenant(),
            &caller_person().principal(),
            &[ResourceCapability::use_of_tool(&id)],
        ))
        .unwrap();
        assert_eq!(held.len(), 1);
    }

    /// A tool targeting transfers cannot use the orders route for its
    /// classification; registration is refused and no tool is stored.
    #[test]
    fn a_tool_its_route_does_not_serve_is_refused() {
        let route = orders_route();
        let tenant = Tenant::with(&route);

        let result = tenant.register(
            tenant.ports(),
            request(ToolMethod::Post, "/transfers", &route),
        );

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert_eq!(tenant.tools.count(), 0);
    }

    /// Ann names a route the tenant does not have. It is not found.
    #[test]
    fn an_unknown_route_is_not_found() {
        let tenant = Tenant::with(&orders_route());
        let elsewhere = orders_route();

        let result = tenant.register(
            tenant.ports(),
            request(ToolMethod::Get, "/orders/{id}", &elsewhere),
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// The view right does not authorize tool registration; the attempt
    /// creates neither a stored tool nor an audit record.
    #[test]
    fn a_caller_who_may_not_manage_agents_is_refused() {
        let route = orders_route();
        let tenant = Tenant::with(&route);
        let ports = RegisterPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
                SystemPermission::Agents(AgentAction::View),
            ])),
            ..tenant.ports()
        };

        let result = tenant.register(ports, request(ToolMethod::Get, "/orders/{id}", &route));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(tenant.tools.count(), 0);
        assert!(tenant.sink.records.lock().unwrap().is_empty());
    }

    /// A signed-out caller cannot register a tool.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let route = orders_route();
        let tenant = Tenant::with(&route);
        let ports = RegisterPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..tenant.ports()
        };

        let result = tenant.register(ports, request(ToolMethod::Get, "/orders/{id}", &route));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(tenant.tools.count(), 0);
    }

    /// The tenant's plan allows no more tools. Ann's registration is
    /// refused and nothing is kept.
    #[test]
    fn register_tool_rejects_when_plan_limit_reached() {
        let route = orders_route();
        let tenant = Tenant::with(&route);
        let ports = RegisterPorts {
            limit_enforcer: Arc::new(RejectingLimitEnforcer),
            ..tenant.ports()
        };

        let result = tenant.register(ports, request(ToolMethod::Get, "/orders/{id}", &route));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(tenant.tools.count(), 0);
    }
}
