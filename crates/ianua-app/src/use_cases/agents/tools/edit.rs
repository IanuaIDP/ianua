//! Edit tool: replace a tool's definition.
//!
//! A tool's name, description, input schema, method, path and route are
//! replaced together. Its action class and data class are read again from
//! the route it now calls, the way registering reads them, so an edit
//! cannot keep a read's classes for what is now a payment. The tool keeps
//! its status and whoever was given use of it. Only someone allowed to
//! manage agents edits one.

use std::sync::Arc;

use ianua_domain::domains::agents::execution::tool::{
    RegisterToolParams, ToolDescription, ToolMethod, ToolName, ToolPath, ToolSchema,
};
use ianua_domain::domains::agents::identity::control::AgentControl;
use ianua_domain::domains::authorization::permission::{AgentAction, SystemPermission};
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{AgentToolId, RouteId};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::agents::ToolStore;
use crate::ports::routing::RouteStore;
use crate::use_case::Command;
use crate::use_cases::agents::lookup::existing_tool;
use crate::use_cases::routing::lookup::existing_route;

/// Which tool to edit, and what it is to call and say.
pub struct EditRequest {
    /// The registered model operation whose definition will change.
    pub tool_id: AgentToolId,
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

/// The ports [`EditUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct EditPorts {
    /// Loads and keeps the tool.
    pub tool_store: Arc<dyn ToolStore>,
    /// Loads the route the tool calls.
    pub route_store: Arc<dyn RouteStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Edits the tenant's tools.
pub struct EditUseCase {
    ports: EditPorts,
}

impl EditUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: EditPorts) -> Self {
        Self { ports }
    }
}

impl Command for EditUseCase {
    type Caller = CallerContext;
    type Input = EditRequest;
    type Output = Result<(), AppError>;

    /// Replaces the tool's definition with `request`, over the route it
    /// names, and records `agents.tool_edited` with the classes it now
    /// takes.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not manage agents, before
    ///   any tool or route is read.
    /// - `AppError::NotFound` when the tenant has no such tool or route.
    /// - `AppError::Domain` when the route does not serve the new method
    ///   and path.
    /// - `AppError::Internal` on persistence or audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: EditRequest,
    ) -> Result<(), AppError> {
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        authority
            .ensure_holds(SystemPermission::Agents(AgentAction::Manage))
            .map_err(AppError::from_domain)?;
        let mut tool =
            existing_tool(self.ports.tool_store.as_ref(), &tenant, &request.tool_id).await?;
        let route =
            existing_route(self.ports.route_store.as_ref(), &tenant, &request.route_id).await?;
        tool.edit(definition(request), &route, &AgentControl::new(&authority))
            .map_err(AppError::from_domain)?;
        self.ports
            .tool_store
            .save(&tenant, &tool)
            .await
            .or_internal()?;
        auditor
            .dispatch_by(&ctx.actor(), tool.take_events(&tenant))
            .await
            .or_internal()?;
        Ok(())
    }
}

/// The definition `request` gives the tool.
fn definition(request: EditRequest) -> RegisterToolParams {
    RegisterToolParams {
        name: request.name,
        description: request.description,
        schema: request.schema,
        method: request.method,
        path: request.path,
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::agents::execution::tool::AgentTool;
    use ianua_domain::domains::authorization::permission::{AgentAction, SystemPermission};
    use ianua_domain::domains::data_classification::level::DataClassLevel;
    use ianua_domain::domains::routing::route::Route;
    use ianua_domain::isolation::scope::ResolvedTenant;
    use ianua_domain::types::{ActionClass, DeclaredAction};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::agents::{FakeToolStore, registered_tool, tool_route, tools_holding};
    use crate::test_support::routing::FakeRouteStore;
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// The tenant's `get_order` tool, the transfers route it may be moved
    /// to, and what an edit wrote.
    struct Tenant {
        tool: AgentToolId,
        transfers: Route<ResolvedTenant>,
        tools: Arc<FakeToolStore>,
        routes: Arc<FakeRouteStore>,
        sink: Arc<FakeEventDispatcher>,
    }

    impl Tenant {
        fn new() -> Self {
            let tool = registered_tool("get_order");
            let transfers = tool_route(
                "/transfers",
                DeclaredAction::Declared(ActionClass::Financial),
                DataClassLevel::Restricted,
            );
            let routes = Arc::new(FakeRouteStore::empty());
            block_on(routes.save(&test_ctx().tenant(), &transfers)).unwrap();
            Self {
                tool: *tool.id(),
                transfers,
                tools: Arc::new(tools_holding([tool])),
                routes,
                sink: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn ports(&self) -> EditPorts {
            EditPorts {
                tool_store: self.tools.clone(),
                route_store: self.routes.clone(),
                ..EditPorts::fakes()
            }
        }

        fn request(&self, method: ToolMethod, path: &str) -> EditRequest {
            EditRequest {
                tool_id: self.tool,
                name: ToolName::new("transfer").unwrap(),
                description: ToolDescription::new("Move money between accounts").unwrap(),
                schema: ToolSchema::new(r#"{"type":"object"}"#).unwrap(),
                method,
                path: ToolPath::new(path).unwrap(),
                route_id: *self.transfers.id(),
            }
        }

        fn edit(&self, ports: EditPorts, request: EditRequest) -> Result<(), AppError> {
            block_on(EditUseCase::new(ports).execute(
                &test_ctx(),
                &test_auditor(self.sink.clone()),
                request,
            ))
        }

        fn stored(&self) -> AgentTool<ResolvedTenant> {
            block_on(self.tools.find_by_id(&test_ctx().tenant(), &self.tool))
                .unwrap()
                .unwrap()
        }
    }

    /// Ann moves `get_order` to `POST /transfers` on the financial,
    /// restricted transfers route. The tool takes that route's classes, not
    /// its old ones, so a run pauses on it, and the edit is recorded.
    #[test]
    fn an_edited_tool_takes_the_classes_of_its_new_route() {
        let tenant = Tenant::new();

        tenant
            .edit(
                tenant.ports(),
                tenant.request(ToolMethod::Post, "/transfers"),
            )
            .unwrap();

        let tool = tenant.stored();
        assert_eq!(tool.name().as_str(), "transfer");
        assert_eq!(tool.action_class(), ActionClass::Financial);
        assert_eq!(tool.classification(), DataClassLevel::Restricted);
        assert_eq!(
            tenant.sink.records.lock().unwrap().as_slice(),
            ["agents.tool_edited"]
        );
    }

    /// An edit targeting a path outside the selected route is rejected,
    /// and the stored tool retains its original name.
    #[test]
    fn an_edit_its_route_does_not_serve_is_refused() {
        let tenant = Tenant::new();

        let result = tenant.edit(tenant.ports(), tenant.request(ToolMethod::Post, "/weather"));

        assert!(matches!(result, Err(AppError::Domain(_))), "{result:?}");
        assert_eq!(tenant.stored().name().as_str(), "get_order");
    }

    /// Ann edits a tool the tenant does not have. It is not found.
    #[test]
    fn an_unknown_tool_is_not_found() {
        let tenant = Tenant::new();
        let request = EditRequest {
            tool_id: AgentToolId::new(),
            ..tenant.request(ToolMethod::Post, "/transfers")
        };

        let result = tenant.edit(tenant.ports(), request);

        assert!(matches!(result, Err(AppError::NotFound(_))), "{result:?}");
    }

    /// A caller with only the view right cannot edit the tool; its stored
    /// name stays unchanged and no edit is recorded.
    #[test]
    fn a_caller_who_may_not_manage_agents_is_refused() {
        let tenant = Tenant::new();
        let ports = EditPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
                SystemPermission::Agents(AgentAction::View),
            ])),
            ..tenant.ports()
        };

        let result = tenant.edit(ports, tenant.request(ToolMethod::Post, "/transfers"));

        assert!(matches!(result, Err(AppError::Forbidden(_))), "{result:?}");
        assert_eq!(tenant.stored().name().as_str(), "get_order");
        assert!(tenant.sink.records.lock().unwrap().is_empty());
    }

    /// A signed-out caller cannot edit a tool, whose stored name remains
    /// unchanged.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let tenant = Tenant::new();
        let ports = EditPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..tenant.ports()
        };

        let result = tenant.edit(ports, tenant.request(ToolMethod::Post, "/transfers"));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(tenant.stored().name().as_str(), "get_order");
    }
}
