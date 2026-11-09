//! Update tool status: turn a tool on or off.
//!
//! A disabled tool is kept but offered to no run. Only someone allowed to
//! manage agents turns one on or off.

use std::sync::Arc;

use ianua_domain::domains::agents::execution::tool::{AgentTool, ToolStatus};
use ianua_domain::domains::agents::identity::control::AgentControl;
use ianua_domain::domains::authorization::permission::{AgentAction, SystemPermission};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::AgentToolId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::agents::ToolStore;
use crate::use_case::Command;
use crate::use_cases::agents::lookup::existing_tool;

/// The ports [`UpdateStatusUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct UpdateStatusPorts {
    /// Loads and saves tools.
    pub tool_store: Arc<dyn ToolStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Which tool to change, and the status it should have.
pub struct UpdateStatusRequest {
    /// The tool to turn on or off.
    pub tool_id: AgentToolId,
    /// The status the tool should end up in.
    pub status: ToolStatus,
}

/// Turns a tool of the caller's tenant on or off.
pub struct UpdateStatusUseCase {
    ports: UpdateStatusPorts,
}

impl UpdateStatusUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: UpdateStatusPorts) -> Self {
        Self { ports }
    }
}

impl Command for UpdateStatusUseCase {
    type Caller = CallerContext;
    type Input = UpdateStatusRequest;
    type Output = Result<(), AppError>;

    /// Moves the tool to the status `request` asks for.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not manage agents, before
    ///   any tool is read.
    /// - `AppError::NotFound` when the tenant has no such tool.
    /// - `AppError::Domain` when the tool already has that status.
    /// - `AppError::Internal` on persistence or audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: UpdateStatusRequest,
    ) -> Result<(), AppError> {
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        authority
            .ensure_holds(SystemPermission::Agents(AgentAction::Manage))
            .map_err(AppError::from_domain)?;
        let mut tool =
            existing_tool(self.ports.tool_store.as_ref(), &tenant, &request.tool_id).await?;
        move_to(&mut tool, &AgentControl::new(&authority), request.status)
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

/// Moves `tool` to `status`, as the person `control` names.
fn move_to(
    tool: &mut AgentTool<ResolvedTenant>,
    control: &AgentControl<'_>,
    status: ToolStatus,
) -> Result<(), DomainError> {
    match status {
        ToolStatus::Active => tool.enable(control),
        ToolStatus::Disabled => tool.disable(control),
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{AgentAction, SystemPermission};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::agents::{FakeToolStore, registered_tool, tools_holding};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    fn change(
        ports: UpdateStatusPorts,
        sink: &Arc<FakeEventDispatcher>,
        tool_id: AgentToolId,
        status: ToolStatus,
    ) -> Result<(), AppError> {
        block_on(UpdateStatusUseCase::new(ports).execute(
            &test_ctx(),
            &test_auditor(sink.clone()),
            UpdateStatusRequest { tool_id, status },
        ))
    }

    fn ports_over(store: &Arc<FakeToolStore>) -> UpdateStatusPorts {
        UpdateStatusPorts {
            tool_store: store.clone(),
            ..UpdateStatusPorts::fakes()
        }
    }

    fn is_active(store: &FakeToolStore, id: &AgentToolId) -> bool {
        block_on(store.find_by_id(&test_ctx().tenant(), id))
            .unwrap()
            .unwrap()
            .is_active()
    }

    /// Ann turns `get_order` off and back on. Each change is kept and
    /// recorded.
    #[test]
    fn a_tool_is_turned_off_and_back_on() {
        let tool = registered_tool("get_order");
        let id = *tool.id();
        let store = Arc::new(tools_holding([tool]));
        let sink = Arc::new(FakeEventDispatcher::new());

        change(ports_over(&store), &sink, id, ToolStatus::Disabled).unwrap();
        assert!(!is_active(&store, &id));
        change(ports_over(&store), &sink, id, ToolStatus::Active).unwrap();

        assert!(is_active(&store, &id));
        assert_eq!(
            sink.records.lock().unwrap().as_slice(),
            ["agents.tool_status_changed", "agents.tool_status_changed"]
        );
    }

    /// Ann turns on a tool that is already on. She is told it already is,
    /// and nothing is recorded.
    #[test]
    fn turning_on_an_active_tool_is_refused() {
        let tool = registered_tool("get_order");
        let id = *tool.id();
        let store = Arc::new(tools_holding([tool]));
        let sink = Arc::new(FakeEventDispatcher::new());

        let result = change(ports_over(&store), &sink, id, ToolStatus::Active);

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert!(sink.records.lock().unwrap().is_empty());
    }

    /// Ann turns off a tool the tenant does not have. It is not found.
    #[test]
    fn an_unknown_tool_is_not_found() {
        let store = Arc::new(FakeToolStore::empty());

        let result = change(
            ports_over(&store),
            &Arc::new(FakeEventDispatcher::new()),
            AgentToolId::new(),
            ToolStatus::Disabled,
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A caller with only the view right cannot disable an active tool;
    /// the stored tool stays active.
    #[test]
    fn a_caller_who_may_not_manage_agents_is_refused() {
        let tool = registered_tool("get_order");
        let id = *tool.id();
        let store = Arc::new(tools_holding([tool]));
        let ports = UpdateStatusPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
                SystemPermission::Agents(AgentAction::View),
            ])),
            ..ports_over(&store)
        };

        let result = change(
            ports,
            &Arc::new(FakeEventDispatcher::new()),
            id,
            ToolStatus::Disabled,
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(is_active(&store, &id));
    }

    /// A signed-out caller's attempt to disable a tool is refused, leaving
    /// the tool active.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let tool = registered_tool("get_order");
        let id = *tool.id();
        let store = Arc::new(tools_holding([tool]));
        let ports = UpdateStatusPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..ports_over(&store)
        };

        let result = change(
            ports,
            &Arc::new(FakeEventDispatcher::new()),
            id,
            ToolStatus::Disabled,
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert!(is_active(&store, &id));
    }
}
