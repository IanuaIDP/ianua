//! Delete tool: remove a disabled tool for good.
//!
//! A tool is disabled before it goes, so no run is part way through a call
//! to it. Only someone allowed to manage agents deletes one; the domain
//! decides both.

use std::sync::Arc;

use ianua_domain::domains::agents::identity::control::AgentControl;
use ianua_domain::domains::authorization::permission::{AgentAction, SystemPermission};
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::AgentToolId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::agents::ToolStore;
use crate::use_case::Command;
use crate::use_cases::agents::lookup::existing_tool;

/// The ports [`DeleteUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct DeletePorts {
    /// Loads and deletes tools.
    pub tool_store: Arc<dyn ToolStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Deletes a tool of the caller's tenant.
pub struct DeleteUseCase {
    ports: DeletePorts,
}

impl DeleteUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: DeletePorts) -> Self {
        Self { ports }
    }
}

impl Command for DeleteUseCase {
    type Caller = CallerContext;
    type Input = AgentToolId;
    type Output = Result<(), AppError>;

    /// Deletes the tool `tool_id`, once it is disabled.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not manage agents, before
    ///   any tool is read.
    /// - `AppError::NotFound` when the tenant has no such tool.
    /// - `AppError::Domain` while the tool is still active.
    /// - `AppError::Internal` on persistence or audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        tool_id: AgentToolId,
    ) -> Result<(), AppError> {
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        authority
            .ensure_holds(SystemPermission::Agents(AgentAction::Manage))
            .map_err(AppError::from_domain)?;
        let mut tool = existing_tool(self.ports.tool_store.as_ref(), &tenant, &tool_id).await?;
        tool.delete(&AgentControl::new(&authority))
            .map_err(AppError::from_domain)?;
        self.ports
            .tool_store
            .delete(&tenant, &tool_id)
            .await
            .or_internal()?;
        auditor
            .dispatch_by(&ctx.actor(), tool.take_events(&tenant))
            .await
            .or_internal()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{AgentAction, SystemPermission};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::agents::{
        FakeToolStore, disabled_tool, registered_tool, tools_holding,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    fn delete(
        ports: DeletePorts,
        sink: &Arc<FakeEventDispatcher>,
        tool_id: AgentToolId,
    ) -> Result<(), AppError> {
        block_on(DeleteUseCase::new(ports).execute(
            &test_ctx(),
            &test_auditor(sink.clone()),
            tool_id,
        ))
    }

    fn ports_over(store: &Arc<FakeToolStore>) -> DeletePorts {
        DeletePorts {
            tool_store: store.clone(),
            ..DeletePorts::fakes()
        }
    }

    /// Ann deletes `get_order`, which she disabled first. It is gone, and
    /// the delete is recorded with the tool's name.
    #[test]
    fn a_disabled_tool_is_deleted_and_recorded() {
        let tool = disabled_tool(registered_tool("get_order"));
        let id = *tool.id();
        let store = Arc::new(tools_holding([tool]));
        let sink = Arc::new(FakeEventDispatcher::new());

        delete(ports_over(&store), &sink, id).unwrap();

        assert_eq!(store.count(), 0);
        assert_eq!(
            sink.label_of("agents.tool_deleted", "tool").as_deref(),
            Some("get_order")
        );
    }

    /// Ann deletes `get_order` while it is still active, so a run could be
    /// part way through a call to it. She is refused and the tool stays.
    #[test]
    fn an_active_tool_is_kept() {
        let tool = registered_tool("get_order");
        let id = *tool.id();
        let store = Arc::new(tools_holding([tool]));

        let result = delete(
            ports_over(&store),
            &Arc::new(FakeEventDispatcher::new()),
            id,
        );

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert_eq!(store.count(), 1);
    }

    /// Ann deletes a tool the tenant does not have. It is not found.
    #[test]
    fn an_unknown_tool_is_not_found() {
        let store = Arc::new(FakeToolStore::empty());

        let result = delete(
            ports_over(&store),
            &Arc::new(FakeEventDispatcher::new()),
            AgentToolId::new(),
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A caller with only the view right cannot delete a disabled tool;
    /// the tool remains stored and no deletion is recorded.
    #[test]
    fn a_caller_who_may_not_manage_agents_is_refused() {
        let tool = disabled_tool(registered_tool("get_order"));
        let id = *tool.id();
        let store = Arc::new(tools_holding([tool]));
        let sink = Arc::new(FakeEventDispatcher::new());
        let ports = DeletePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
                SystemPermission::Agents(AgentAction::View),
            ])),
            ..ports_over(&store)
        };

        let result = delete(ports, &sink, id);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(store.count(), 1);
        assert!(sink.records.lock().unwrap().is_empty());
    }

    /// A signed-out caller cannot delete a disabled tool, which remains
    /// in the store.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let tool = disabled_tool(registered_tool("get_order"));
        let id = *tool.id();
        let store = Arc::new(tools_holding([tool]));
        let ports = DeletePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..ports_over(&store)
        };

        let result = delete(ports, &Arc::new(FakeEventDispatcher::new()), id);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(store.count(), 1);
    }
}
