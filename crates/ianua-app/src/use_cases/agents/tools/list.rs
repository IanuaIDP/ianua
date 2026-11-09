//! List tools: the tenant's registered APIs agents may call.

use std::sync::Arc;

use ianua_domain::domains::agents::execution::tool::AgentTool;
use ianua_domain::domains::authorization::permission::{AgentAction, SystemPermission};
use ianua_domain::isolation::scope::ResolvedTenant;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::agents::ToolStore;
use crate::use_case::Query;

/// The ports [`ListUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ListPorts {
    /// Loads tools.
    pub tool_store: Arc<dyn ToolStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Lists the tools of the caller's tenant.
pub struct ListUseCase {
    ports: ListPorts,
}

impl ListUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: ListPorts) -> Self {
        Self { ports }
    }
}

impl Query for ListUseCase {
    type Caller = CallerContext;
    type Input = ();
    type Output = Result<Vec<AgentTool<ResolvedTenant>>, AppError>;

    /// Every tool the tenant registered, for a caller who may view agents.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not view agents.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        (): (),
    ) -> Result<Vec<AgentTool<ResolvedTenant>>, AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        authority
            .ensure_holds(SystemPermission::Agents(AgentAction::View))
            .map_err(AppError::from_domain)?;
        self.ports
            .tool_store
            .list(&ctx.tenant())
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::agents::{registered_tool, tools_holding};
    use crate::test_support::{block_on, test_ctx};

    fn list(ports: ListPorts) -> Result<Vec<AgentTool<ResolvedTenant>>, AppError> {
        block_on(ListUseCase::new(ports).execute(&test_ctx(), ()))
    }

    fn with_one_tool() -> ListPorts {
        ListPorts {
            tool_store: Arc::new(tools_holding([registered_tool("get_order")])),
            ..ListPorts::fakes()
        }
    }

    /// Ann lists the tools. She sees `get_order`, the one the tenant
    /// registered.
    #[test]
    fn lists_the_tools_the_tenant_registered() {
        let listed = list(with_one_tool()).unwrap();

        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].name().as_str(), "get_order");
    }

    /// A caller without the view right is refused the tenant's tool list.
    #[test]
    fn a_caller_who_may_not_view_agents_is_refused() {
        let ports = ListPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[])),
            ..with_one_tool()
        };

        assert!(matches!(list(ports), Err(AppError::Forbidden(_))));
    }

    /// A signed-out caller cannot list the tenant's registered tools.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let ports = ListPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..with_one_tool()
        };

        assert!(matches!(list(ports), Err(AppError::Unauthenticated)));
    }
}
