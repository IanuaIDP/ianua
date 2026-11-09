//! List model providers: the LLMs the tenant connected for runs.

use std::sync::Arc;

use ianua_domain::domains::agents::execution::model_provider::ModelProvider;
use ianua_domain::domains::authorization::permission::{AgentAction, SystemPermission};
use ianua_domain::isolation::scope::ResolvedTenant;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::agents::ModelProviderStore;
use crate::use_case::Query;

/// The ports [`ListUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ListPorts {
    /// Loads providers.
    pub provider_store: Arc<dyn ModelProviderStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Lists the model providers of the caller's tenant.
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
    type Output = Result<Vec<ModelProvider<ResolvedTenant>>, AppError>;

    /// Every provider the tenant connected, for a caller who may view
    /// agents.
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
    ) -> Result<Vec<ModelProvider<ResolvedTenant>>, AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        authority
            .ensure_holds(SystemPermission::Agents(AgentAction::View))
            .map_err(AppError::from_domain)?;
        self.ports
            .provider_store
            .list(&ctx.tenant())
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::agents::{connected_provider, providers_holding};
    use crate::test_support::{block_on, test_ctx};

    fn list(ports: ListPorts) -> Result<Vec<ModelProvider<ResolvedTenant>>, AppError> {
        block_on(ListUseCase::new(ports).execute(&test_ctx(), ()))
    }

    fn with_one_provider() -> ListPorts {
        ListPorts {
            provider_store: Arc::new(providers_holding([connected_provider("prod-deepseek")])),
            ..ListPorts::fakes()
        }
    }

    /// Ann lists the providers. She sees `prod-deepseek`, the one the
    /// tenant connected.
    #[test]
    fn lists_the_providers_the_tenant_connected() {
        let listed = list(with_one_provider()).unwrap();

        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].name().as_str(), "prod-deepseek");
    }

    /// A caller without the agent view right is refused the provider list.
    #[test]
    fn a_caller_who_may_not_view_agents_is_refused() {
        let ports = ListPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[])),
            ..with_one_provider()
        };

        assert!(matches!(list(ports), Err(AppError::Forbidden(_))));
    }

    /// A signed-out caller cannot list connected model providers.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let ports = ListPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..with_one_provider()
        };

        assert!(matches!(list(ports), Err(AppError::Unauthenticated)));
    }
}
