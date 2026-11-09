//! Delete model provider: remove a disabled provider for good.
//!
//! A provider is disabled before it goes, so no new run picks it while it
//! goes. Only someone allowed to manage agents deletes one; the domain
//! decides both.

use std::sync::Arc;

use ianua_domain::domains::agents::identity::control::AgentControl;
use ianua_domain::domains::authorization::permission::{AgentAction, SystemPermission};
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::ModelProviderId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::agents::ModelProviderStore;
use crate::use_case::Command;
use crate::use_cases::agents::lookup::existing_model_provider;

/// The ports [`DeleteUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct DeletePorts {
    /// Loads and deletes model providers.
    pub provider_store: Arc<dyn ModelProviderStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Deletes a model provider of the caller's tenant.
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
    type Input = ModelProviderId;
    type Output = Result<(), AppError>;

    /// Deletes the provider `provider_id`, once it is disabled.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not manage agents, before
    ///   any provider is read.
    /// - `AppError::NotFound` when the tenant has no such provider.
    /// - `AppError::Domain` while the provider is still active.
    /// - `AppError::Internal` on persistence or audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        provider_id: ModelProviderId,
    ) -> Result<(), AppError> {
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        authority
            .ensure_holds(SystemPermission::Agents(AgentAction::Manage))
            .map_err(AppError::from_domain)?;
        let mut provider =
            existing_model_provider(self.ports.provider_store.as_ref(), &tenant, &provider_id)
                .await?;
        provider
            .delete(&AgentControl::new(&authority))
            .map_err(AppError::from_domain)?;
        self.ports
            .provider_store
            .delete(&tenant, &provider_id)
            .await
            .or_internal()?;
        auditor
            .dispatch_by(&ctx.actor(), provider.take_events(&tenant))
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
        FakeModelProviderStore, connected_provider, disabled_provider, providers_holding,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    fn delete(
        ports: DeletePorts,
        sink: &Arc<FakeEventDispatcher>,
        provider_id: ModelProviderId,
    ) -> Result<(), AppError> {
        block_on(DeleteUseCase::new(ports).execute(
            &test_ctx(),
            &test_auditor(sink.clone()),
            provider_id,
        ))
    }

    fn ports_over(store: &Arc<FakeModelProviderStore>) -> DeletePorts {
        DeletePorts {
            provider_store: store.clone(),
            ..DeletePorts::fakes()
        }
    }

    /// Ann deletes `prod-deepseek`, which she disabled first. It is gone,
    /// and the delete is recorded.
    #[test]
    fn a_disabled_provider_is_deleted_and_recorded() {
        let provider = disabled_provider(connected_provider("prod-deepseek"));
        let id = *provider.id();
        let store = Arc::new(providers_holding([provider]));
        let sink = Arc::new(FakeEventDispatcher::new());

        delete(ports_over(&store), &sink, id).unwrap();

        assert_eq!(store.count(), 0);
        assert_eq!(
            sink.records.lock().unwrap().as_slice(),
            ["agents.model_provider_deleted"]
        );
    }

    /// Ann deletes `prod-deepseek` while it is still active, so a new run
    /// could pick it. She is refused and it stays.
    #[test]
    fn an_active_provider_is_kept() {
        let provider = connected_provider("prod-deepseek");
        let id = *provider.id();
        let store = Arc::new(providers_holding([provider]));

        let result = delete(
            ports_over(&store),
            &Arc::new(FakeEventDispatcher::new()),
            id,
        );

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert_eq!(store.count(), 1);
    }

    /// Ann deletes a provider the tenant does not have. It is not found.
    #[test]
    fn an_unknown_provider_is_not_found() {
        let store = Arc::new(FakeModelProviderStore::empty());

        let result = delete(
            ports_over(&store),
            &Arc::new(FakeEventDispatcher::new()),
            ModelProviderId::new(),
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A caller with only the view right cannot delete a disabled provider;
    /// the provider stays in the store.
    #[test]
    fn a_caller_who_may_not_manage_agents_is_refused() {
        let provider = disabled_provider(connected_provider("prod-deepseek"));
        let id = *provider.id();
        let store = Arc::new(providers_holding([provider]));
        let ports = DeletePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
                SystemPermission::Agents(AgentAction::View),
            ])),
            ..ports_over(&store)
        };

        let result = delete(ports, &Arc::new(FakeEventDispatcher::new()), id);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(store.count(), 1);
    }

    /// Attempting to delete an unknown provider without management rights
    /// returns forbidden rather than revealing that the id is missing.
    #[test]
    fn a_caller_who_may_not_manage_agents_learns_nothing_of_an_id() {
        let store = Arc::new(FakeModelProviderStore::empty());
        let ports = DeletePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
                SystemPermission::Agents(AgentAction::View),
            ])),
            ..ports_over(&store)
        };

        let result = delete(
            ports,
            &Arc::new(FakeEventDispatcher::new()),
            ModelProviderId::new(),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out caller cannot delete a disabled provider, which remains
    /// stored.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let provider = disabled_provider(connected_provider("prod-deepseek"));
        let id = *provider.id();
        let store = Arc::new(providers_holding([provider]));
        let ports = DeletePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..ports_over(&store)
        };

        let result = delete(ports, &Arc::new(FakeEventDispatcher::new()), id);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(store.count(), 1);
    }
}
