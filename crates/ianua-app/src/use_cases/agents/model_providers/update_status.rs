//! Update model provider status: turn a provider on or off.
//!
//! A disabled provider is kept, but no new run picks it. Only someone
//! allowed to manage agents turns one on or off.

use std::sync::Arc;

use ianua_domain::domains::agents::execution::model_provider::{
    ModelProvider, ModelProviderStatus,
};
use ianua_domain::domains::agents::identity::control::AgentControl;
use ianua_domain::domains::authorization::permission::{AgentAction, SystemPermission};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::ModelProviderId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::agents::ModelProviderStore;
use crate::use_case::Command;
use crate::use_cases::agents::lookup::existing_model_provider;

/// The ports [`UpdateStatusUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct UpdateStatusPorts {
    /// Loads and saves model providers.
    pub provider_store: Arc<dyn ModelProviderStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Which provider to change, and the status it should have.
pub struct UpdateStatusRequest {
    /// The provider to turn on or off.
    pub provider_id: ModelProviderId,
    /// The status the provider should end up in.
    pub status: ModelProviderStatus,
}

/// Turns a model provider of the caller's tenant on or off.
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

    /// Moves the provider to the status `request` asks for.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not manage agents, before
    ///   any provider is read.
    /// - `AppError::NotFound` when the tenant has no such provider.
    /// - `AppError::Domain` when the provider already has that status.
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
        let mut provider = existing_model_provider(
            self.ports.provider_store.as_ref(),
            &tenant,
            &request.provider_id,
        )
        .await?;
        move_to(
            &mut provider,
            &AgentControl::new(&authority),
            request.status,
        )
        .map_err(AppError::from_domain)?;
        self.ports
            .provider_store
            .save(&tenant, &provider)
            .await
            .or_internal()?;
        auditor
            .dispatch_by(&ctx.actor(), provider.take_events(&tenant))
            .await
            .or_internal()?;
        Ok(())
    }
}

/// Moves `provider` to `status`, as the person `control` names.
fn move_to(
    provider: &mut ModelProvider<ResolvedTenant>,
    control: &AgentControl<'_>,
    status: ModelProviderStatus,
) -> Result<(), DomainError> {
    match status {
        ModelProviderStatus::Active => provider.enable(control),
        ModelProviderStatus::Disabled => provider.disable(control),
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{AgentAction, SystemPermission};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::agents::{
        FakeModelProviderStore, connected_provider, providers_holding,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    fn change(
        ports: UpdateStatusPorts,
        sink: &Arc<FakeEventDispatcher>,
        provider_id: ModelProviderId,
        status: ModelProviderStatus,
    ) -> Result<(), AppError> {
        block_on(UpdateStatusUseCase::new(ports).execute(
            &test_ctx(),
            &test_auditor(sink.clone()),
            UpdateStatusRequest {
                provider_id,
                status,
            },
        ))
    }

    fn ports_over(store: &Arc<FakeModelProviderStore>) -> UpdateStatusPorts {
        UpdateStatusPorts {
            provider_store: store.clone(),
            ..UpdateStatusPorts::fakes()
        }
    }

    fn is_active(store: &FakeModelProviderStore, id: &ModelProviderId) -> bool {
        block_on(store.find_by_id(&test_ctx().tenant(), id))
            .unwrap()
            .unwrap()
            .is_active()
    }

    /// Ann turns `prod-deepseek` off and back on. Each change is kept and
    /// recorded.
    #[test]
    fn a_provider_is_turned_off_and_back_on() {
        let provider = connected_provider("prod-deepseek");
        let id = *provider.id();
        let store = Arc::new(providers_holding([provider]));
        let sink = Arc::new(FakeEventDispatcher::new());

        change(ports_over(&store), &sink, id, ModelProviderStatus::Disabled).unwrap();
        assert!(!is_active(&store, &id));
        change(ports_over(&store), &sink, id, ModelProviderStatus::Active).unwrap();

        assert!(is_active(&store, &id));
        assert_eq!(
            sink.records.lock().unwrap().as_slice(),
            [
                "agents.model_provider_status_changed",
                "agents.model_provider_status_changed"
            ]
        );
    }

    /// Ann turns off a provider the tenant does not have. It is not found.
    #[test]
    fn an_unknown_provider_is_not_found() {
        let store = Arc::new(FakeModelProviderStore::empty());

        let result = change(
            ports_over(&store),
            &Arc::new(FakeEventDispatcher::new()),
            ModelProviderId::new(),
            ModelProviderStatus::Disabled,
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A caller with only the view right cannot disable a provider, which
    /// remains active.
    #[test]
    fn a_caller_who_may_not_manage_agents_is_refused() {
        let provider = connected_provider("prod-deepseek");
        let id = *provider.id();
        let store = Arc::new(providers_holding([provider]));
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
            ModelProviderStatus::Disabled,
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(is_active(&store, &id));
    }

    /// A signed-out caller cannot disable the active provider.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let provider = connected_provider("prod-deepseek");
        let id = *provider.id();
        let store = Arc::new(providers_holding([provider]));
        let ports = UpdateStatusPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..ports_over(&store)
        };

        let result = change(
            ports,
            &Arc::new(FakeEventDispatcher::new()),
            id,
            ModelProviderStatus::Disabled,
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert!(is_active(&store, &id));
    }
}
