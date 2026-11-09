//! Change model provider clearance: set the most sensitive data runs may
//! send a provider.
//!
//! A run is never sent to a provider cleared below what it has read, so a
//! provider's clearance decides which runs may reason with it. Only someone
//! allowed to manage agents changes it.

use std::sync::Arc;

use ianua_domain::domains::agents::identity::control::AgentControl;
use ianua_domain::domains::authorization::permission::{AgentAction, SystemPermission};
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::ModelProviderId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::agents::ModelProviderStore;
use crate::use_case::Command;
use crate::use_cases::agents::lookup::existing_model_provider;

/// Which provider is cleared for what.
pub struct ChangeClearanceRequest {
    /// The configured endpoint whose data ceiling will change.
    pub provider_id: ModelProviderId,
    /// The most sensitive data runs may send it from now on.
    pub clearance: DataClassLevel,
}

/// The ports [`ChangeClearanceUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ChangeClearancePorts {
    /// Loads and saves model providers.
    pub provider_store: Arc<dyn ModelProviderStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Changes what model providers are cleared for.
pub struct ChangeClearanceUseCase {
    ports: ChangeClearancePorts,
}

impl ChangeClearanceUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: ChangeClearancePorts) -> Self {
        Self { ports }
    }
}

impl Command for ChangeClearanceUseCase {
    type Caller = CallerContext;
    type Input = ChangeClearanceRequest;
    type Output = Result<(), AppError>;

    /// Clears the provider for `request.clearance` and keeps it, then
    /// dispatches whatever the provider raised.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not manage agents, before
    ///   any provider is read.
    /// - `AppError::NotFound` when the tenant has no such provider.
    /// - `AppError::Internal` on persistence or audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: ChangeClearanceRequest,
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
        provider
            .change_clearance(&AgentControl::new(&authority), request.clearance)
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

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{AgentAction, SystemPermission};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::agents::{
        FakeModelProviderStore, connected_provider, providers_holding,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// `prod-deepseek`, cleared for internal data, and the store keeping
    /// it.
    fn deepseek() -> (Arc<FakeModelProviderStore>, ModelProviderId) {
        let provider = connected_provider("prod-deepseek");
        let id = *provider.id();
        (Arc::new(providers_holding([provider])), id)
    }

    fn ports_over(store: &Arc<FakeModelProviderStore>) -> ChangeClearancePorts {
        ChangeClearancePorts {
            provider_store: store.clone(),
            ..ChangeClearancePorts::fakes()
        }
    }

    fn clear(
        ports: ChangeClearancePorts,
        provider_id: ModelProviderId,
        clearance: DataClassLevel,
    ) -> Result<(), AppError> {
        clear_into(
            &Arc::new(FakeEventDispatcher::new()),
            ports,
            provider_id,
            clearance,
        )
    }

    fn clear_into(
        sink: &Arc<FakeEventDispatcher>,
        ports: ChangeClearancePorts,
        provider_id: ModelProviderId,
        clearance: DataClassLevel,
    ) -> Result<(), AppError> {
        block_on(ChangeClearanceUseCase::new(ports).execute(
            &test_ctx(),
            &test_auditor(sink.clone()),
            ChangeClearanceRequest {
                provider_id,
                clearance,
            },
        ))
    }

    fn clearance_of(store: &FakeModelProviderStore, id: &ModelProviderId) -> DataClassLevel {
        block_on(store.find_by_id(&test_ctx().tenant(), id))
            .unwrap()
            .unwrap()
            .clearance()
    }

    /// Ann clears the self-hosted `prod-deepseek` for confidential data. It
    /// is kept so, and runs that read confidential data may reason with it.
    #[test]
    fn a_provider_is_cleared_for_more_sensitive_data() {
        let (store, id) = deepseek();

        clear(ports_over(&store), id, DataClassLevel::Confidential).unwrap();

        assert_eq!(clearance_of(&store, &id), DataClassLevel::Confidential);
    }

    /// Ann clears `prod-deepseek` for confidential data. The change is
    /// recorded, so a review sees when runs began sending it more.
    #[test]
    fn a_clearance_change_is_recorded() {
        let (store, id) = deepseek();
        let sink = Arc::new(FakeEventDispatcher::new());

        clear_into(&sink, ports_over(&store), id, DataClassLevel::Confidential).unwrap();

        assert_eq!(
            sink.records.lock().unwrap().as_slice(),
            ["agents.model_provider_clearance_changed"]
        );
    }

    /// Ann changes a provider the tenant does not have. It is not found.
    #[test]
    fn an_unknown_provider_is_not_found() {
        let store = Arc::new(FakeModelProviderStore::empty());

        let result = clear(
            ports_over(&store),
            ModelProviderId::new(),
            DataClassLevel::Public,
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A caller with only the view right cannot raise a provider's data
    /// clearance; it remains limited to internal data.
    #[test]
    fn a_caller_who_may_not_manage_agents_is_refused() {
        let (store, id) = deepseek();
        let ports = ChangeClearancePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
                SystemPermission::Agents(AgentAction::View),
            ])),
            ..ports_over(&store)
        };

        let result = clear(ports, id, DataClassLevel::Restricted);

        assert!(matches!(result, Err(AppError::Forbidden(_))), "{result:?}");
        assert_eq!(clearance_of(&store, &id), DataClassLevel::Internal);
    }

    /// A signed-out caller cannot raise the provider's internal-data clearance.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let (store, id) = deepseek();
        let ports = ChangeClearancePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..ports_over(&store)
        };

        let result = clear(ports, id, DataClassLevel::Restricted);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(clearance_of(&store, &id), DataClassLevel::Internal);
    }
}
