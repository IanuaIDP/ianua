//! Change model provider model: point a provider at another model, or
//! change what it charges.
//!
//! A tenant moves to a newer model or puts a price on the one it has, so
//! runs under a spend limit can tell what they spend. A new model has not
//! been tested, so the provider's last test no longer counts. Only someone
//! allowed to manage agents changes it.

use std::sync::Arc;

use ianua_domain::domains::agents::execution::model_provider::{ModelChange, ModelName};
use ianua_domain::domains::agents::execution::usage::ModelPricing;
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

/// Which provider asks for which model, at which price.
pub struct ChangeModelRequest {
    /// The configured endpoint whose requested model will change.
    pub provider_id: ModelProviderId,
    /// The model to request from now on.
    pub model: ModelName,
    /// What it charges, or that its price is unknown.
    pub pricing: ModelPricing,
}

/// The ports [`ChangeModelUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ChangeModelPorts {
    /// Loads and saves model providers.
    pub provider_store: Arc<dyn ModelProviderStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Changes the model and price model providers ask for.
pub struct ChangeModelUseCase {
    ports: ChangeModelPorts,
}

impl ChangeModelUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: ChangeModelPorts) -> Self {
        Self { ports }
    }
}

impl Command for ChangeModelUseCase {
    type Caller = CallerContext;
    type Input = ChangeModelRequest;
    type Output = Result<(), AppError>;

    /// Points the provider at `request.model` at `request.pricing` and
    /// records `agents.model_provider_model_changed`, naming both models.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not manage agents, before
    ///   any provider is read.
    /// - `AppError::NotFound` when the tenant has no such provider.
    /// - `AppError::Conflict` when it names the model and price the
    ///   provider has.
    /// - `AppError::Internal` on persistence or audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: ChangeModelRequest,
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
        let change = ModelChange {
            model: request.model,
            pricing: request.pricing,
        };
        provider
            .change_model(&AgentControl::new(&authority), change)
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
    use ianua_domain::domains::agents::execution::model_provider::ModelProvider;
    use ianua_domain::domains::agents::execution::usage::Spend;
    use ianua_domain::domains::authorization::permission::{AgentAction, SystemPermission};
    use ianua_domain::isolation::scope::ResolvedTenant;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::agents::{
        FakeModelProviderStore, connected_provider, providers_holding,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// `prod-deepseek`, asking for `deepseek-chat` with no price, and the
    /// store keeping it.
    fn deepseek() -> (Arc<FakeModelProviderStore>, ModelProviderId) {
        let provider = connected_provider("prod-deepseek");
        let id = *provider.id();
        (Arc::new(providers_holding([provider])), id)
    }

    /// What DeepSeek charges per million tokens for its newer model.
    fn v3_pricing() -> ModelPricing {
        ModelPricing::PerMillionTokens {
            input: Spend::from_micros(270_000),
            output: Spend::from_micros(1_100_000),
        }
    }

    fn change(
        ports: ChangeModelPorts,
        sink: &Arc<FakeEventDispatcher>,
        provider_id: ModelProviderId,
        model: &str,
    ) -> Result<(), AppError> {
        block_on(ChangeModelUseCase::new(ports).execute(
            &test_ctx(),
            &test_auditor(sink.clone()),
            ChangeModelRequest {
                provider_id,
                model: ModelName::new(model).unwrap(),
                pricing: v3_pricing(),
            },
        ))
    }

    fn ports_over(store: &Arc<FakeModelProviderStore>) -> ChangeModelPorts {
        ChangeModelPorts {
            provider_store: store.clone(),
            ..ChangeModelPorts::fakes()
        }
    }

    fn stored(
        store: &FakeModelProviderStore,
        id: &ModelProviderId,
    ) -> ModelProvider<ResolvedTenant> {
        block_on(store.find_by_id(&test_ctx().tenant(), id))
            .unwrap()
            .unwrap()
    }

    /// Ann moves `prod-deepseek` to `deepseek-v3` with its price. The
    /// provider asks for that model at that price, and the change is
    /// recorded.
    #[test]
    fn a_provider_moves_to_a_new_model_and_price() {
        let (store, id) = deepseek();
        let sink = Arc::new(FakeEventDispatcher::new());

        change(ports_over(&store), &sink, id, "deepseek-v3").unwrap();

        let provider = stored(&store, &id);
        assert_eq!(provider.model().as_str(), "deepseek-v3");
        assert_eq!(provider.pricing(), v3_pricing());
        assert_eq!(
            sink.records.lock().unwrap().as_slice(),
            ["agents.model_provider_model_changed"]
        );
    }

    /// Ann changes a provider the tenant does not have. It is not found.
    #[test]
    fn an_unknown_provider_is_not_found() {
        let store = Arc::new(FakeModelProviderStore::empty());

        let result = change(
            ports_over(&store),
            &Arc::new(FakeEventDispatcher::new()),
            ModelProviderId::new(),
            "deepseek-v3",
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// The view right alone cannot change a provider's model; the original
    /// model remains stored and no change is recorded.
    #[test]
    fn a_caller_who_may_not_manage_agents_is_refused() {
        let (store, id) = deepseek();
        let sink = Arc::new(FakeEventDispatcher::new());
        let ports = ChangeModelPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
                SystemPermission::Agents(AgentAction::View),
            ])),
            ..ports_over(&store)
        };

        let result = change(ports, &sink, id, "uncleared");

        assert!(matches!(result, Err(AppError::Forbidden(_))), "{result:?}");
        assert_eq!(stored(&store, &id).model().as_str(), "deepseek-chat");
        assert!(sink.records.lock().unwrap().is_empty());
    }

    /// A signed-out caller cannot replace the provider's stored model.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let (store, id) = deepseek();
        let ports = ChangeModelPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..ports_over(&store)
        };

        let result = change(
            ports,
            &Arc::new(FakeEventDispatcher::new()),
            id,
            "deepseek-v3",
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(stored(&store, &id).model().as_str(), "deepseek-chat");
    }
}
