//! Rotate model provider key: give a provider a new API key.
//!
//! A key that leaked, or one the backend is retiring, is replaced. The new
//! key is sealed through the [`SecretEncryptor`] port before the provider
//! is kept, so the raw key never reaches the provider row, a log or an
//! event, and the old one is no longer sent. Only someone allowed to
//! manage agents rotates one.

use std::sync::Arc;

use ianua_domain::domains::agents::execution::model_provider::ProviderKey;
use ianua_domain::domains::agents::identity::control::AgentControl;
use ianua_domain::domains::authorization::permission::{AgentAction, SystemPermission};
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::ModelProviderId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::agents::ModelProviderStore;
use crate::ports::authentication::SecretEncryptor;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::agents::lookup::existing_model_provider;
use crate::use_cases::agents::model_providers::connect::{key_place, sealed_key};

/// Which provider gets which key.
pub struct RotateKeyRequest {
    /// The configured endpoint whose authentication secret will change.
    pub provider_id: ModelProviderId,
    /// The new raw API key, or `None` for a self-hosted endpoint that takes
    /// none.
    pub api_key: Option<Secret>,
}

/// The ports [`RotateKeyUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RotateKeyPorts {
    /// Loads and saves model providers.
    pub provider_store: Arc<dyn ModelProviderStore>,
    /// Seals the new key at rest.
    pub encryptor: Arc<dyn SecretEncryptor>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Gives model providers new API keys.
pub struct RotateKeyUseCase {
    ports: RotateKeyPorts,
}

impl RotateKeyUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: RotateKeyPorts) -> Self {
        Self { ports }
    }

    /// `api_key` sealed for `tenant`'s provider `provider_id`, or keyless
    /// when none is given.
    async fn new_key(
        &self,
        tenant: &ScopedTenant,
        provider_id: &ModelProviderId,
        api_key: Option<&Secret>,
    ) -> Result<ProviderKey, AppError> {
        let place = key_place(tenant, provider_id);
        sealed_key(self.ports.encryptor.as_ref(), api_key, &place).await
    }
}

impl Command for RotateKeyUseCase {
    type Caller = CallerContext;
    type Input = RotateKeyRequest;
    type Output = Result<(), AppError>;

    /// Seals `request.api_key` and calls the provider with it from now on,
    /// recording `agents.model_provider_key_rotated` without the key. The
    /// last test of the provider no longer counts.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `Forbidden` for missing management rights, before reading the provider.
    /// - `AppError::NotFound` when the provider is outside the tenant.
    /// - `AppError::Domain` for a missing required key; `Conflict` for an unchanged key.
    /// - `AppError::Internal` on sealing, persistence or audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: RotateKeyRequest,
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
        let key = self
            .new_key(&tenant, provider.id(), request.api_key.as_ref())
            .await?;
        provider
            .rotate_key(&AgentControl::new(&authority), key)
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
    use ianua_domain::domains::agents::execution::model_provider::{
        CreateModelProviderParams, ModelEndpoint, ModelName, ModelProvider, ModelProviderKind,
        ProviderKey,
    };
    use ianua_domain::domains::agents::execution::usage::ModelPricing;
    use ianua_domain::domains::authorization::permission::{AgentAction, SystemPermission};
    use ianua_domain::domains::data_classification::level::DataClassLevel;
    use ianua_domain::isolation::scope::ResolvedTenant;
    use ianua_domain::types::{Label, SealedSecret};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::agents::{
        FakeModelProviderStore, agent_manager, providers_holding, someone_else,
    };
    use crate::test_support::authentication::FakeEncryptor;
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// The OpenAI provider `prod-openai`, holding a sealed key, and the
    /// store keeping it.
    fn openai() -> (Arc<FakeModelProviderStore>, ModelProviderId) {
        let manager = agent_manager(someone_else());
        let id = ModelProviderId::new();
        let provider = ModelProvider::create(
            &AgentControl::new(&manager),
            CreateModelProviderParams {
                id,
                name: Label::new("name", "prod-openai").unwrap(),
                kind: ModelProviderKind::OpenAi,
                endpoint: ModelEndpoint::new("https://api.openai.com/v1").unwrap(),
                model: ModelName::new("gpt-4o").unwrap(),
                pricing: ModelPricing::Unpriced,
                credential_ref: ProviderKey::Sealed(sealed_as(&id, "sk-old")),
                clearance: DataClassLevel::Internal,
            },
        )
        .unwrap();
        let id = *provider.id();
        (Arc::new(providers_holding([provider])), id)
    }

    fn ports_over(store: &Arc<FakeModelProviderStore>) -> RotateKeyPorts {
        RotateKeyPorts {
            provider_store: store.clone(),
            encryptor: Arc::new(FakeEncryptor),
            ..RotateKeyPorts::fakes()
        }
    }

    fn rotate(
        ports: RotateKeyPorts,
        sink: &Arc<FakeEventDispatcher>,
        provider_id: ModelProviderId,
        api_key: Option<&str>,
    ) -> Result<(), AppError> {
        block_on(RotateKeyUseCase::new(ports).execute(
            &test_ctx(),
            &test_auditor(sink.clone()),
            RotateKeyRequest {
                provider_id,
                api_key: api_key.map(Secret::new),
            },
        ))
    }

    fn stored(
        store: &FakeModelProviderStore,
        id: &ModelProviderId,
    ) -> ModelProvider<ResolvedTenant> {
        block_on(store.find_by_id(&test_ctx().tenant(), id))
            .unwrap()
            .unwrap()
    }

    /// `key` as the fake seals it for the test tenant's provider `id`.
    fn sealed_as(id: &ModelProviderId, key: &str) -> SealedSecret {
        FakeEncryptor::sealed_for(key, &key_place(&test_ctx().tenant(), id))
    }

    fn sealed_of(store: &FakeModelProviderStore, id: &ModelProviderId) -> SealedSecret {
        stored(store, id).credential_ref().sealed().unwrap().clone()
    }

    /// Ann rotates the leaked key of `prod-openai`. The provider holds the
    /// new key sealed, never raw, and the rotation is recorded.
    #[test]
    fn a_rotated_key_is_kept_sealed_and_recorded() {
        let (store, id) = openai();
        let sink = Arc::new(FakeEventDispatcher::new());

        rotate(ports_over(&store), &sink, id, Some("sk-new")).unwrap();

        assert_eq!(sealed_of(&store, &id), sealed_as(&id, "sk-new"));
        assert_eq!(
            sink.records.lock().unwrap().as_slice(),
            ["agents.model_provider_key_rotated"]
        );
    }

    /// OpenAI always takes a key. Taking it away is refused and the old
    /// key stays.
    #[test]
    fn a_provider_that_takes_a_key_keeps_one() {
        let (store, id) = openai();

        let result = rotate(
            ports_over(&store),
            &Arc::new(FakeEventDispatcher::new()),
            id,
            None,
        );

        assert!(matches!(result, Err(AppError::Domain(_))), "{result:?}");
        assert_eq!(sealed_of(&store, &id), sealed_as(&id, "sk-old"));
    }

    /// Ann rotates the key of a provider the tenant does not have. It is
    /// not found.
    #[test]
    fn an_unknown_provider_is_not_found() {
        let store = Arc::new(FakeModelProviderStore::empty());

        let result = rotate(
            ports_over(&store),
            &Arc::new(FakeEventDispatcher::new()),
            ModelProviderId::new(),
            Some("sk-new"),
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// The view right does not authorize replacing a provider key; the
    /// original sealed key remains and no rotation is recorded.
    #[test]
    fn a_caller_who_may_not_manage_agents_is_refused() {
        let (store, id) = openai();
        let sink = Arc::new(FakeEventDispatcher::new());
        let ports = RotateKeyPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
                SystemPermission::Agents(AgentAction::View),
            ])),
            ..ports_over(&store)
        };

        let result = rotate(ports, &sink, id, Some("sk-sams"));

        assert!(matches!(result, Err(AppError::Forbidden(_))), "{result:?}");
        assert_eq!(sealed_of(&store, &id), sealed_as(&id, "sk-old"));
        assert!(sink.records.lock().unwrap().is_empty());
    }

    /// A signed-out caller cannot rotate the key, and the original sealed
    /// value stays stored.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let (store, id) = openai();
        let ports = RotateKeyPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..ports_over(&store)
        };

        let result = rotate(
            ports,
            &Arc::new(FakeEventDispatcher::new()),
            id,
            Some("sk-new"),
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(sealed_of(&store, &id), sealed_as(&id, "sk-old"));
    }
}
