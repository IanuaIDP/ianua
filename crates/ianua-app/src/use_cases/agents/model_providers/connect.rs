//! Connect model provider: register a tenant's own LLM for runs to reason
//! with.
//!
//! The tenant points runs at where their reasoning comes from: a
//! self-hosted OpenAI-compatible endpoint, OpenAI, or Anthropic. Any API key
//! is sealed through the [`SecretEncryptor`] port before the provider is
//! kept, so the raw key never reaches the provider row, a log or an event.
//! The provider is cleared for the most sensitive data runs may send it.
//! Only someone allowed to manage agents connects one.
//!
//! The person who connects a provider is given use of it. Anyone else needs
//! that use shared with them, or to manage agents, before a run of theirs
//! may spend its key.

use std::sync::Arc;

use ianua_domain::domains::agents::authority::capability::ResourceCapability;
use ianua_domain::domains::agents::execution::model_provider::{
    CreateModelProviderParams, ModelEndpoint, ModelName, ModelProvider, ModelProviderKind,
    ProviderKey,
};
use ianua_domain::domains::agents::execution::usage::ModelPricing;
use ianua_domain::domains::agents::identity::control::AgentControl;
use ianua_domain::domains::authorization::authority::TenantAuthority;
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{Label, ModelProviderId};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::agents::{ModelProviderStore, ResourceGrantStore};
use crate::ports::authentication::{SealOwner, SealedField, SealedFor, SecretEncryptor};
use crate::ports::limits::{LimitEnforcer, ResourceKind};
use crate::services::sealing::{opened_text, sealed_text};
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::agents::delegation::resources::usage::grant_use_to_creator;

/// The provider to connect.
pub struct ConnectRequest {
    /// A name people know it by, such as `prod-deepseek`.
    pub name: Label,
    /// The backend kind.
    pub kind: ModelProviderKind,
    /// The base endpoint URL.
    pub endpoint: ModelEndpoint,
    /// The model to request.
    pub model: ModelName,
    /// What the model charges, or that its price is unknown.
    pub pricing: ModelPricing,
    /// The raw API key, or `None` for a keyless self-hosted endpoint.
    pub api_key: Option<Secret>,
    /// The most sensitive data runs may send it.
    pub clearance: DataClassLevel,
}

/// The ports [`ConnectUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ConnectPorts {
    /// Enforces the tenant's plan limit on providers.
    pub limit_enforcer: Arc<dyn LimitEnforcer>,
    /// Keeps the provider.
    pub provider_store: Arc<dyn ModelProviderStore>,
    /// Seals the API key at rest.
    pub encryptor: Arc<dyn SecretEncryptor>,
    /// Gives the connecting person use of the provider.
    pub resource_grants: Arc<dyn ResourceGrantStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Connects a model provider in the caller's tenant.
pub struct ConnectUseCase {
    ports: ConnectPorts,
}

impl ConnectUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: ConnectPorts) -> Self {
        Self { ports }
    }
}

impl Command for ConnectUseCase {
    type Caller = CallerContext;
    type Input = ConnectRequest;
    type Output = Result<ModelProviderId, AppError>;

    /// Connects the provider `req` describes and returns its id.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not manage agents, or the
    ///   plan's model provider limit is reached.
    /// - `AppError::Internal` on encryption, persistence or audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        req: ConnectRequest,
    ) -> Result<ModelProviderId, AppError> {
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        self.ports
            .limit_enforcer
            .check_tenant_limit(ctx.plan_limits(), &tenant, ResourceKind::ModelProviders)
            .await
            .map_err(AppError::from_domain)?;
        let mut provider = connected(&self.ports, &tenant, &authority, req).await?;
        self.ports
            .provider_store
            .save(&tenant, &provider)
            .await
            .or_internal()?;
        grant_use_to_creator(
            self.ports.resource_grants.as_ref(),
            &tenant,
            &authority,
            &ResourceCapability::use_of_provider(provider.id()),
        )
        .await?;
        auditor
            .dispatch_by(&ctx.actor(), provider.take_events(&tenant))
            .await
            .or_internal()?;
        Ok(*provider.id())
    }
}

/// The provider `req` describes for `tenant`, its key sealed, connected by
/// the person `authority` names.
async fn connected(
    ports: &ConnectPorts,
    tenant: &ScopedTenant,
    authority: &TenantAuthority,
    req: ConnectRequest,
) -> Result<ModelProvider<ResolvedTenant>, AppError> {
    let id = ModelProviderId::new();
    let place = key_place(tenant, &id);
    let credential_ref = sealed_key(ports.encryptor.as_ref(), req.api_key.as_ref(), &place).await?;
    let params = CreateModelProviderParams {
        id,
        name: req.name,
        kind: req.kind,
        endpoint: req.endpoint,
        model: req.model,
        pricing: req.pricing,
        credential_ref,
        clearance: req.clearance,
    };
    ModelProvider::create(&AgentControl::new(authority), params).map_err(AppError::from_domain)
}

/// Where `tenant`'s provider `provider` keeps its API key.
pub(crate) fn key_place(tenant: &ScopedTenant, provider: &ModelProviderId) -> SealedFor {
    SealedFor::new(
        SealOwner::from(tenant),
        SealedField::ModelProviderKey,
        provider,
    )
}

/// The API key of `tenant`'s `provider`, opened for one call, or `None`
/// when it takes none.
///
/// # Errors
///
/// `DomainError::Infrastructure` when the key does not open for the
/// provider, or opens to something that is not text.
pub(crate) async fn opened_key(
    encryptor: &dyn SecretEncryptor,
    tenant: &ScopedTenant,
    provider: &ModelProvider<ResolvedTenant>,
) -> Result<Option<Secret>, DomainError> {
    let Some(sealed) = provider.credential_ref().sealed() else {
        return Ok(None);
    };
    let place = key_place(tenant, provider.id());
    opened_text(encryptor, sealed, &place).await.map(Some)
}

/// The API key, sealed for `place`, or keyless when there is none. The
/// raw key is never kept.
///
/// # Errors
///
/// - `AppError::Internal` when the key cannot be sealed.
pub(super) async fn sealed_key(
    encryptor: &dyn SecretEncryptor,
    api_key: Option<&Secret>,
    place: &SealedFor,
) -> Result<ProviderKey, AppError> {
    let Some(key) = api_key else {
        return Ok(ProviderKey::Keyless);
    };
    sealed_text(encryptor, key.expose(), place)
        .await
        .map(ProviderKey::Sealed)
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::agents::execution::model_provider::ModelProviderStatus;
    use ianua_domain::domains::authorization::permission::{AgentAction, SystemPermission};

    use super::*;
    use crate::ports::agents::RelationshipResolver;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::agents::{FakeModelProviderStore, FakeResourceGraph, caller_person};
    use crate::test_support::{
        FakeEventDispatcher, RejectingLimitEnforcer, block_on, test_auditor, test_ctx,
    };

    fn request(api_key: Option<&str>) -> ConnectRequest {
        ConnectRequest {
            name: Label::new("name", "prod-deepseek").unwrap(),
            kind: ModelProviderKind::SelfHosted,
            endpoint: ModelEndpoint::new("http://deepseek.models.svc:8000/v1").unwrap(),
            model: ModelName::new("deepseek-chat").unwrap(),
            pricing: ModelPricing::Unpriced,
            api_key: api_key.map(Secret::new),
            clearance: DataClassLevel::Confidential,
        }
    }

    fn ports_over(store: &Arc<FakeModelProviderStore>) -> ConnectPorts {
        ConnectPorts {
            provider_store: store.clone(),
            ..ConnectPorts::fakes()
        }
    }

    fn connect(
        ports: ConnectPorts,
        sink: &Arc<FakeEventDispatcher>,
        req: ConnectRequest,
    ) -> Result<ModelProviderId, AppError> {
        block_on(ConnectUseCase::new(ports).execute(&test_ctx(), &test_auditor(sink.clone()), req))
    }

    fn stored(
        store: &FakeModelProviderStore,
        id: &ModelProviderId,
    ) -> ModelProvider<ResolvedTenant> {
        block_on(store.find_by_id(&test_ctx().tenant(), id))
            .unwrap()
            .unwrap()
    }

    /// Ann connects `prod-deepseek` with its API key, cleared for
    /// confidential data. It is kept active with the key sealed, never raw,
    /// and the connection is recorded.
    #[test]
    fn a_provider_is_kept_with_its_key_sealed() {
        let store = Arc::new(FakeModelProviderStore::empty());
        let sink = Arc::new(FakeEventDispatcher::new());

        let id = connect(ports_over(&store), &sink, request(Some("sk-secret-123"))).unwrap();

        let provider = stored(&store, &id);
        assert_eq!(provider.status(), ModelProviderStatus::Active);
        assert_eq!(provider.clearance(), DataClassLevel::Confidential);
        let sealed = provider.credential_ref().sealed().unwrap();
        assert!(!sealed.as_str().contains("sk-secret-123"));
        assert_eq!(
            sink.records.lock().unwrap().as_slice(),
            ["agents.model_provider_connected"]
        );
    }

    /// Ann connects a self-hosted endpoint that takes no key. It is kept
    /// keyless.
    #[test]
    fn a_keyless_provider_keeps_no_key() {
        let store = Arc::new(FakeModelProviderStore::empty());

        let id = connect(
            ports_over(&store),
            &Arc::new(FakeEventDispatcher::new()),
            request(None),
        )
        .unwrap();

        assert!(stored(&store, &id).credential_ref().sealed().is_none());
    }

    /// Ann connects a provider. She is given use of it, so her runs may
    /// reason with it before anyone shares it with her.
    #[test]
    fn the_person_who_connects_a_provider_is_given_use_of_it() {
        let graph = Arc::new(FakeResourceGraph::empty());
        let ports = ConnectPorts {
            resource_grants: graph.clone(),
            ..ConnectPorts::fakes()
        };

        let id = connect(ports, &Arc::new(FakeEventDispatcher::new()), request(None)).unwrap();

        let held = block_on(graph.held_subset(
            &test_ctx().tenant(),
            &caller_person().principal(),
            &[ResourceCapability::use_of_provider(&id)],
        ))
        .unwrap();
        assert_eq!(held.len(), 1);
    }

    /// A caller with only the view right cannot connect an endpoint;
    /// neither a provider nor an audit record is created.
    #[test]
    fn a_caller_who_may_not_manage_agents_is_refused() {
        let store = Arc::new(FakeModelProviderStore::empty());
        let sink = Arc::new(FakeEventDispatcher::new());
        let ports = ConnectPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
                SystemPermission::Agents(AgentAction::View),
            ])),
            ..ports_over(&store)
        };

        let result = connect(ports, &sink, request(None));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(store.count(), 0);
        assert!(sink.records.lock().unwrap().is_empty());
    }

    /// A signed-out caller cannot connect a provider, leaving the store empty.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let store = Arc::new(FakeModelProviderStore::empty());
        let ports = ConnectPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..ports_over(&store)
        };

        let result = connect(ports, &Arc::new(FakeEventDispatcher::new()), request(None));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(store.count(), 0);
    }

    /// The tenant's plan allows no more providers. Ann's connection is
    /// refused and nothing is kept.
    #[test]
    fn connect_model_provider_rejects_when_plan_limit_reached() {
        let store = Arc::new(FakeModelProviderStore::empty());
        let ports = ConnectPorts {
            limit_enforcer: Arc::new(RejectingLimitEnforcer),
            ..ports_over(&store)
        };

        let result = connect(ports, &Arc::new(FakeEventDispatcher::new()), request(None));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(store.count(), 0);
    }
}
