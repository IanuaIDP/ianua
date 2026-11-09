//! Create memory: a person makes a named memory filled by the platform's
//! embedding server or one of the tenant's model providers.
//!
//! The embedding model is asked once for a vector, so the memory keeps the
//! length its vectors have from the start. A provider must offer an
//! embedding model and be cleared for the data the memory may hold, since
//! every text kept is sent to it. Only someone who may create workflows
//! makes one, and the tenant's plan caps how many it holds.

use std::sync::Arc;

use ianua_domain::domains::agents::execution::model_provider::ModelProvider;
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::domains::workflows::control::WorkflowControl;
use ianua_domain::domains::workflows::memory::entry::MemoryText;
use ianua_domain::domains::workflows::memory::source::{EmbeddingSource, VectorSize};
use ianua_domain::domains::workflows::memory::{CreateMemoryParams, Memory};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{Label, ModelProviderId};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal, OrNotFound};
use crate::ports::agents::ModelProviderStore;
use crate::ports::authentication::SecretEncryptor;
use crate::ports::limits::{LimitEnforcer, ResourceKind};
use crate::ports::workflows::{Embedder, MemoryStore};
use crate::services::embeddings::Embeddings;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;

/// The text the embedding model is asked for once, to learn how long its
/// vectors are.
const SIZE_PROBE: &str = "How long are this model's vectors?";

/// Where a new memory's vectors come from, as a person picks it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemorySourceChoice {
    /// The platform's own embedding server.
    Platform,
    /// The tenant's model provider, through the embedding model it offers.
    Provider(ModelProviderId),
}

/// A new memory, as a person names it.
#[derive(Debug)]
pub struct CreateRequest {
    /// The label people use to recognize this searchable collection.
    pub name: Label,
    /// Where its vectors come from.
    pub source: MemorySourceChoice,
    /// The most sensitive data its texts may hold.
    pub clearance: DataClassLevel,
}

/// The ports [`CreateUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct CreatePorts {
    /// Keeps the memories.
    pub memories: Arc<dyn MemoryStore>,
    /// Turns texts into vectors.
    pub embedder: Arc<dyn Embedder>,
    /// The tenant's model providers.
    pub providers: Arc<dyn ModelProviderStore>,
    /// Opens a provider's key.
    pub encryptor: Arc<dyn SecretEncryptor>,
    /// Checks the plan's memory limit.
    pub limit_enforcer: Arc<dyn LimitEnforcer>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Makes memories.
pub struct CreateUseCase {
    ports: CreatePorts,
}

impl CreateUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: CreatePorts) -> Self {
        Self { ports }
    }

    /// The values a memory is made with: where its vectors come from, and
    /// how long its embedding model makes them.
    async fn params_of(
        &self,
        tenant: &ScopedTenant,
        request: CreateRequest,
    ) -> Result<CreateMemoryParams, AppError> {
        let source = self
            .source_of(tenant, request.source, request.clearance)
            .await?;
        let vector_size = self.size_of(tenant, &source).await?;
        Ok(CreateMemoryParams {
            name: request.name,
            source,
            vector_size,
            clearance: request.clearance,
        })
    }

    /// The embedding source `choice` names, with its model as offered now,
    /// for a memory cleared for `clearance`.
    async fn source_of(
        &self,
        tenant: &ScopedTenant,
        choice: MemorySourceChoice,
        clearance: DataClassLevel,
    ) -> Result<EmbeddingSource, AppError> {
        let MemorySourceChoice::Provider(id) = choice else {
            return self
                .ports
                .embedder
                .platform_model()
                .map(EmbeddingSource::Platform)
                .ok_or_else(no_platform_server);
        };
        let provider = self
            .ports
            .providers
            .find_by_id(tenant, &id)
            .await
            .or_internal()?
            .filter(ModelProvider::is_active)
            .or_not_found(message!("workflows-model-provider", "model provider"))?;
        ensure_provider_clears(&provider, clearance)?;
        let model = provider
            .embeddings()
            .model()
            .cloned()
            .ok_or_else(no_embedding_model)?;
        Ok(EmbeddingSource::Provider {
            provider_id: id,
            model,
        })
    }

    /// How long `source`'s vectors are, asking its embedding model once.
    async fn size_of(
        &self,
        tenant: &ScopedTenant,
        source: &EmbeddingSource,
    ) -> Result<VectorSize, AppError> {
        let embeddings = Embeddings {
            embedder: self.ports.embedder.as_ref(),
            providers: self.ports.providers.as_ref(),
            encryptor: self.ports.encryptor.as_ref(),
            tenant,
        };
        let probe = MemoryText::new(SIZE_PROBE)
            .map_err(|rule| AppError::from_domain(DomainError::Validation(rule)))?;
        let raw = embeddings.raw(source, &probe).await?;
        u16::try_from(raw.len())
            .ok()
            .and_then(|size| VectorSize::new(size).ok())
            .ok_or_else(|| {
                AppError::from_domain(DomainError::invalid(message!(
                    "workflows-the-embedding-model-makes-no-usable-vector",
                    "the embedding model makes vectors of a length no memory keeps"
                )))
            })
    }
}

impl Command for CreateUseCase {
    type Caller = CallerContext;
    type Input = CreateRequest;
    type Output = Result<Memory<ResolvedTenant>, AppError>;

    /// Makes a memory for the person `ctx` names, and records it.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the plan's memory limit is reached, the
    ///   caller may not create workflows, or the provider is not cleared
    ///   for the memory's data.
    /// - `AppError::NotFound` when the provider is gone or disabled.
    /// - `AppError::Domain` when the platform runs no embedding server or
    ///   the provider offers no embedding model.
    /// - `AppError::Internal` when the embedding model, storage or the
    ///   audit trail fails.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: CreateRequest,
    ) -> Result<Memory<ResolvedTenant>, AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let tenant = ctx.tenant();
        self.ports
            .limit_enforcer
            .check_tenant_limit(ctx.plan_limits(), &tenant, ResourceKind::Memories)
            .await
            .map_err(AppError::from_domain)?;
        let params = self.params_of(&tenant, request).await?;
        let mut memory = Memory::create(params, &WorkflowControl::new(&authority))
            .map_err(AppError::from_domain)?;
        self.ports
            .memories
            .save(&tenant, &memory)
            .await
            .map_err(AppError::from_domain)?;
        auditor
            .dispatch_by(&ctx.actor(), memory.take_events(&tenant))
            .await
            .or_internal()?;
        Ok(memory)
    }
}

/// Refuses a provider not cleared for data as sensitive as the memory may
/// hold: every text kept is sent to it.
fn ensure_provider_clears(
    provider: &ModelProvider<ResolvedTenant>,
    clearance: DataClassLevel,
) -> Result<(), AppError> {
    if clearance <= provider.clearance() {
        return Ok(());
    }
    Err(AppError::from_domain(DomainError::forbidden(message!(
        "workflows-the-provider-is-not-cleared-for-the-memory",
        "the model provider is not cleared for data as sensitive as this memory may hold"
    ))))
}

/// The refusal of the platform's server where the deployment runs none.
fn no_platform_server() -> AppError {
    AppError::from_domain(DomainError::invalid(message!(
        "workflows-the-platform-runs-no-embedding-server",
        "this deployment runs no embedding server; pick a model provider that offers an embedding model"
    )))
}

/// The refusal of a provider offering no embedding model.
fn no_embedding_model() -> AppError {
    AppError::from_domain(DomainError::invalid(message!(
        "workflows-the-provider-offers-no-embedding-model",
        "the model provider offers no embedding model"
    )))
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{SystemPermission, WorkflowAction};
    use ianua_domain::domains::workflows::memory::MemoryStatus;

    use super::*;
    use crate::test_support::acting::FakeTenantAuthorities;
    use crate::test_support::agents::{
        FakeModelProviderStore, connected_provider, embedding_provider, providers_holding,
    };
    use crate::test_support::authentication::FakeEncryptor;
    use crate::test_support::workflows::{
        FAKE_VECTOR_SIZE, FakeEmbedder, FakeMemoryStore, PLATFORM_MODEL,
    };
    use crate::test_support::{
        FakeEventDispatcher, FakeLimitEnforcer, RejectingLimitEnforcer, block_on, test_auditor,
        test_ctx,
    };

    struct Fixture {
        memories: Arc<FakeMemoryStore>,
        sink: Arc<FakeEventDispatcher>,
        use_case: CreateUseCase,
    }

    fn fixture(embedder: FakeEmbedder, providers: FakeModelProviderStore) -> Fixture {
        let memories = Arc::new(FakeMemoryStore::empty());
        Fixture {
            use_case: CreateUseCase::new(CreatePorts {
                memories: memories.clone(),
                embedder: Arc::new(embedder),
                providers: Arc::new(providers),
                encryptor: Arc::new(FakeEncryptor),
                limit_enforcer: Arc::new(FakeLimitEnforcer),
                tenant_authorities: Arc::new(creator()),
            }),
            memories,
            sink: Arc::new(FakeEventDispatcher::new()),
        }
    }

    fn creator() -> FakeTenantAuthorities {
        FakeTenantAuthorities::holding(&[SystemPermission::Workflows(WorkflowAction::Create)])
    }

    fn request(source: MemorySourceChoice, clearance: DataClassLevel) -> CreateRequest {
        CreateRequest {
            name: Label::new("name", "Support tickets").unwrap(),
            source,
            clearance,
        }
    }

    fn run(f: &Fixture, request: CreateRequest) -> Result<Memory<ResolvedTenant>, AppError> {
        block_on(
            f.use_case
                .execute(&test_ctx(), &test_auditor(f.sink.clone()), request),
        )
    }

    /// Ann makes a memory on the platform's embedding server: it keeps the
    /// server's model and the length its vectors have, and the trail records
    /// it.
    #[test]
    fn a_memory_on_the_platform_server_keeps_its_model_and_length() {
        let f = fixture(
            FakeEmbedder::with_platform(),
            FakeModelProviderStore::empty(),
        );

        let memory = run(
            &f,
            request(MemorySourceChoice::Platform, DataClassLevel::Internal),
        )
        .unwrap();

        assert_eq!(memory.source().model().as_str(), PLATFORM_MODEL);
        assert_eq!(memory.vector_size().get(), FAKE_VECTOR_SIZE);
        assert_eq!(memory.status(), MemoryStatus::Active);
        assert_eq!(f.memories.kept().len(), 1);
        assert_eq!(
            *f.sink.records.lock().unwrap(),
            ["workflows.memory_created"]
        );
    }

    /// Ann makes a memory on the tenant's OpenAI provider, which offers
    /// `text-embedding-3-small`: it is filled through that model.
    #[test]
    fn a_memory_on_a_provider_uses_its_embedding_model() {
        let provider = embedding_provider(connected_provider("openai"));
        let id = *provider.id();
        let f = fixture(
            FakeEmbedder::without_platform(),
            providers_holding([provider]),
        );

        let memory = run(
            &f,
            request(MemorySourceChoice::Provider(id), DataClassLevel::Internal),
        )
        .unwrap();

        assert_eq!(memory.source().model().as_str(), "text-embedding-3-small");
    }

    /// Choosing platform embeddings without a configured server is refused,
    /// leaving no memory stored.
    #[test]
    fn the_platform_server_is_refused_where_none_runs() {
        let f = fixture(
            FakeEmbedder::without_platform(),
            FakeModelProviderStore::empty(),
        );

        let made = run(
            &f,
            request(MemorySourceChoice::Platform, DataClassLevel::Internal),
        );

        assert!(matches!(made, Err(AppError::Domain(_))), "{made:?}");
        assert!(f.memories.kept().is_empty());
    }

    /// A chat-only provider cannot supply the embedding model a memory needs.
    #[test]
    fn a_provider_without_an_embedding_model_is_refused() {
        let provider = connected_provider("deepseek");
        let id = *provider.id();
        let f = fixture(FakeEmbedder::with_platform(), providers_holding([provider]));

        let made = run(
            &f,
            request(MemorySourceChoice::Provider(id), DataClassLevel::Internal),
        );

        assert!(matches!(made, Err(AppError::Domain(_))), "{made:?}");
    }

    /// A provider cleared only for internal data cannot back a memory cleared
    /// for confidential texts.
    #[test]
    fn a_provider_not_cleared_for_the_memory_is_refused() {
        let provider = embedding_provider(connected_provider("openai"));
        let id = *provider.id();
        let f = fixture(FakeEmbedder::with_platform(), providers_holding([provider]));

        let made = run(
            &f,
            request(
                MemorySourceChoice::Provider(id),
                DataClassLevel::Confidential,
            ),
        );

        assert!(matches!(made, Err(AppError::Forbidden(_))), "{made:?}");
    }

    /// A model that does not answer is told as an outside failure, and leaves
    /// no memory stored with an unknown vector length.
    #[test]
    fn no_memory_is_made_when_the_embedding_model_does_not_answer() {
        let f = fixture(FakeEmbedder::failing(), FakeModelProviderStore::empty());

        let made = run(
            &f,
            request(MemorySourceChoice::Platform, DataClassLevel::Internal),
        );

        assert!(matches!(made, Err(AppError::Upstream(_))), "{made:?}");
        assert!(f.memories.kept().is_empty());
    }

    /// A plan-limit refusal prevents both memory persistence and its creation
    /// audit record.
    #[test]
    fn the_plan_s_memory_limit_refuses_another() {
        let mut f = fixture(
            FakeEmbedder::with_platform(),
            FakeModelProviderStore::empty(),
        );
        f.use_case.ports.limit_enforcer = Arc::new(RejectingLimitEnforcer);

        let made = run(
            &f,
            request(MemorySourceChoice::Platform, DataClassLevel::Internal),
        );

        assert!(matches!(made, Err(AppError::Forbidden(_))), "{made:?}");
        assert!(f.memories.kept().is_empty());
        assert!(f.sink.records.lock().unwrap().is_empty());
    }

    /// A caller holding no workflow rights is forbidden from creating a memory.
    #[test]
    fn a_viewer_makes_no_memory() {
        let mut f = fixture(
            FakeEmbedder::with_platform(),
            FakeModelProviderStore::empty(),
        );
        f.use_case.ports.tenant_authorities = Arc::new(FakeTenantAuthorities::holding(&[]));

        let made = run(
            &f,
            request(MemorySourceChoice::Platform, DataClassLevel::Internal),
        );

        assert!(matches!(made, Err(AppError::Forbidden(_))), "{made:?}");
    }
}
