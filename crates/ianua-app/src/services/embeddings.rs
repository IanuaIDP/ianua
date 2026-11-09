//! Turning a text into a memory's vector: through the platform's own
//! embedding server or the tenant's model provider the memory names, with
//! the provider's key opened for the one call, the vector checked against
//! the memory's length.
//!
//! A memory keeps the embedding model it was filled with. If the platform's
//! server now serves another model, or the provider no longer offers that
//! one, the text is refused rather than turned into a vector that would
//! mean nothing beside the memory's others.

use ianua_domain::domains::agents::execution::model_provider::{ModelName, ModelProvider};
use ianua_domain::domains::workflows::memory::entry::{Embedding, MemoryText};
use ianua_domain::domains::workflows::memory::source::{EmbeddingSource, VectorSize};
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;

use crate::error::{AppError, OrInternal, OrNotFound};
use crate::ports::agents::ModelProviderStore;
use crate::ports::authentication::SecretEncryptor;
use crate::ports::workflows::{Embedder, EmbeddingTarget};
use crate::tenancy::ScopedTenant;
use crate::use_cases::agents::model_providers::connect::opened_key;

/// What turns a tenant's texts into vectors.
pub(crate) struct Embeddings<'a> {
    /// The embeddings client.
    pub(crate) embedder: &'a dyn Embedder,
    /// The tenant's model providers.
    pub(crate) providers: &'a dyn ModelProviderStore,
    /// Opens a provider's key.
    pub(crate) encryptor: &'a dyn SecretEncryptor,
    /// The scope used to resolve providers and open their credentials.
    pub(crate) tenant: &'a ScopedTenant,
}

impl Embeddings<'_> {
    /// The raw numbers `source`'s embedding model makes for `text`.
    ///
    /// # Errors
    ///
    /// - `AppError::NotFound` when the provider is gone or disabled.
    /// - `AppError::Domain` when the model is no longer the one offered.
    /// - `AppError::Upstream` when the embedding model does not answer.
    /// - `AppError::Internal` when the store or the key fails.
    pub(crate) async fn raw(
        &self,
        source: &EmbeddingSource,
        text: &MemoryText,
    ) -> Result<Vec<f32>, AppError> {
        let target = self.target(source).await?;
        self.embedder
            .embed(&target, text)
            .await
            .map_err(AppError::upstream)
    }

    /// The vector `source`'s embedding model makes for `text`, as long as a
    /// memory's vectors of `size`.
    ///
    /// # Errors
    ///
    /// As [`Embeddings::raw`], and `AppError::Domain` when the vector is of
    /// another length.
    pub(crate) async fn vector(
        &self,
        source: &EmbeddingSource,
        size: VectorSize,
        text: &MemoryText,
    ) -> Result<Embedding, AppError> {
        let raw = self.raw(source, text).await?;
        Embedding::new(raw, size).map_err(AppError::from_domain)
    }

    /// Where `source`'s embedding model is reached now.
    async fn target(&self, source: &EmbeddingSource) -> Result<EmbeddingTarget, AppError> {
        match source {
            EmbeddingSource::Platform(model) => {
                ensure_offered(model, self.embedder.platform_model().as_ref())?;
                Ok(EmbeddingTarget::Platform(model.clone()))
            }
            EmbeddingSource::Provider { provider_id, model } => {
                let provider = self
                    .providers
                    .find_by_id(self.tenant, provider_id)
                    .await
                    .or_internal()?
                    .filter(ModelProvider::is_active)
                    .or_not_found(message!("workflows-model-provider", "model provider"))?;
                ensure_offered(model, provider.embeddings().model())?;
                let api_key = opened_key(self.encryptor, self.tenant, &provider)
                    .await
                    .or_internal()?;
                Ok(EmbeddingTarget::Provider {
                    endpoint: provider.endpoint().clone(),
                    model: model.clone(),
                    api_key,
                })
            }
        }
    }
}

/// Refuses a memory filled with `kept` when `offered` is another model or
/// none.
fn ensure_offered(kept: &ModelName, offered: Option<&ModelName>) -> Result<(), AppError> {
    if offered == Some(kept) {
        return Ok(());
    }
    Err(AppError::from_domain(DomainError::invalid(message!(
        "workflows-the-memory-s-embedding-model-is-no-longer-offered",
        "the embedding model this memory was filled with is no longer offered, so its texts cannot be compared with new ones"
    ))))
}
