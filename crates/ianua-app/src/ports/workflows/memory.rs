//! Memory: where a tenant's memories are kept, the vector store holding
//! the texts they keep with their vectors, and the embeddings client that
//! turns a text into a vector through a memory's embedding model.

use std::fmt;

use async_trait::async_trait;
use ianua_domain::domains::agents::execution::model_provider::{ModelEndpoint, ModelName};
use ianua_domain::domains::workflows::memory::Memory;
use ianua_domain::domains::workflows::memory::entry::{
    Embedding, EntryPage, FoundCount, FoundEntry, MemoryEntry, MemoryText, PageStart,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{MemoryId, TenantId};
use time::OffsetDateTime;

use crate::ports::TenantScoped;
use crate::tenancy::ScopedTenant;

/// Dyn-safe port keeping a tenant's memories: their names, embedding
/// models and whether they wait to be deleted, never their texts.
#[async_trait]
pub trait MemoryStore: Send + Sync + TenantScoped {
    /// The tenant's memory `id`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &MemoryId,
    ) -> Result<Option<Memory<ResolvedTenant>>, DomainError>;

    /// Every memory of the tenant's, by name, those waiting to be deleted
    /// among them.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn list(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<Vec<Memory<ResolvedTenant>>, DomainError>;

    /// Saves a new or changed memory.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        memory: &Memory<ResolvedTenant>,
    ) -> Result<(), DomainError>;

    /// Deletes memory `id`, once its texts are gone and its waiting period
    /// is over. Deleting one already gone does nothing.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn delete(&self, tenant_id: &ScopedTenant, id: &MemoryId) -> Result<(), DomainError>;

    /// The tenant's memories whose waiting period is over at `now`, at
    /// most `limit`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn due_for_purge(
        &self,
        tenant_id: &ScopedTenant,
        now: OffsetDateTime,
        limit: u32,
    ) -> Result<Vec<Memory<ResolvedTenant>>, DomainError>;
}

/// Dyn-safe port finding which tenants hold memories due to be deleted.
///
/// Not [`TenantScoped`]: the sweep asks across every tenant, then reads
/// each tenant's memories through [`MemoryStore`] under its own scope.
#[async_trait]
pub trait CrossTenantMemories: Send + Sync {
    /// The tenants holding a memory whose waiting period is over at `now`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn tenants_with_memories_due(
        &self,
        now: OffsetDateTime,
    ) -> Result<Vec<TenantId>, DomainError>;
}

/// Dyn-safe port of the vector store: the texts a memory keeps with their
/// vectors, searched for the nearest. Each tenant's entries are apart from
/// every other tenant's, whatever the store.
#[async_trait]
pub trait MemoryEntries: Send + Sync + TenantScoped {
    /// Keeps `entry` in memory `memory`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the store fails.
    async fn keep(
        &self,
        tenant_id: &ScopedTenant,
        memory: &MemoryId,
        entry: &MemoryEntry,
    ) -> Result<(), DomainError>;

    /// The entries of memory `memory` whose vectors are nearest `near`, by
    /// cosine, at most `count`, the nearest first.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the store fails.
    async fn find_similar(
        &self,
        tenant_id: &ScopedTenant,
        memory: &MemoryId,
        near: &Embedding,
        count: FoundCount,
    ) -> Result<Vec<FoundEntry>, DomainError>;

    /// A page of memory `memory`'s texts, oldest first, at most `limit`,
    /// starting at `start`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the store fails.
    async fn page(
        &self,
        tenant_id: &ScopedTenant,
        memory: &MemoryId,
        start: PageStart,
        limit: u8,
    ) -> Result<EntryPage, DomainError>;

    /// How many entries the tenant's memories hold together, for its plan's
    /// limit.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the store fails.
    async fn count(&self, tenant_id: &ScopedTenant) -> Result<u64, DomainError>;

    /// Deletes every entry of memory `memory`. Deleting from a memory with
    /// none, or once more after a crash, does nothing.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the store fails.
    async fn forget_all(
        &self,
        tenant_id: &ScopedTenant,
        memory: &MemoryId,
    ) -> Result<(), DomainError>;
}

/// Where a text is turned into a vector.
pub enum EmbeddingTarget {
    /// The platform's own embedding server, with its model.
    Platform(ModelName),
    /// A tenant's model provider's OpenAI-compatible embeddings endpoint,
    /// with its embedding model and opened API key.
    Provider {
        /// The provider's base endpoint.
        endpoint: ModelEndpoint,
        /// The embedding model.
        model: ModelName,
        /// The opened API key, or `None` for a keyless endpoint.
        api_key: Option<Secret>,
    },
}

impl fmt::Debug for EmbeddingTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Platform(model) => f.debug_tuple("Platform").field(model).finish(),
            Self::Provider {
                endpoint, model, ..
            } => f
                .debug_struct("Provider")
                .field("endpoint", endpoint)
                .field("model", model)
                .finish_non_exhaustive(),
        }
    }
}

/// Dyn-safe port of the embeddings client, speaking OpenAI's
/// `/v1/embeddings` API to a tenant's provider or the platform's own
/// embedding server.
#[async_trait]
pub trait Embedder: Send + Sync {
    /// The model the platform's own embedding server serves, or `None`
    /// where the deployment runs none.
    fn platform_model(&self) -> Option<ModelName>;

    /// The vector `target`'s embedding model makes for `text`, as raw
    /// numbers the caller checks against the memory.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the endpoint cannot be
    /// reached, answers with an error, takes too long, or answers with
    /// something that is not one vector; and when the platform's server is
    /// asked for while the deployment runs none. The API key is never part
    /// of the error.
    async fn embed(
        &self,
        target: &EmbeddingTarget,
        text: &MemoryText,
    ) -> Result<Vec<f32>, DomainError>;
}
