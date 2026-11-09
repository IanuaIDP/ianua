//! The memories' parts every node shares: where memories are kept, where
//! their texts and vectors are kept, pgvector or a vector server as
//! `VECTOR_STORE_URL` says, and the embeddings client reaching tenants'
//! providers and the platform's own embedding server.

use std::sync::Arc;
use std::time::Duration;

use ianua_app::ports::tenant::TenantMemoryPurger;
use ianua_app::ports::workflows::{CrossTenantMemories, Embedder, MemoryEntries, MemoryStore};
use ianua_infra::http::HttpEmbedder;
use ianua_infra::postgres::Databases;
use ianua_infra::postgres::workflows::{
    PgCrossTenantMemories, PgMemoryEntries, PgMemoryStore, PgTenantMemoryPurger,
};
use ianua_infra::vectors::VectorMemoryEntries;

use crate::config::Config;
use crate::config::serving::VectorStore;
use crate::error::PlatformError;
use crate::platform::services::Outbound;

/// The memories' parts.
pub(crate) struct MemoryParts {
    /// Keeps the tenants' memories.
    pub store: Arc<dyn MemoryStore>,
    /// Finds the tenants holding memories due to be deleted.
    pub due: Arc<dyn CrossTenantMemories>,
    /// Keeps the memories' texts and vectors.
    pub entries: Arc<dyn MemoryEntries>,
    /// Removes a deleted tenant's texts and vectors from the same store.
    pub purger: Arc<dyn TenantMemoryPurger>,
    /// Turns texts into vectors.
    pub embedder: Arc<dyn Embedder>,
}

/// The memories' parts `config` describes, over `databases`, reaching
/// tenants' providers only where `outbound` permits a model call.
///
/// # Errors
///
/// [`PlatformError`] when a client cannot be built.
pub(super) fn memory(
    config: &Config,
    databases: &Arc<Databases>,
    outbound: &Outbound,
) -> Result<MemoryParts, PlatformError> {
    let settings = &config.memory;
    let vectors = vector_store(&settings.vectors, databases, settings.timeout)?;
    let embedder = HttpEmbedder::new(
        outbound.model_networks.clone(),
        settings.platform.clone(),
        settings.timeout,
    )
    .map_err(PlatformError::of("the embeddings client"))?;
    Ok(MemoryParts {
        store: Arc::new(PgMemoryStore::new(Arc::clone(databases))),
        due: Arc::new(PgCrossTenantMemories::new(Arc::clone(databases))),
        entries: vectors.entries,
        purger: vectors.purger,
        embedder: Arc::new(embedder),
    })
}

/// The store keeping the memories' texts and vectors, and its removal of a
/// deleted tenant's.
struct VectorParts {
    entries: Arc<dyn MemoryEntries>,
    purger: Arc<dyn TenantMemoryPurger>,
}

/// Where the memories' texts and vectors are kept, as `vectors` says, and
/// the same store's removal of a deleted tenant's.
///
/// # Errors
///
/// [`PlatformError`] when the vector server's client cannot be built.
fn vector_store(
    vectors: &VectorStore,
    databases: &Arc<Databases>,
    timeout: Duration,
) -> Result<VectorParts, PlatformError> {
    match vectors {
        VectorStore::Postgres => Ok(VectorParts {
            entries: Arc::new(PgMemoryEntries::new(Arc::clone(databases))),
            purger: Arc::new(PgTenantMemoryPurger::new(Arc::clone(databases))),
        }),
        VectorStore::Server(server) => {
            let entries = Arc::new(
                VectorMemoryEntries::new(server.clone(), timeout)
                    .map_err(PlatformError::of("the vector server's client"))?,
            );
            Ok(VectorParts {
                entries: Arc::clone(&entries) as Arc<dyn MemoryEntries>,
                purger: entries,
            })
        }
    }
}
