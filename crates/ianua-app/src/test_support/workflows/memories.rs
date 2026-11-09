//! Memories, the vector store and the embeddings client as the tests need
//! them: memories kept and read back the way storage reads them, entries
//! searched by cosine in memory, and an embedding model whose vectors
//! count letters, so texts sharing words come out alike.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::agents::execution::model_provider::ModelName;
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::domains::workflows::memory::entry::{
    Embedding, EntryPage, FoundCount, FoundEntry, KeptEntry, MemoryEntry, MemoryText, NextPage,
    PageStart,
};
use ianua_domain::domains::workflows::memory::source::{EmbeddingSource, VectorSize};
use ianua_domain::domains::workflows::memory::{
    CreateMemoryParams, Memory, MemoryRow, MemoryStatus,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::model::aggregate::Aggregate;
use ianua_domain::types::{Label, MemoryId, TenantId};
use time::OffsetDateTime;

use crate::ports::TenantScoped;
use crate::ports::tenant::TenantMemoryPurger;
use crate::ports::workflows::{
    CrossTenantMemories, Embedder, EmbeddingTarget, MemoryEntries, MemoryStore,
};
use crate::tenancy::ScopedTenant;
use crate::test_support::workflows::graphs::{managing, person};
use crate::test_support::{Fake, block_on, test_ctx};

/// How long the fake embedding model's vectors are: one number per letter.
pub const FAKE_VECTOR_SIZE: u16 = 26;

/// The model the fake platform server serves.
pub const PLATFORM_MODEL: &str = "bge-small-en-v1.5";

/// `memory` read back from its row, as storage reads it.
fn memory_copy(memory: &Memory<ResolvedTenant>) -> Memory<ResolvedTenant> {
    Memory::reconstitute(MemoryRow {
        id: *memory.id(),
        name: memory.name().clone(),
        source: memory.source().clone(),
        vector_size: memory.vector_size(),
        clearance: memory.clearance(),
        status: memory.status(),
        created_by: memory.created_by().clone(),
        created_at: Aggregate::created_at(memory),
        updated_at: Aggregate::updated_at(memory),
    })
    .expect("a kept memory reads back as itself")
}

/// In-memory memory store: memories kept under their tenant.
#[derive(Default)]
pub struct FakeMemoryStore {
    memories: Mutex<Vec<(TenantId, Memory<ResolvedTenant>)>>,
}

impl TenantScoped for FakeMemoryStore {}

impl FakeMemoryStore {
    /// A store holding no memory.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Every memory kept, of any tenant.
    #[must_use]
    pub fn kept(&self) -> Vec<Memory<ResolvedTenant>> {
        self.memories
            .lock()
            .unwrap()
            .iter()
            .map(|(_, memory)| memory_copy(memory))
            .collect()
    }
}

#[async_trait]
impl MemoryStore for FakeMemoryStore {
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &MemoryId,
    ) -> Result<Option<Memory<ResolvedTenant>>, DomainError> {
        Ok(self
            .memories
            .lock()
            .unwrap()
            .iter()
            .find(|(owner, memory)| owner == &**tenant_id && memory.id() == id)
            .map(|(_, memory)| memory_copy(memory)))
    }

    async fn list(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<Vec<Memory<ResolvedTenant>>, DomainError> {
        Ok(self
            .memories
            .lock()
            .unwrap()
            .iter()
            .filter(|(owner, _)| owner == &**tenant_id)
            .map(|(_, memory)| memory_copy(memory))
            .collect())
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        memory: &Memory<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let mut memories = self.memories.lock().unwrap();
        memories.retain(|(owner, kept)| !(owner == &**tenant_id && kept.id() == memory.id()));
        memories.push((**tenant_id, memory_copy(memory)));
        Ok(())
    }

    async fn delete(&self, tenant_id: &ScopedTenant, id: &MemoryId) -> Result<(), DomainError> {
        self.memories
            .lock()
            .unwrap()
            .retain(|(owner, kept)| !(owner == &**tenant_id && kept.id() == id));
        Ok(())
    }

    async fn due_for_purge(
        &self,
        tenant_id: &ScopedTenant,
        now: OffsetDateTime,
        limit: u32,
    ) -> Result<Vec<Memory<ResolvedTenant>>, DomainError> {
        Ok(self
            .memories
            .lock()
            .unwrap()
            .iter()
            .filter(|(owner, memory)| owner == &**tenant_id && due(memory, now))
            .take(usize::try_from(limit).unwrap_or(usize::MAX))
            .map(|(_, memory)| memory_copy(memory))
            .collect())
    }
}

#[async_trait]
impl CrossTenantMemories for FakeMemoryStore {
    async fn tenants_with_memories_due(
        &self,
        now: OffsetDateTime,
    ) -> Result<Vec<TenantId>, DomainError> {
        let mut tenants: Vec<TenantId> = self
            .memories
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, memory)| due(memory, now))
            .map(|(owner, _)| *owner)
            .collect();
        tenants.dedup();
        Ok(tenants)
    }
}

/// Whether `memory`'s waiting period is over at `now`.
fn due(memory: &Memory<ResolvedTenant>, now: OffsetDateTime) -> bool {
    matches!(memory.status(), MemoryStatus::DeletionRequested { deleted_after } if deleted_after <= now)
}

impl Fake for Arc<dyn MemoryStore> {
    fn fake() -> Self {
        Arc::new(FakeMemoryStore::empty())
    }
}

/// In-memory vector store: entries kept under their tenant and memory,
/// searched by cosine.
#[derive(Default)]
pub struct FakeMemoryEntries {
    entries: Mutex<Vec<(TenantId, MemoryId, MemoryEntry)>>,
}

impl TenantScoped for FakeMemoryEntries {}

impl FakeMemoryEntries {
    /// The texts kept in memory `memory` of any tenant.
    #[must_use]
    pub fn texts_in(&self, memory: &MemoryId) -> Vec<String> {
        self.entries
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, kept, _)| kept == memory)
            .map(|(_, _, entry)| entry.text().as_str().to_owned())
            .collect()
    }
}

#[async_trait]
impl MemoryEntries for FakeMemoryEntries {
    async fn keep(
        &self,
        tenant_id: &ScopedTenant,
        memory: &MemoryId,
        entry: &MemoryEntry,
    ) -> Result<(), DomainError> {
        self.entries
            .lock()
            .unwrap()
            .push((**tenant_id, *memory, entry.clone()));
        Ok(())
    }

    async fn find_similar(
        &self,
        tenant_id: &ScopedTenant,
        memory: &MemoryId,
        near: &Embedding,
        count: FoundCount,
    ) -> Result<Vec<FoundEntry>, DomainError> {
        let mut found: Vec<FoundEntry> = self
            .entries
            .lock()
            .unwrap()
            .iter()
            .filter(|(owner, kept, _)| owner == &**tenant_id && kept == memory)
            .map(|(_, _, entry)| FoundEntry {
                id: *entry.id(),
                text: entry.text().clone(),
                exposure: entry.exposure(),
                similarity: cosine(entry.embedding().values(), near.values()),
                kept_at: entry.created_at(),
            })
            .collect();
        found.sort_by(|a, b| b.similarity.total_cmp(&a.similarity));
        found.truncate(usize::from(count.get()));
        Ok(found)
    }

    async fn page(
        &self,
        tenant_id: &ScopedTenant,
        memory: &MemoryId,
        start: PageStart,
        limit: u8,
    ) -> Result<EntryPage, DomainError> {
        let mut kept: Vec<KeptEntry> = self
            .entries
            .lock()
            .unwrap()
            .iter()
            .filter(|(owner, held, _)| owner == &**tenant_id && held == memory)
            .map(|(_, _, entry)| KeptEntry {
                id: *entry.id(),
                text: entry.text().clone(),
                exposure: entry.exposure(),
                kept_at: entry.created_at(),
            })
            .filter(|entry| match start {
                PageStart::First => true,
                PageStart::At(from) => entry.id.as_uuid() >= from.as_uuid(),
            })
            .collect();
        kept.sort_by_key(|entry| *entry.id.as_uuid());
        let after = kept.split_off(usize::from(limit).min(kept.len()));
        let next = after
            .first()
            .map_or(NextPage::Done, |entry| NextPage::At(entry.id));
        Ok(EntryPage {
            entries: kept,
            next,
        })
    }

    async fn count(&self, tenant_id: &ScopedTenant) -> Result<u64, DomainError> {
        let kept = self
            .entries
            .lock()
            .unwrap()
            .iter()
            .filter(|(owner, _, _)| owner == &**tenant_id)
            .count();
        Ok(u64::try_from(kept).unwrap_or(u64::MAX))
    }

    async fn forget_all(
        &self,
        tenant_id: &ScopedTenant,
        memory: &MemoryId,
    ) -> Result<(), DomainError> {
        self.entries
            .lock()
            .unwrap()
            .retain(|(owner, kept, _)| !(owner == &**tenant_id && kept == memory));
        Ok(())
    }
}

#[async_trait]
impl TenantMemoryPurger for FakeMemoryEntries {
    async fn purge(&self, tenant_id: &TenantId) -> Result<(), DomainError> {
        self.entries
            .lock()
            .unwrap()
            .retain(|(owner, _, _)| owner != tenant_id);
        Ok(())
    }
}

impl Fake for Arc<dyn TenantMemoryPurger> {
    fn fake() -> Self {
        Arc::new(FakeMemoryEntries::default())
    }
}

impl Fake for Arc<dyn CrossTenantMemories> {
    fn fake() -> Self {
        Arc::new(FakeMemoryStore::default())
    }
}

impl Fake for Arc<dyn MemoryEntries> {
    fn fake() -> Self {
        Arc::new(FakeMemoryEntries::default())
    }
}

/// The cosine of the angle between `a` and `b`.
fn cosine(a: &[f32], b: &[f32]) -> f32 {
    let dot: f32 = a.iter().zip(b).map(|(x, y)| x * y).sum();
    let norm = |v: &[f32]| v.iter().map(|x| x * x).sum::<f32>().sqrt();
    let product = norm(a) * norm(b);
    if product == 0.0 {
        return 0.0;
    }
    dot / product
}

/// An embedding model counting each letter of a text, served by the fake
/// platform server and by any provider; one built to refuse answers with
/// an error.
pub struct FakeEmbedder {
    platform: Option<ModelName>,
    answering: Answering,
    asked: Mutex<Vec<String>>,
}

/// Whether the fake embedder answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Answering {
    Vectors,
    Failure,
}

impl FakeEmbedder {
    /// A client whose platform server serves [`PLATFORM_MODEL`].
    #[must_use]
    pub fn with_platform() -> Self {
        Self {
            platform: Some(ModelName::new(PLATFORM_MODEL).expect("a model name")),
            answering: Answering::Vectors,
            asked: Mutex::new(Vec::new()),
        }
    }

    /// A client on a deployment running no embedding server.
    #[must_use]
    pub fn without_platform() -> Self {
        Self {
            platform: None,
            ..Self::with_platform()
        }
    }

    /// A client whose every call fails, as an unreachable endpoint does.
    #[must_use]
    pub fn failing() -> Self {
        Self {
            answering: Answering::Failure,
            ..Self::with_platform()
        }
    }

    /// The models asked, in order.
    #[must_use]
    pub fn asked(&self) -> Vec<String> {
        self.asked.lock().unwrap().clone()
    }
}

#[async_trait]
impl Embedder for FakeEmbedder {
    fn platform_model(&self) -> Option<ModelName> {
        self.platform.clone()
    }

    async fn embed(
        &self,
        target: &EmbeddingTarget,
        text: &MemoryText,
    ) -> Result<Vec<f32>, DomainError> {
        let model = match target {
            EmbeddingTarget::Platform(model) | EmbeddingTarget::Provider { model, .. } => model,
        };
        self.asked.lock().unwrap().push(model.as_str().to_owned());
        if self.answering == Answering::Failure {
            return Err(DomainError::infra_msg(
                "the embedding endpoint did not answer",
            ));
        }
        Ok(letter_counts(text.as_str()))
    }
}

impl Fake for Arc<dyn Embedder> {
    fn fake() -> Self {
        Arc::new(FakeEmbedder::with_platform())
    }
}

/// One number per letter of the alphabet: how often it appears in `text`.
fn letter_counts(text: &str) -> Vec<f32> {
    let mut counts = vec![0.0_f32; usize::from(FAKE_VECTOR_SIZE)];
    for letter in text
        .to_ascii_lowercase()
        .bytes()
        .filter(u8::is_ascii_lowercase)
    {
        counts[usize::from(letter - b'a')] += 1.0;
    }
    counts
}

/// Ann's support tickets memory on the platform's server, kept in the
/// test tenant.
///
/// # Panics
///
/// - Never: the values are valid and Ann may create workflows.
#[must_use]
pub fn kept_memory(store: &FakeMemoryStore) -> Memory<ResolvedTenant> {
    let ann = person("ann@acme.test");
    let memory = Memory::create(
        CreateMemoryParams {
            name: Label::new("name", "Support tickets").expect("a name"),
            source: EmbeddingSource::Platform(ModelName::new(PLATFORM_MODEL).expect("a model")),
            vector_size: VectorSize::new(FAKE_VECTOR_SIZE).expect("a size"),
            clearance: DataClassLevel::Internal,
        },
        &managing(&ann),
    )
    .expect("Ann makes a memory");
    block_on(store.save(&test_ctx().tenant(), &memory)).expect("the fake store keeps it");
    memory
}

/// The same memory, set to be deleted by Ann.
///
/// # Panics
///
/// - Never: Ann may delete workflows and types its name.
#[must_use]
pub fn deleted_memory(store: &FakeMemoryStore) -> Memory<ResolvedTenant> {
    let ann = person("ann@acme.test");
    let mut memory = kept_memory(store);
    memory
        .request_deletion("Support tickets", &managing(&ann))
        .expect("Ann deletes the memory");
    block_on(store.save(&test_ctx().tenant(), &memory)).expect("the fake store keeps it");
    memory
}
