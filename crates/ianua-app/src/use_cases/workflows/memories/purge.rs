//! The background sweep that deletes for good the memories whose waiting
//! period is over: every text they kept first, then the memory and the
//! record of its deletion together.
//!
//! Only a memory a person set to be deleted, typing its name, is ever
//! deleted here, never one that sat idle or outgrew a plan. The texts go
//! first, from whichever vector store keeps them; deleting them again after
//! a crash does nothing, so a sweep that stops between the two steps
//! finishes the memory next round, never leaving texts behind a deleted
//! memory or a memory recorded as deleted with its texts still kept.

use std::sync::Arc;

use ianua_domain::domains::workflows::memory::Memory;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{ActorRef, TenantId};

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::runtime::UnitOfWork;
use crate::ports::workflows::{CrossTenantMemories, MemoryEntries, MemoryStore};
use crate::services::kept_together::kept_together;
use crate::services::sweep_round::SweepRound;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;

/// The most memories one round deletes in one tenant.
const PER_TENANT: u32 = 50;

/// The ports [`PurgeUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct PurgePorts {
    /// Keeps the memories.
    pub memories: Arc<dyn MemoryStore>,
    /// Finds the tenants holding memories due.
    pub due: Arc<dyn CrossTenantMemories>,
    /// The vector store keeping their texts.
    pub entries: Arc<dyn MemoryEntries>,
    /// Keeps a memory's deletion and its record together.
    pub unit_of_work: Arc<dyn UnitOfWork>,
}

/// Deletes for good the memories whose waiting period is over.
pub struct PurgeUseCase {
    ports: PurgePorts,
}

impl PurgeUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: PurgePorts) -> Self {
        Self { ports }
    }

    /// Deletes `memory` of `tenant` and every text it kept, and records it
    /// by the platform.
    async fn purge(
        &self,
        auditor: &RequestAuditor,
        tenant: &ScopedTenant,
        mut memory: Memory<ResolvedTenant>,
    ) -> Result<(), AppError> {
        let now = ianua_domain::shared::clock::now();
        memory.purge(now).map_err(AppError::from_domain)?;
        self.ports
            .entries
            .forget_all(tenant, memory.id())
            .await
            .or_internal()?;
        let events = memory.take_events(tenant);
        kept_together(self.ports.unit_of_work.as_ref(), async {
            self.ports
                .memories
                .delete(tenant, memory.id())
                .await
                .or_internal()?;
            auditor
                .with_tenant(**tenant)
                .dispatch_by(&ActorRef::System, events)
                .await
                .or_internal()
        })
        .await
    }

    /// One round in `tenant_id`, each memory deleted or left for the next.
    async fn swept(
        &self,
        auditor: &RequestAuditor,
        tenant_id: TenantId,
        round: SweepRound,
    ) -> Result<SweepRound, AppError> {
        let tenant = ScopedTenant::for_background(tenant_id);
        let due = self
            .ports
            .memories
            .due_for_purge(&tenant, ianua_domain::shared::clock::now(), PER_TENANT)
            .await
            .or_internal()?;
        let mut round = round;
        for memory in due {
            let id = *memory.id();
            round = match self.purge(auditor, &tenant, memory).await {
                Ok(()) => round.with_changed(),
                Err(error) => {
                    tracing::warn!(%tenant_id, memory = %id, %error, "deleting a memory failed; left for the next round");
                    round.with_failed()
                }
            };
        }
        Ok(round)
    }
}

impl Command for PurgeUseCase {
    type Caller = ();
    type Input = ();
    type Output = Result<SweepRound, AppError>;

    /// Deletes for good, in every tenant, the memories whose waiting period
    /// is over, recording `workflows.memory_purged` for each by the
    /// platform. Returns how the round went.
    ///
    /// # Errors
    ///
    /// - `AppError::Internal` when the tenants to sweep cannot be listed. A
    ///   memory that cannot be deleted is logged, counted as failed and
    ///   found again by the next round.
    async fn execute(
        &self,
        (): &(),
        auditor: &RequestAuditor,
        (): (),
    ) -> Result<SweepRound, AppError> {
        let tenants = self
            .ports
            .due
            .tenants_with_memories_due(ianua_domain::shared::clock::now())
            .await
            .or_internal()?;
        let mut round = SweepRound::default();
        for tenant_id in tenants {
            round = match self.swept(auditor, tenant_id, round).await {
                Ok(next) => next,
                Err(error) => {
                    tracing::warn!(%tenant_id, %error, "reading a tenant's memories to delete failed; left for the next round");
                    round.with_failed()
                }
            };
        }
        Ok(round)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::agents::execution::model_provider::ModelName;
    use ianua_domain::domains::data_classification::level::DataClassLevel;
    use ianua_domain::domains::workflows::memory::entry::{
        Embedding, MemoryEntry, MemoryEntryParams, MemoryText,
    };
    use ianua_domain::domains::workflows::memory::source::{EmbeddingSource, VectorSize};
    use ianua_domain::domains::workflows::memory::{
        DELETION_WAITING_DAYS, MemoryRow, MemoryStatus,
    };
    use ianua_domain::types::{Label, MemoryId};
    use time::Duration;

    use super::*;
    use crate::test_support::workflows::{FakeMemoryEntries, FakeMemoryStore, kept_memory, person};
    use crate::test_support::{Fake, FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// A memory Ann set to be deleted, whose waiting period ended a day ago,
    /// keeping one text.
    fn expired(memories: &FakeMemoryStore, entries: &FakeMemoryEntries) -> MemoryId {
        let now = ianua_domain::shared::clock::now();
        let deleted_after = now - Duration::days(1);
        let changed = deleted_after - Duration::days(DELETION_WAITING_DAYS);
        let memory = Memory::<ResolvedTenant>::reconstitute(MemoryRow {
            id: MemoryId::new(),
            name: Label::new("name", "Old tickets").unwrap(),
            source: EmbeddingSource::Platform(ModelName::new("bge-small-en-v1.5").unwrap()),
            vector_size: VectorSize::new(2).unwrap(),
            clearance: DataClassLevel::Internal,
            status: MemoryStatus::DeletionRequested { deleted_after },
            created_by: person("ann@acme.test"),
            created_at: changed,
            updated_at: changed,
        })
        .unwrap();
        let tenant = test_ctx().tenant();
        block_on(memories.save(&tenant, &memory)).unwrap();
        let entry = MemoryEntry::new(MemoryEntryParams {
            text: MemoryText::new("I want my money back").unwrap(),
            embedding: Embedding::new(vec![1.0, 0.0], VectorSize::new(2).unwrap()).unwrap(),
            exposure: DataClassLevel::Internal,
        });
        block_on(entries.keep(&tenant, memory.id(), &entry)).unwrap();
        *memory.id()
    }

    fn sweep(
        memories: &Arc<FakeMemoryStore>,
        entries: &Arc<FakeMemoryEntries>,
        sink: &Arc<FakeEventDispatcher>,
    ) -> SweepRound {
        let use_case = PurgeUseCase::new(PurgePorts {
            memories: memories.clone(),
            due: memories.clone(),
            entries: entries.clone(),
            unit_of_work: Fake::fake(),
        });
        block_on(use_case.execute(&(), &test_auditor(sink.clone()), ())).unwrap()
    }

    /// The old tickets memory's waiting period ended yesterday: the sweep
    /// deletes its texts and the memory, and records it by the platform.
    #[test]
    fn a_memory_past_its_waiting_period_is_deleted_with_its_texts() {
        let memories = Arc::new(FakeMemoryStore::empty());
        let entries = Arc::new(FakeMemoryEntries::default());
        let sink = Arc::new(FakeEventDispatcher::new());
        let id = expired(&memories, &entries);

        let round = sweep(&memories, &entries, &sink);

        assert_eq!(round, SweepRound::default().with_changed());
        assert!(memories.kept().is_empty());
        assert!(entries.texts_in(&id).is_empty());
        assert_eq!(*sink.records.lock().unwrap(), ["workflows.memory_purged"]);
    }

    /// The purge sweep keeps active memories and those still in their deletion
    /// waiting period, reporting no changes and adding no audit records.
    #[test]
    fn memories_not_yet_due_are_kept() {
        let memories = Arc::new(FakeMemoryStore::empty());
        let entries = Arc::new(FakeMemoryEntries::default());
        let sink = Arc::new(FakeEventDispatcher::new());
        let _tickets = kept_memory(&memories);
        let _waiting = crate::test_support::workflows::deleted_memory(&memories);

        let round = sweep(&memories, &entries, &sink);

        assert_eq!(round, SweepRound::default());
        assert_eq!(memories.kept().len(), 2);
        assert!(sink.records.lock().unwrap().is_empty());
    }
}
