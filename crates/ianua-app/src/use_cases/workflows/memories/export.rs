//! Export memory: a person who may delete workflows reads a memory's
//! texts page by page, oldest first, so they can keep a copy before they
//! delete it. A memory waiting to be deleted can still be read, since its
//! waiting period is when a copy matters most.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::WorkflowAction;
use ianua_domain::domains::workflows::control::WorkflowControl;
use ianua_domain::domains::workflows::memory::entry::{EntryPage, PageStart};
use ianua_domain::types::MemoryId;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::workflows::{MemoryEntries, MemoryStore};
use crate::use_case::Query;
use crate::use_cases::workflows::memories::lookup::existing_memory;

/// The most texts one page holds.
pub(crate) const PAGE_SIZE: u8 = 100;

/// Which page of which memory to read.
#[derive(Debug, Clone, Copy)]
pub struct ExportRequest {
    /// The searchable collection whose stored entries are being exported.
    pub memory_id: MemoryId,
    /// Where the page starts.
    pub start: PageStart,
}

/// The ports [`ExportUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ExportPorts {
    /// Keeps the memories.
    pub memories: Arc<dyn MemoryStore>,
    /// The vector store keeping their texts.
    pub entries: Arc<dyn MemoryEntries>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Reads a memory's texts for a copy.
pub struct ExportUseCase {
    ports: ExportPorts,
}

impl ExportUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: ExportPorts) -> Self {
        Self { ports }
    }
}

impl Query for ExportUseCase {
    type Caller = CallerContext;
    type Input = ExportRequest;
    type Output = Result<EntryPage, AppError>;

    /// A page of at most [`PAGE_SIZE`] of the memory's texts, oldest
    /// first, with where the next page starts.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not delete workflows.
    /// - `AppError::NotFound` when the tenant has no such memory, as after
    ///   it was deleted for good.
    /// - `AppError::Internal` when a store fails.
    async fn execute(
        &self,
        ctx: &CallerContext,
        request: ExportRequest,
    ) -> Result<EntryPage, AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        WorkflowControl::new(&authority)
            .ensure_may(WorkflowAction::Delete)
            .map_err(AppError::from_domain)?;
        let tenant = ctx.tenant();
        let memory =
            existing_memory(self.ports.memories.as_ref(), &tenant, &request.memory_id).await?;
        self.ports
            .entries
            .page(&tenant, memory.id(), request.start, PAGE_SIZE)
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::SystemPermission;
    use ianua_domain::domains::data_classification::level::DataClassLevel;
    use ianua_domain::domains::workflows::memory::entry::{
        Embedding, MemoryEntry, MemoryEntryParams, MemoryText, NextPage,
    };
    use ianua_domain::domains::workflows::memory::source::VectorSize;

    use super::*;
    use crate::test_support::acting::FakeTenantAuthorities;
    use crate::test_support::workflows::{
        FAKE_VECTOR_SIZE, FakeMemoryEntries, FakeMemoryStore, deleted_memory, kept_memory,
    };
    use crate::test_support::{block_on, test_ctx};

    fn use_case(
        memories: &Arc<FakeMemoryStore>,
        entries: &Arc<FakeMemoryEntries>,
        held: &[SystemPermission],
    ) -> ExportUseCase {
        ExportUseCase::new(ExportPorts {
            memories: memories.clone(),
            entries: entries.clone(),
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(held)),
        })
    }

    fn deleting() -> [SystemPermission; 1] {
        [SystemPermission::Workflows(WorkflowAction::Delete)]
    }

    fn kept(entries: &FakeMemoryEntries, memory: &MemoryId, count: usize) {
        let size = VectorSize::new(FAKE_VECTOR_SIZE).unwrap();
        for number in 0..count {
            let entry = MemoryEntry::new(MemoryEntryParams {
                text: MemoryText::new(format!("ticket {number}")).unwrap(),
                embedding: Embedding::new(vec![1.0; usize::from(FAKE_VECTOR_SIZE)], size).unwrap(),
                exposure: DataClassLevel::Internal,
            });
            block_on(entries.keep(&test_ctx().tenant(), memory, &entry)).unwrap();
        }
    }

    /// Ann's memory keeps 150 tickets: the first page holds the oldest 100
    /// and names where the next starts, which holds the other 50 and ends.
    #[test]
    fn a_memory_is_read_page_by_page_oldest_first() {
        let memories = Arc::new(FakeMemoryStore::empty());
        let entries = Arc::new(FakeMemoryEntries::default());
        let memory = kept_memory(&memories);
        kept(&entries, memory.id(), 150);
        let export = use_case(&memories, &entries, &deleting());

        let first = block_on(export.execute(
            &test_ctx(),
            ExportRequest {
                memory_id: *memory.id(),
                start: PageStart::First,
            },
        ))
        .unwrap();
        let NextPage::At(next) = first.next else {
            panic!("a second page follows")
        };
        let second = block_on(export.execute(
            &test_ctx(),
            ExportRequest {
                memory_id: *memory.id(),
                start: PageStart::At(next),
            },
        ))
        .unwrap();

        assert_eq!(first.entries.len(), 100);
        assert_eq!(first.entries[0].text.as_str(), "ticket 0");
        assert_eq!(second.entries.len(), 50);
        assert_eq!(second.entries[49].text.as_str(), "ticket 149");
        assert_eq!(second.next, NextPage::Done);
    }

    /// A memory waiting to be deleted can still be read, so Ann can keep a
    /// copy during its waiting period.
    #[test]
    fn a_memory_waiting_to_be_deleted_is_still_read() {
        let memories = Arc::new(FakeMemoryStore::empty());
        let entries = Arc::new(FakeMemoryEntries::default());
        let memory = deleted_memory(&memories);
        kept(&entries, memory.id(), 2);

        let page = block_on(use_case(&memories, &entries, &deleting()).execute(
            &test_ctx(),
            ExportRequest {
                memory_id: *memory.id(),
                start: PageStart::First,
            },
        ))
        .unwrap();

        assert_eq!(page.entries.len(), 2);
    }

    /// Workflow view rights alone do not permit exporting a memory's texts.
    #[test]
    fn someone_who_may_not_delete_workflows_reads_nothing() {
        let memories = Arc::new(FakeMemoryStore::empty());
        let entries = Arc::new(FakeMemoryEntries::default());
        let memory = kept_memory(&memories);
        kept(&entries, memory.id(), 1);

        let read = block_on(
            use_case(
                &memories,
                &entries,
                &[SystemPermission::Workflows(WorkflowAction::View)],
            )
            .execute(
                &test_ctx(),
                ExportRequest {
                    memory_id: *memory.id(),
                    start: PageStart::First,
                },
            ),
        );

        assert!(matches!(read, Err(AppError::Forbidden(_))), "{read:?}");
    }

    /// Exporting an absent memory returns not found despite delete permission.
    #[test]
    fn an_unknown_memory_is_not_found() {
        let memories = Arc::new(FakeMemoryStore::empty());
        let entries = Arc::new(FakeMemoryEntries::default());

        let read = block_on(use_case(&memories, &entries, &deleting()).execute(
            &test_ctx(),
            ExportRequest {
                memory_id: MemoryId::new(),
                start: PageStart::First,
            },
        ));

        assert!(matches!(read, Err(AppError::NotFound(_))), "{read:?}");
    }
}
