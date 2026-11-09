//! Delete memory: a person who may delete workflows sets a memory to be
//! deleted, typing its name to confirm. Nothing is kept in or found in it
//! from then on, and it and every text it kept are deleted for good only
//! once its waiting period is over, unless brought back first.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::WorkflowAction;
use ianua_domain::domains::workflows::control::WorkflowControl;
use ianua_domain::domains::workflows::memory::Memory;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::MemoryId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::runtime::UnitOfWork;
use crate::ports::workflows::MemoryStore;
use crate::services::kept_together::kept_together;
use crate::use_case::Command;
use crate::use_cases::workflows::memories::lookup::existing_memory;

/// Which memory, and its name as the person typed it to confirm.
#[derive(Debug)]
pub struct DeleteRequest {
    /// The searchable collection to remove after confirmation.
    pub memory_id: MemoryId,
    /// The confirmation text that must match the collection's current label.
    pub typed_name: String,
}

/// The ports [`DeleteUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct DeletePorts {
    /// Keeps the memories.
    pub memories: Arc<dyn MemoryStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
    /// Keeps the memory and its record together.
    pub unit_of_work: Arc<dyn UnitOfWork>,
}

/// Sets memories to be deleted.
pub struct DeleteUseCase {
    ports: DeletePorts,
}

impl DeleteUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: DeletePorts) -> Self {
        Self { ports }
    }
}

impl Command for DeleteUseCase {
    type Caller = CallerContext;
    type Input = DeleteRequest;
    type Output = Result<Memory<ResolvedTenant>, AppError>;

    /// Sets the tenant's memory to be deleted after its waiting period,
    /// and records `workflows.memory_deletion_requested`.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::NotFound` when the tenant has no such memory.
    /// - `AppError::Forbidden` when the caller may not delete workflows.
    /// - `AppError::Domain` when the typed name is not the memory's, or it
    ///   is set to be deleted already.
    /// - `AppError::Internal` on persistence or audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: DeleteRequest,
    ) -> Result<Memory<ResolvedTenant>, AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let control = WorkflowControl::new(&authority);
        control
            .ensure_may(WorkflowAction::Delete)
            .map_err(AppError::from_domain)?;
        let tenant = ctx.tenant();
        let mut memory =
            existing_memory(self.ports.memories.as_ref(), &tenant, &request.memory_id).await?;
        memory
            .request_deletion(&request.typed_name, &control)
            .map_err(AppError::from_domain)?;
        let events = memory.take_events(&tenant);
        kept_together(self.ports.unit_of_work.as_ref(), async {
            self.ports
                .memories
                .save(&tenant, &memory)
                .await
                .map_err(AppError::from_domain)?;
            auditor
                .dispatch_by(&ctx.actor(), events)
                .await
                .or_internal()
        })
        .await?;
        Ok(memory)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{SystemPermission, WorkflowAction};
    use ianua_domain::domains::workflows::memory::MemoryStatus;

    use super::*;
    use crate::test_support::acting::FakeTenantAuthorities;
    use crate::test_support::workflows::{FakeMemoryStore, kept_memory};
    use crate::test_support::{Fake, FakeEventDispatcher, block_on, test_auditor, test_ctx};

    fn deleting(
        memories: &Arc<FakeMemoryStore>,
        sink: &Arc<FakeEventDispatcher>,
        memory_id: MemoryId,
        typed: &str,
    ) -> Result<Memory<ResolvedTenant>, AppError> {
        let use_case = DeleteUseCase::new(DeletePorts {
            memories: memories.clone(),
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
                SystemPermission::Workflows(WorkflowAction::Delete),
            ])),
            unit_of_work: Fake::fake(),
        });
        block_on(use_case.execute(
            &test_ctx(),
            &test_auditor(sink.clone()),
            DeleteRequest {
                memory_id,
                typed_name: typed.to_owned(),
            },
        ))
    }

    /// Ann deletes the support tickets memory, typing its name: it waits
    /// to be deleted, and the trail records it.
    #[test]
    fn typing_the_name_sets_the_memory_to_be_deleted() {
        let memories = Arc::new(FakeMemoryStore::empty());
        let sink = Arc::new(FakeEventDispatcher::new());
        let memory = kept_memory(&memories);

        let deleted = deleting(&memories, &sink, *memory.id(), "Support tickets").unwrap();

        assert!(matches!(
            deleted.status(),
            MemoryStatus::DeletionRequested { .. }
        ));
        assert_eq!(
            *sink.records.lock().unwrap(),
            ["workflows.memory_deletion_requested"]
        );
    }

    /// A mismatched confirmation name refuses deletion, leaving the memory
    /// active and adding no audit record.
    #[test]
    fn a_wrong_name_deletes_nothing() {
        let memories = Arc::new(FakeMemoryStore::empty());
        let sink = Arc::new(FakeEventDispatcher::new());
        let memory = kept_memory(&memories);

        let deleted = deleting(&memories, &sink, *memory.id(), "tickets");

        assert!(matches!(deleted, Err(AppError::Domain(_))), "{deleted:?}");
        assert_eq!(memories.kept()[0].status(), MemoryStatus::Active);
        assert!(sink.records.lock().unwrap().is_empty());
    }
}
