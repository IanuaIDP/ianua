//! Restore memory: a person who may delete workflows brings back a memory
//! set to be deleted, within its waiting period, with every text it kept.

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

/// The ports [`RestoreUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RestorePorts {
    /// Keeps the memories.
    pub memories: Arc<dyn MemoryStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
    /// Keeps the memory and its record together.
    pub unit_of_work: Arc<dyn UnitOfWork>,
}

/// Brings memories back.
pub struct RestoreUseCase {
    ports: RestorePorts,
}

impl RestoreUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: RestorePorts) -> Self {
        Self { ports }
    }
}

impl Command for RestoreUseCase {
    type Caller = CallerContext;
    type Input = MemoryId;
    type Output = Result<Memory<ResolvedTenant>, AppError>;

    /// Brings back the tenant's memory `memory_id`, and records
    /// `workflows.memory_restored`.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::NotFound` when the tenant has no such memory, as after
    ///   it was deleted for good.
    /// - `AppError::Forbidden` when the caller may not delete workflows.
    /// - `AppError::Domain` when it is not set to be deleted.
    /// - `AppError::Internal` on persistence or audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        memory_id: MemoryId,
    ) -> Result<Memory<ResolvedTenant>, AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let control = WorkflowControl::new(&authority);
        control
            .ensure_may(WorkflowAction::Delete)
            .map_err(AppError::from_domain)?;
        let tenant = ctx.tenant();
        let mut memory = existing_memory(self.ports.memories.as_ref(), &tenant, &memory_id).await?;
        memory.restore(&control).map_err(AppError::from_domain)?;
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
    use crate::test_support::workflows::{FakeMemoryStore, deleted_memory};
    use crate::test_support::{Fake, FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// Ann brings back the memory she set to be deleted: it is active
    /// again, and the trail records it.
    #[test]
    fn a_memory_set_to_be_deleted_is_brought_back() {
        let memories = Arc::new(FakeMemoryStore::empty());
        let sink = Arc::new(FakeEventDispatcher::new());
        let memory = deleted_memory(&memories);
        let use_case = RestoreUseCase::new(RestorePorts {
            memories: memories.clone(),
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
                SystemPermission::Workflows(WorkflowAction::Delete),
            ])),
            unit_of_work: Fake::fake(),
        });

        let restored =
            block_on(use_case.execute(&test_ctx(), &test_auditor(sink.clone()), *memory.id()))
                .unwrap();

        assert_eq!(restored.status(), MemoryStatus::Active);
        assert_eq!(*sink.records.lock().unwrap(), ["workflows.memory_restored"]);
    }
}
