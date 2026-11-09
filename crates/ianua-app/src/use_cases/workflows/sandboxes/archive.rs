//! Archive sandbox: a person who may delete workflows archives a sandbox,
//! so nothing new is saved or picked. Versions a published workflow already
//! names keep running, since what was published is what runs.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::WorkflowAction;
use ianua_domain::domains::workflows::control::WorkflowControl;
use ianua_domain::domains::workflows::sandbox::Sandbox;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::SandboxId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::workflows::SandboxStore;
use crate::use_case::Command;
use crate::use_cases::workflows::sandboxes::lookup::existing_sandbox;

/// The ports [`ArchiveSandboxUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ArchiveSandboxPorts {
    /// Keeps the sandboxes.
    pub sandboxes: Arc<dyn SandboxStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Archives sandboxes.
pub struct ArchiveSandboxUseCase {
    ports: ArchiveSandboxPorts,
}

impl ArchiveSandboxUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: ArchiveSandboxPorts) -> Self {
        Self { ports }
    }
}

impl Command for ArchiveSandboxUseCase {
    type Caller = CallerContext;
    type Input = SandboxId;
    type Output = Result<Sandbox<ResolvedTenant>, AppError>;

    /// Archives the tenant's sandbox `sandbox_id`.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::NotFound` when the tenant has no such sandbox.
    /// - `AppError::Forbidden` when the caller may not delete workflows.
    /// - `AppError::Conflict` when it is archived already.
    /// - `AppError::Internal` on persistence or audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        sandbox_id: SandboxId,
    ) -> Result<Sandbox<ResolvedTenant>, AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let control = WorkflowControl::new(&authority);
        control
            .ensure_may(WorkflowAction::Delete)
            .map_err(AppError::from_domain)?;
        let tenant = ctx.tenant();
        let mut sandbox =
            existing_sandbox(self.ports.sandboxes.as_ref(), &tenant, &sandbox_id).await?;
        sandbox.archive(&control).map_err(AppError::from_domain)?;
        self.ports
            .sandboxes
            .save(&tenant, &sandbox)
            .await
            .map_err(AppError::from_domain)?;
        auditor
            .dispatch_by(&ctx.actor(), sandbox.take_events(&tenant))
            .await
            .or_internal()?;
        Ok(sandbox)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{SystemPermission, WorkflowAction};
    use ianua_domain::domains::workflows::sandbox::SandboxStatus;

    use super::*;
    use crate::test_support::acting::FakeTenantAuthorities;
    use crate::test_support::workflows::{FakeSandboxStore, python_sandbox};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    fn archiving(
        sandboxes: &Arc<FakeSandboxStore>,
        id: SandboxId,
        holds: &[SystemPermission],
    ) -> Result<Sandbox<ResolvedTenant>, AppError> {
        let use_case = ArchiveSandboxUseCase::new(ArchiveSandboxPorts {
            sandboxes: sandboxes.clone(),
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(holds)),
        });
        block_on(use_case.execute(
            &test_ctx(),
            &test_auditor(Arc::new(FakeEventDispatcher::new())),
            id,
        ))
    }

    /// Ann may delete workflows and archives her sandbox: it is kept
    /// archived. Sam, who may only change them, is refused.
    #[test]
    fn only_someone_who_may_delete_workflows_archives_a_sandbox() {
        let sandbox = python_sandbox();
        let sandboxes = Arc::new(FakeSandboxStore::holding(&sandbox));

        let by_sam = archiving(
            &sandboxes,
            *sandbox.id(),
            &[SystemPermission::Workflows(WorkflowAction::Update)],
        );
        archiving(
            &sandboxes,
            *sandbox.id(),
            &[SystemPermission::Workflows(WorkflowAction::Delete)],
        )
        .unwrap();

        assert!(matches!(by_sam, Err(AppError::Forbidden(_))));
        assert_eq!(
            sandboxes.stored(sandbox.id()).unwrap().status(),
            SandboxStatus::Archived
        );
    }
}
