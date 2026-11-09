//! Get sandbox: one sandbox and its versions, newest first and paged, for
//! someone who may view workflows.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::WorkflowAction;
use ianua_domain::domains::workflows::control::WorkflowControl;
use ianua_domain::domains::workflows::sandbox::Sandbox;
use ianua_domain::domains::workflows::sandbox::version::SandboxVersion;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::SandboxId;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::listing::{Page, PageRequest};
use crate::ports::workflows::{SandboxStore, SandboxVersionStore};
use crate::use_case::Query;
use crate::use_cases::workflows::sandboxes::lookup::existing_sandbox;

/// Which sandbox to read, and which page of its versions.
pub struct GetSandboxRequest {
    /// The code project whose revision history is requested.
    pub sandbox_id: SandboxId,
    /// Which page of its versions, newest first.
    pub page: PageRequest,
}

/// A sandbox and one page of its versions.
pub struct SandboxDetail {
    /// The stored code project accompanied by its revision history.
    pub sandbox: Sandbox<ResolvedTenant>,
    /// Its versions, newest first.
    pub versions: Page<SandboxVersion<ResolvedTenant>>,
}

/// The ports [`GetSandboxUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct GetSandboxPorts {
    /// Keeps the sandboxes.
    pub sandboxes: Arc<dyn SandboxStore>,
    /// Keeps their versions.
    pub versions: Arc<dyn SandboxVersionStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Reads one sandbox and its versions.
pub struct GetSandboxUseCase {
    ports: GetSandboxPorts,
}

impl GetSandboxUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: GetSandboxPorts) -> Self {
        Self { ports }
    }
}

impl Query for GetSandboxUseCase {
    type Caller = CallerContext;
    type Input = GetSandboxRequest;
    type Output = Result<SandboxDetail, AppError>;

    /// The sandbox `request.sandbox_id` and the page of its versions it
    /// names, each with its code, packages, limits and build.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not view workflows.
    /// - `AppError::NotFound` when the tenant has no such sandbox.
    /// - `AppError::Internal` when a store fails.
    async fn execute(
        &self,
        ctx: &CallerContext,
        request: GetSandboxRequest,
    ) -> Result<SandboxDetail, AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        WorkflowControl::new(&authority)
            .ensure_may(WorkflowAction::View)
            .map_err(AppError::from_domain)?;
        let tenant = ctx.tenant();
        let sandbox =
            existing_sandbox(self.ports.sandboxes.as_ref(), &tenant, &request.sandbox_id).await?;
        let versions = self
            .ports
            .versions
            .list_of(&tenant, sandbox.id(), &request.page)
            .await
            .or_internal()?;
        Ok(SandboxDetail { sandbox, versions })
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::SystemPermission;

    use super::*;
    use crate::test_support::acting::FakeTenantAuthorities;
    use crate::test_support::workflows::{
        FakeSandboxStore, FakeSandboxVersionStore, python_sandbox, version_of,
    };
    use crate::test_support::{block_on, test_ctx};

    /// Bob may view workflows and reads Ann's sandbox: he sees it with its
    /// one version. Another sandbox is not found.
    #[test]
    fn a_viewer_reads_a_sandbox_with_its_versions() {
        let mut sandbox = python_sandbox();
        let version = version_of(&mut sandbox);
        let use_case = GetSandboxUseCase::new(GetSandboxPorts {
            sandboxes: Arc::new(FakeSandboxStore::holding(&sandbox)),
            versions: Arc::new(FakeSandboxVersionStore::holding(&version)),
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
                SystemPermission::Workflows(WorkflowAction::View),
            ])),
        });
        let read = |sandbox_id| {
            block_on(use_case.execute(
                &test_ctx(),
                GetSandboxRequest {
                    sandbox_id,
                    page: PageRequest::default(),
                },
            ))
        };

        let detail = read(*sandbox.id()).unwrap();

        assert_eq!(detail.versions.items.len(), 1);
        assert!(matches!(read(SandboxId::new()), Err(AppError::NotFound(_))));
    }
}
