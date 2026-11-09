//! List runtimes: the runtimes a new sandbox version may pick now, each
//! with the exact image it would keep, for someone who may view workflows.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::WorkflowAction;
use ianua_domain::domains::workflows::control::WorkflowControl;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::ports::workflows::{OfferedRuntime, SandboxRuntimes};
use crate::use_case::Query;

/// The ports [`ListRuntimesUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ListRuntimesPorts {
    /// The runtimes offered now.
    pub runtimes: Arc<dyn SandboxRuntimes>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Lists the runtimes offered for new versions.
pub struct ListRuntimesUseCase {
    ports: ListRuntimesPorts,
}

impl ListRuntimesUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: ListRuntimesPorts) -> Self {
        Self { ports }
    }
}

impl Query for ListRuntimesUseCase {
    type Caller = CallerContext;
    type Input = ();
    type Output = Result<Vec<OfferedRuntime>, AppError>;

    /// Every runtime offered now, with its image. A retired one is left
    /// out.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not view workflows.
    async fn execute(&self, ctx: &CallerContext, (): ()) -> Result<Vec<OfferedRuntime>, AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        WorkflowControl::new(&authority)
            .ensure_may(WorkflowAction::View)
            .map_err(AppError::from_domain)?;
        Ok(self.ports.runtimes.offered())
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::SystemPermission;
    use ianua_domain::domains::workflows::sandbox::runtime::Runtime;

    use super::*;
    use crate::test_support::acting::FakeTenantAuthorities;
    use crate::test_support::workflows::FakeSandboxRuntimes;
    use crate::test_support::{block_on, test_ctx};

    fn listing(
        runtimes: FakeSandboxRuntimes,
        holds: &[SystemPermission],
    ) -> Result<Vec<OfferedRuntime>, AppError> {
        let use_case = ListRuntimesUseCase::new(ListRuntimesPorts {
            runtimes: Arc::new(runtimes),
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(holds)),
        });
        block_on(use_case.execute(&test_ctx(), ()))
    }

    /// Ann may view workflows. She is shown every runtime but Python 3.11,
    /// which the operator retired.
    #[test]
    fn a_retired_runtime_is_not_shown() {
        let offered = listing(
            FakeSandboxRuntimes::retiring(Runtime::Python311),
            &[SystemPermission::Workflows(WorkflowAction::View)],
        )
        .unwrap();

        assert_eq!(offered.len(), Runtime::ALL.len() - 1);
        assert!(offered.iter().all(|one| one.runtime != Runtime::Python311));
    }

    /// A caller without workflow rights cannot list sandbox runtimes.
    #[test]
    fn someone_who_may_not_view_workflows_is_refused() {
        let result = listing(FakeSandboxRuntimes::offering_all(), &[]);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }
}
