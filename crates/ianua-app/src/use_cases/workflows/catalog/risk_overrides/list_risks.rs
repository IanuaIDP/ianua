//! List risks: every operation a tenant raised, for someone who may view
//! workflows.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::WorkflowAction;
use ianua_domain::domains::workflows::control::WorkflowControl;
use ianua_domain::domains::workflows::integration::risk_override::OperationRiskOverride;
use ianua_domain::isolation::scope::ResolvedTenant;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::workflows::OperationRiskOverrideStore;
use crate::use_case::Query;

/// The ports [`ListRisksUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ListRisksPorts {
    /// Keeps the overrides.
    pub risks: Arc<dyn OperationRiskOverrideStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Lists the operations a tenant raised.
pub struct ListRisksUseCase {
    ports: ListRisksPorts,
}

impl ListRisksUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: ListRisksPorts) -> Self {
        Self { ports }
    }
}

impl Query for ListRisksUseCase {
    type Caller = CallerContext;
    type Input = ();
    type Output = Result<Vec<OperationRiskOverride<ResolvedTenant>>, AppError>;

    /// Every override the tenant set, oldest first.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not view workflows.
    /// - `AppError::Internal` when the store fails.
    async fn execute(
        &self,
        ctx: &CallerContext,
        (): (),
    ) -> Result<Vec<OperationRiskOverride<ResolvedTenant>>, AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        WorkflowControl::new(&authority)
            .ensure_may(WorkflowAction::View)
            .map_err(AppError::from_domain)?;
        self.ports.risks.list(&ctx.tenant()).await.or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::SystemPermission;
    use ianua_domain::types::{ActionClass, DeclaredAction};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::workflows::{
        FakeOperationRiskOverrideStore, person, raised_to_payment,
    };
    use crate::test_support::{block_on, test_ctx};

    fn listing(
        authorities: FakeTenantAuthorities,
    ) -> Result<Vec<OperationRiskOverride<ResolvedTenant>>, AppError> {
        let risk = raised_to_payment(&person("bob@corp.test"));
        let use_case = ListRisksUseCase::new(ListRisksPorts {
            risks: Arc::new(FakeOperationRiskOverrideStore::holding(&risk)),
            tenant_authorities: Arc::new(authorities),
        });
        block_on(use_case.execute(&test_ctx(), ()))
    }

    /// Ann may view workflows. She sees that Bob raised "append row" to a
    /// payment.
    #[test]
    fn a_viewer_sees_what_the_tenant_raised() {
        let viewer =
            FakeTenantAuthorities::holding(&[SystemPermission::Workflows(WorkflowAction::View)]);

        let risks = listing(viewer).unwrap();

        assert_eq!(risks.len(), 1);
        assert_eq!(
            risks[0].effect(),
            DeclaredAction::Declared(ActionClass::Financial)
        );
    }

    /// A caller without workflow view rights cannot list risk overrides.
    #[test]
    fn a_caller_without_the_view_right_is_refused() {
        let result = listing(FakeTenantAuthorities::holding(&[]));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out session cannot list risk overrides.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let result = listing(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
