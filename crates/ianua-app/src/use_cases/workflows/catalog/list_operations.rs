//! List operations: everything the installed integrations offer a
//! workflow's builder, as the tenant treats it, for someone who may view
//! workflows.
//!
//! Each operation comes through the tenant's raised views, so a builder
//! sees an operation as risky as the tenant counts it, never as the
//! integration alone declared it; and with its guide: what it does, what
//! each input means and what it gives back.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::WorkflowAction;
use ianua_domain::domains::workflows::control::WorkflowControl;
use ianua_domain::domains::workflows::integration::guide::OperationGuide;
use ianua_domain::domains::workflows::integration::risk_override::{
    OperationRiskOverride, TenantOperation,
};
use ianua_domain::domains::workflows::integration::{IntegrationKey, OperationSpec};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::workflows::{IntegrationCatalog, OperationRiskOverrideStore};
use crate::use_case::Query;

/// One operation a builder may use: as the tenant treats it, and how its
/// integration explains it.
#[derive(Debug, Clone)]
pub struct OfferedOperation {
    /// The operation, as risky as the tenant counts it.
    pub operation: TenantOperation,
    /// What it does, what its inputs mean and what it gives back.
    pub guide: OperationGuide,
}

/// One operation as its integration declares and explains it, before the
/// tenant's views are applied.
struct Declared {
    spec: OperationSpec,
    guide: OperationGuide,
}

/// The ports [`ListOperationsUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ListOperationsPorts {
    /// The integrations installed and what they declare.
    pub catalog: Arc<dyn IntegrationCatalog>,
    /// The tenant's raised views of operations.
    pub risks: Arc<dyn OperationRiskOverrideStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Lists the operations a workflow's builder may use.
pub struct ListOperationsUseCase {
    ports: ListOperationsPorts,
}

impl ListOperationsUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: ListOperationsPorts) -> Self {
        Self { ports }
    }

    /// Every operation the installed integrations offer now, as they
    /// declare and explain it, integration by integration.
    ///
    /// # Errors
    ///
    /// - `AppError::Internal` when the catalog cannot be read, or an
    ///   operation has no guide.
    async fn offered(&self) -> Result<Vec<Declared>, AppError> {
        let installed = self.ports.catalog.installed().await.or_internal()?;
        let mut offered = Vec::new();
        for profile in &installed {
            offered.extend(self.declared_by(profile.key()).await?);
        }
        Ok(offered)
    }

    /// The operations `integration` offers, each with its guide.
    ///
    /// # Errors
    ///
    /// - `AppError::Internal` when the catalog cannot be read, or an
    ///   operation has no guide.
    async fn declared_by(&self, integration: &IntegrationKey) -> Result<Vec<Declared>, AppError> {
        let catalog = self.ports.catalog.as_ref();
        let specs = catalog.offered(integration).await.or_internal()?;
        let mut guides = catalog.guides(integration).await.or_internal()?;
        specs
            .into_iter()
            .map(|spec| {
                let place = guides
                    .iter()
                    .position(|guide| guide.operation() == spec.operation())
                    .ok_or_else(|| unguided(&spec))
                    .or_internal()?;
                let guide = guides.swap_remove(place);
                Ok(Declared { spec, guide })
            })
            .collect()
    }
}

impl Query for ListOperationsUseCase {
    type Caller = CallerContext;
    type Input = ();
    type Output = Result<Vec<OfferedOperation>, AppError>;

    /// Every operation offered now, each as the tenant treats it and as
    /// its integration explains it.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not view workflows.
    /// - `AppError::Internal` when the catalog or the overrides cannot be
    ///   read.
    async fn execute(
        &self,
        ctx: &CallerContext,
        (): (),
    ) -> Result<Vec<OfferedOperation>, AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        WorkflowControl::new(&authority)
            .ensure_may(WorkflowAction::View)
            .map_err(AppError::from_domain)?;
        let overrides = self.ports.risks.list(&ctx.tenant()).await.or_internal()?;
        let offered = self.offered().await?;
        Ok(offered
            .into_iter()
            .map(|declared| as_treated(declared, &overrides))
            .collect())
    }
}

/// `declared` as the tenant treats it under `overrides`.
fn as_treated(
    declared: Declared,
    overrides: &[OperationRiskOverride<ResolvedTenant>],
) -> OfferedOperation {
    OfferedOperation {
        operation: TenantOperation::of(declared.spec, overrides),
        guide: declared.guide,
    }
}

/// The failure of an integration offering `spec` with no guide for it: the
/// wiring is wrong, as installing checks every operation has one.
fn unguided(spec: &OperationSpec) -> DomainError {
    DomainError::infra_msg(format!(
        "{}.{} is offered without a guide",
        spec.integration(),
        spec.operation()
    ))
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::SystemPermission;
    use ianua_domain::types::{ActionClass, DeclaredAction};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::workflows::{
        FakeIntegrationCatalog, FakeOperationRiskOverrideStore, append_row, person,
        raised_to_payment,
    };
    use crate::test_support::{block_on, test_ctx};

    /// The caller, holding what `authorities` say, lists the operations of
    /// a catalog offering "append row" as a write, with the tenant having
    /// raised it to a payment.
    fn list(authorities: FakeTenantAuthorities) -> Result<Vec<OfferedOperation>, AppError> {
        let risk = raised_to_payment(&person("bob@corp.test"));
        let use_case = ListOperationsUseCase::new(ListOperationsPorts {
            catalog: Arc::new(FakeIntegrationCatalog::offering(vec![append_row(
                ActionClass::Write,
            )])),
            risks: Arc::new(FakeOperationRiskOverrideStore::holding(&risk)),
            tenant_authorities: Arc::new(authorities),
        });
        block_on(use_case.execute(&test_ctx(), ()))
    }

    /// Someone who may view workflows.
    fn viewer() -> FakeTenantAuthorities {
        FakeTenantAuthorities::holding(&[SystemPermission::Workflows(WorkflowAction::View)])
    }

    /// Ann builds a workflow and lists what she may use. "Append row" is
    /// listed as the payment the tenant raised it to, not the write the
    /// integration declared.
    #[test]
    fn operations_are_listed_as_the_tenant_treats_them() {
        let listed = list(viewer()).unwrap();

        assert_eq!(listed.len(), 1);
        assert_eq!(
            listed[0].operation.spec().effect(),
            DeclaredAction::Declared(ActionClass::Financial)
        );
    }

    /// Each operation comes with the guide its integration wrote for it,
    /// explaining every input.
    #[test]
    fn each_operation_comes_with_its_guide() {
        let listed = list(viewer()).unwrap();

        let offered = &listed[0];
        assert_eq!(
            offered.guide.operation(),
            offered.operation.spec().operation()
        );
        assert_eq!(
            offered.guide.inputs().len(),
            offered.operation.spec().inputs().len()
        );
    }

    /// An operation without a guide makes the catalog listing fail internally.
    #[test]
    fn an_operation_without_a_guide_fails_the_listing() {
        let use_case = ListOperationsUseCase::new(ListOperationsPorts {
            catalog: Arc::new(
                FakeIntegrationCatalog::offering(vec![append_row(ActionClass::Write)])
                    .without_guides(),
            ),
            risks: Arc::new(FakeOperationRiskOverrideStore::empty()),
            tenant_authorities: Arc::new(viewer()),
        });

        let result = block_on(use_case.execute(&test_ctx(), ()));

        assert!(matches!(result, Err(AppError::Internal(_))));
    }

    /// A caller without workflow rights cannot list integration operations.
    #[test]
    fn a_caller_who_may_not_view_workflows_is_refused() {
        let result = list(FakeTenantAuthorities::holding(&[]));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out session cannot list integration operations.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let result = list(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
