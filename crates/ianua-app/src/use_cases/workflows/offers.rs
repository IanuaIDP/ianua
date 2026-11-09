//! What the integration catalog offers now, as the tenant treats it.
//!
//! An operation reaches a workflow only through the tenant's overrides, at
//! publish and again before every call, so a risk the tenant raised is never
//! left out.

use ianua_domain::domains::workflows::design::graph::WorkflowGraph;
use ianua_domain::domains::workflows::integration::risk_override::{
    OperationRiskOverride, TenantOperation,
};
use ianua_domain::domains::workflows::integration::{ActionStep, IntegrationKey};
use ianua_domain::isolation::scope::ResolvedTenant;

use crate::error::{AppError, OrInternal};
use crate::ports::workflows::{IntegrationCatalog, OperationRiskOverrideStore};
use crate::tenancy::ScopedTenant;

/// Where the operations a tenant is offered are read from.
pub(crate) struct Offers<'a> {
    /// The integrations installed and what they declare.
    pub(crate) catalog: &'a dyn IntegrationCatalog,
    /// The tenant's raised views of operations.
    pub(crate) risks: &'a dyn OperationRiskOverrideStore,
}

impl Offers<'_> {
    /// Every operation `graph`'s action steps use that is offered now, as
    /// the tenant treats it. One missing from it is no longer offered.
    ///
    /// # Errors
    ///
    /// - `AppError::Internal` when the catalog or the overrides cannot be
    ///   read.
    pub(crate) async fn used_by(
        &self,
        tenant: &ScopedTenant,
        graph: &WorkflowGraph,
    ) -> Result<Vec<TenantOperation>, AppError> {
        let steps = action_steps(graph);
        let overrides = self.risks.list(tenant).await.or_internal()?;
        let mut offered = Vec::new();
        for integration in integrations_of(&steps) {
            let specs = self.catalog.offered(integration).await.or_internal()?;
            offered.extend(
                specs
                    .into_iter()
                    .filter(|spec| {
                        steps.iter().any(|step| {
                            step.integration() == spec.integration()
                                && step.operation() == spec.operation()
                        })
                    })
                    .map(|spec| TenantOperation::of(spec, &overrides)),
            );
        }
        Ok(offered)
    }

    /// The operation `step` calls, as the tenant treats it now. `None` when
    /// its integration no longer offers it.
    ///
    /// # Errors
    ///
    /// - `AppError::Internal` when the catalog or the overrides cannot be
    ///   read.
    pub(crate) async fn for_step(
        &self,
        tenant: &ScopedTenant,
        step: &ActionStep,
    ) -> Result<Option<TenantOperation>, AppError> {
        let specs = self
            .catalog
            .offered(step.integration())
            .await
            .or_internal()?;
        let Some(spec) = specs
            .into_iter()
            .find(|spec| spec.operation() == step.operation())
        else {
            return Ok(None);
        };
        let overrides: Vec<OperationRiskOverride<ResolvedTenant>> =
            self.risks.list(tenant).await.or_internal()?;
        Ok(Some(TenantOperation::of(spec, &overrides)))
    }
}

/// Every action step of `graph`, a loop's own steps included.
fn action_steps(graph: &WorkflowGraph) -> Vec<&ActionStep> {
    graph.action_steps().map(|(_, step)| step).collect()
}

/// The integrations `steps` call, each once.
fn integrations_of<'a>(steps: &[&'a ActionStep]) -> Vec<&'a IntegrationKey> {
    let mut integrations: Vec<&IntegrationKey> = Vec::new();
    for step in steps {
        if !integrations.contains(&step.integration()) {
            integrations.push(step.integration());
        }
    }
    integrations
}
