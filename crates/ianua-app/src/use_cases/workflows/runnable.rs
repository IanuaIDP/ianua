//! Which sandbox versions a graph's code steps name may run now, and
//! whether each one's code reaches the network.
//!
//! Publishing refuses code that may not run and asks for an approval before
//! code that reaches the network; a test stands in for code that reaches
//! the network. Both read it here, so they never disagree.

use ianua_domain::domains::workflows::design::graph::WorkflowGraph;
use ianua_domain::domains::workflows::design::workflow::{CodeReach, RunnableCode};
use ianua_domain::domains::workflows::sandbox::SandboxStatus;
use ianua_domain::types::SandboxVersionId;

use crate::error::{AppError, OrInternal};
use crate::ports::workflows::{SandboxStore, SandboxVersionStore};
use crate::tenancy::ScopedTenant;

/// Where the sandboxes and their versions are read from.
pub(crate) struct Runnable<'a> {
    /// The tenant's sandboxes.
    pub(crate) sandboxes: &'a dyn SandboxStore,
    /// Loads code revisions to verify they are ready and permitted to run.
    pub(crate) versions: &'a dyn SandboxVersionStore,
}

impl Runnable<'_> {
    /// The sandbox versions `graph`'s code steps name that may run now:
    /// kept for the tenant, with a bundle ready or an image cleared, of a
    /// sandbox not archived;
    /// each with whether its code reaches the network.
    ///
    /// # Errors
    ///
    /// - `AppError::Internal` when a store fails.
    pub(crate) async fn in_graph(
        &self,
        tenant: &ScopedTenant,
        graph: &WorkflowGraph,
    ) -> Result<Vec<RunnableCode>, AppError> {
        let mut runnable = Vec::new();
        for (_, step) in graph.code_steps() {
            if let Some(code) = self.code(tenant, &step.version()).await? {
                runnable.push(code);
            }
        }
        Ok(runnable)
    }

    /// Sandbox version `id`, when it may run now, with whether its code
    /// reaches the network; `None` when it may not run.
    async fn code(
        &self,
        tenant: &ScopedTenant,
        id: &SandboxVersionId,
    ) -> Result<Option<RunnableCode>, AppError> {
        let version = self.versions.find_by_id(tenant, id).await.or_internal()?;
        let Some(version) = version.filter(|version| version.build().is_ready()) else {
            return Ok(None);
        };
        let sandbox = self
            .sandboxes
            .find_by_id(tenant, version.sandbox_id())
            .await
            .or_internal()?;
        if !sandbox.is_some_and(|sandbox| sandbox.status() == SandboxStatus::Active) {
            return Ok(None);
        }
        let reach = match version.recipe().network().is_closed() {
            true => CodeReach::Closed,
            false => CodeReach::Networked,
        };
        Ok(Some(RunnableCode {
            version: *id,
            reach,
        }))
    }
}
