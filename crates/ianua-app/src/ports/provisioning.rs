//! Progress of a tenant's setup, as each step ends.
//!
//! A live broadcast for whoever watches a tenant come up, never persisted:
//! the setup itself keeps how far it got. It is not the workflows product
//! (`domains::workflows`), and not a domain event.

use async_trait::async_trait;
use ianua_domain::domains::tenant::setup::SetupStep;
use ianua_domain::shared::model::steps::RunOutcome;
use ianua_domain::types::{OrganizationId, TenantId, UntrustedText};

/// How one step of a setup ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepOutcome {
    /// The step completed and setup may advance.
    Done,
    /// It failed for good, and the setup stopped.
    Failed,
}

/// One step of a tenant's setup ended.
#[derive(Debug, Clone)]
pub struct SetupProgress {
    /// The tenant set up.
    pub tenant_id: TenantId,
    /// The organization the tenant belongs to, whose stream shows it.
    pub organization_id: OrganizationId,
    /// The step that ended.
    pub step: SetupStep,
    /// How it ended.
    pub step_outcome: StepOutcome,
    /// Steps done so far.
    pub done_steps: u32,
    /// Steps in all.
    pub total_steps: u32,
    /// How the setup stands now.
    pub setup: RunOutcome,
    /// Why the step failed, in the words it reported; none unless it did.
    /// Carried here because it is the one place someone watching reads it.
    pub failure_reason: Option<UntrustedText>,
}

/// Dyn-safe port told of each step of a setup that ended.
///
/// Calls are best-effort: a failure is logged, never handed back to the
/// setup, which keeps its own progress.
#[async_trait]
pub trait SetupProgressObserver: Send + Sync {
    /// Called when a step is done or failed.
    async fn on_progress(&self, progress: &SetupProgress);
}
