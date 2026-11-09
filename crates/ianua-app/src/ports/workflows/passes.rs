//! Run passes: what a Protected apps or Protected data step carries to the
//! gateway, so its one call acts as the person its run acts for, on the one
//! route or stream route it names.

use async_trait::async_trait;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{ActionCallId, Issuer, UserId};

use crate::ports::TenantScoped;
use crate::ports::authentication::PassReach;
use crate::tenancy::ScopedTenant;

/// What one pass is made for: one call of a run, acting as its person, on
/// one route or stream route.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunPassGrant {
    /// The call it is made for, which the gateway records the request under.
    pub call_id: ActionCallId,
    /// The person the run acts for.
    pub user_id: UserId,
    /// What it reaches, and nothing else.
    pub reaches: PassReach,
}

/// Dyn-safe port making the pass for one call of a Protected apps or
/// Protected data step.
///
/// The adapter signs it with the tenant's key, typed so it is taken only on
/// the gateway's workflow listener, and has it lapse within a minute.
#[async_trait]
pub trait RunPasses: Send + Sync + TenantScoped {
    /// The pass for `grant`, naming `issuer`, the tenant's own token issuer,
    /// as its `iss`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when no signing key is
    /// available or signing fails.
    async fn issue(
        &self,
        tenant_id: &ScopedTenant,
        issuer: &Issuer,
        grant: &RunPassGrant,
    ) -> Result<Secret, DomainError>;
}
