//! An organization's own branding: the look of its dashboard and mail.

use async_trait::async_trait;
use ianua_domain::domains::organization::branding::OrgBranding;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::OrganizationId;

/// Dyn-safe port for persisting and retrieving an organization's branding.
#[async_trait]
pub trait OrgBrandingStore: Send + Sync {
    /// The branding of `organization_id`, when anyone saved one.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn find(
        &self,
        organization_id: &OrganizationId,
    ) -> Result<Option<OrgBranding>, DomainError>;

    /// Saves the organization's branding, made or changed.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn save(&self, branding: &OrgBranding) -> Result<(), DomainError>;
}
