//! Organization API keys.

use async_trait::async_trait;
use ianua_domain::domains::organization::access::api_key::OrgApiKey;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{OrgApiKeyId, OrganizationId};

use crate::define_sort_field;
use crate::listing::{Page, PageRequest, SortKey, SortKeys, SortOrder};

define_sort_field! {
    /// Field an org-API-key listing can be ordered by.
    pub enum OrgApiKeySortField {
        /// Order by creation time.
        CreatedAt => "created_at",
        /// Order by human-readable name.
        Name => "name",
        /// Order by last-used time.
        LastUsedAt => "last_used_at",
        /// Order by expiry time.
        ExpiresAt => "expires_at",
    }
    default = CreatedAt;
    default direction = Desc;
}

impl SortKeys<OrgApiKeySortField> for OrgApiKey {
    fn sort_key(&self, field: OrgApiKeySortField) -> SortKey {
        match field {
            OrgApiKeySortField::CreatedAt => self.created_at().into(),
            OrgApiKeySortField::Name => self.name().as_str().into(),
            OrgApiKeySortField::LastUsedAt => self.last_used_at().into(),
            OrgApiKeySortField::ExpiresAt => self.expires_at().instant().into(),
        }
    }

    fn tiebreak(&self) -> SortKey {
        self.id().as_uuid().into()
    }
}

/// Dyn-safe port for org API key persistence.
#[async_trait]
pub trait OrgApiKeyStore: Send + Sync {
    /// Lists API keys for an organization (active and revoked) with ordering
    /// and pagination.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on lookup failure.
    async fn list_by_org(
        &self,
        organization_id: &OrganizationId,
        sort: &SortOrder<OrgApiKeySortField>,
        page: &PageRequest,
    ) -> Result<Page<OrgApiKey>, DomainError>;

    /// Every key of `organization_id` minted through `parent`, directly or
    /// through a key minted through it, at any depth, active and revoked.
    ///
    /// One query walks the whole tree, so revoking a key reaches every key
    /// that carries what it carried.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on lookup failure.
    async fn list_minted_through(
        &self,
        organization_id: &OrganizationId,
        parent: &OrgApiKeyId,
    ) -> Result<Vec<OrgApiKey>, DomainError>;

    /// Finds an API key by ID.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on lookup failure.
    async fn find_by_id(&self, id: &OrgApiKeyId) -> Result<Option<OrgApiKey>, DomainError>;

    /// Saves a new or updated API key.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn save(&self, key: &OrgApiKey) -> Result<(), DomainError>;
}
