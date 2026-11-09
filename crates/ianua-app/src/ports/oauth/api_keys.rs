//! Tenant API keys.

use async_trait::async_trait;
use ianua_domain::domains::oauth::clients::api_key::ApiKey;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{ApiKeyId, CountryCode, Label, TenantId};
use time::OffsetDateTime;

use crate::define_sort_field;
use crate::listing::{Page, PageRequest, SortKey, SortKeys, SortOrder};
use crate::ports::TenantScoped;
use crate::tenancy::ScopedTenant;

/// What became of a key's use written over the stored key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UseRecorded {
    /// It was written.
    Written,
    /// The key was revoked since it was read, and stays revoked.
    Gone,
    /// Another use changed the key's countries since this one read it, so
    /// nothing was written: that use noted what this one would have.
    Overtaken,
}

define_sort_field! {
    /// Field an API key listing can be ordered by.
    pub enum ApiKeySortField {
        /// Order by creation time.
        CreatedAt => "created_at",
        /// Order by display name.
        Name => "name",
        /// Order by expiration time.
        ExpiresAt => "expires_at",
        /// Order by last-used time.
        LastUsedAt => "last_used_at",
    }
    default = CreatedAt;
    default direction = Desc;
}

impl SortKeys<ApiKeySortField> for ApiKey<ResolvedTenant> {
    fn sort_key(&self, field: ApiKeySortField) -> SortKey {
        match field {
            ApiKeySortField::CreatedAt => self.created_at().into(),
            ApiKeySortField::Name => self.name().as_str().into(),
            ApiKeySortField::ExpiresAt => self.expires_at().instant().into(),
            ApiKeySortField::LastUsedAt => self.last_used_at().into(),
        }
    }

    fn tiebreak(&self) -> SortKey {
        self.id().as_uuid().into()
    }
}

/// Dyn-safe port for persisting and retrieving API keys.
#[async_trait]
pub trait ApiKeyStore: Send + Sync + TenantScoped {
    /// Finds an API key by its internal ID.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &ApiKeyId,
    ) -> Result<Option<ApiKey<ResolvedTenant>>, DomainError>;

    /// Lists API keys for the tenant with ordering and pagination.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn list_all(
        &self,
        tenant_id: &ScopedTenant,
        sort: &SortOrder<ApiKeySortField>,
        page: &PageRequest,
    ) -> Result<Page<ApiKey<ResolvedTenant>>, DomainError>;

    /// Keeps a key just made.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn insert(
        &self,
        tenant_id: &ScopedTenant,
        key: &ApiKey<ResolvedTenant>,
    ) -> Result<(), DomainError>;

    /// Writes the name and scopes of `key` over the stored key, only while
    /// it is still kept. Returns whether it was: `false` means the key was
    /// revoked since it was read, and stays revoked.
    ///
    /// A write that inserted a missing key would bring a key revoked
    /// meanwhile back, so storage does it in one `UPDATE .. WHERE id`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn update(
        &self,
        tenant_id: &ScopedTenant,
        key: &ApiKey<ResolvedTenant>,
    ) -> Result<bool, DomainError>;

    /// Writes when, from where and from which countries `key` was last
    /// used over the stored key, only while it is still kept and still
    /// remembers `read_countries`, the countries it held when this use read
    /// it, leaving every other field as stored.
    ///
    /// Storage does it in one `UPDATE .. WHERE id`, so a stamp racing a
    /// revocation never brings the key back, and a stamp racing an edit
    /// never undoes it. Two uses from one new country in the same instant
    /// both read the key without it; only the first write lands, so the
    /// country is noted, and recorded, once.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn record_use(
        &self,
        tenant_id: &ScopedTenant,
        key: &ApiKey<ResolvedTenant>,
        read_countries: &[CountryCode],
    ) -> Result<UseRecorded, DomainError>;

    /// Permanently deletes an API key. Revoking a key removes it rather than
    /// flagging it.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn delete(&self, tenant_id: &ScopedTenant, id: &ApiKeyId) -> Result<(), DomainError>;
}

/// Dyn-safe port for the API key sweep, which works across every tenant.
///
/// Not [`TenantScoped`](crate::ports::TenantScoped): the background expiry
/// sweep has no caller to scope it, and works over every tenant's keys.
#[async_trait]
pub trait CrossTenantApiKeyStore: Send + Sync {
    /// Deletes every key whose `expires_at` is at or before `now`, returning
    /// the `(tenant, id, name)` of each removed key so the caller can audit
    /// the expiry.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn delete_expired(
        &self,
        now: OffsetDateTime,
    ) -> Result<Vec<(TenantId, ApiKeyId, Label)>, DomainError>;
}
