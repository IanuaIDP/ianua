//! Device authorization requests.

use async_trait::async_trait;
use ianua_domain::domains::oauth::grants::device_authorization::DeviceAuthorization;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{DeviceUserCode, TokenHash};
use time::OffsetDateTime;

use crate::ports::TenantScoped;
use crate::tenancy::ScopedTenant;

/// The maximum pending device requests returned by one expiry read.
pub const DEVICE_EXPIRY_BATCH: usize = 500;

/// Dyn-safe port for persisting and retrieving device authorizations.
#[async_trait]
pub trait DeviceAuthStore: Send + Sync + TenantScoped {
    /// At most [`DEVICE_EXPIRY_BATCH`] pending authorizations whose expiry is
    /// at or before `now`, read through this tenant's current database route.
    /// Expiry saves consume each batch before the sweep asks again.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence or decoding failure.
    async fn list_lapsed(
        &self,
        tenant: &ScopedTenant,
        now: OffsetDateTime,
    ) -> Result<Vec<DeviceAuthorization<ResolvedTenant>>, DomainError>;
    /// Finds a device authorization by its device code hash.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn find_by_device_code_hash(
        &self,
        tenant_id: &ScopedTenant,
        device_code_hash: &TokenHash,
    ) -> Result<Option<DeviceAuthorization<ResolvedTenant>>, DomainError>;

    /// Finds a device authorization by its user code.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn find_by_user_code(
        &self,
        tenant_id: &ScopedTenant,
        user_code: &DeviceUserCode,
    ) -> Result<Option<DeviceAuthorization<ResolvedTenant>>, DomainError>;

    /// Saves a new or updated device authorization.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        auth: &DeviceAuthorization<ResolvedTenant>,
    ) -> Result<(), DomainError>;

    /// Marks the authorization with this device code hash redeemed, if it is
    /// still approved and unexpired at `now`. Returns whether this call did:
    /// of two polls arriving together, only one gets the approval.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn redeem(
        &self,
        tenant_id: &ScopedTenant,
        device_code_hash: &TokenHash,
        now: OffsetDateTime,
    ) -> Result<bool, DomainError>;

    /// Writes when `auth` was last polled and its interval over the stored
    /// authorization, leaving its state as stored.
    ///
    /// A poll that saved the whole authorization would undo an approval
    /// that landed between its read and its write; storage writes the two
    /// columns alone, in one `UPDATE .. WHERE device_code_hash`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn record_poll(
        &self,
        tenant_id: &ScopedTenant,
        auth: &DeviceAuthorization<ResolvedTenant>,
    ) -> Result<(), DomainError>;
}
