//! Where tenant sessions are kept.

use async_trait::async_trait;
use ianua_domain::domains::authentication::sessions::session::Session;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{SessionId, TokenHash, UserId};
use time::OffsetDateTime;

use crate::ports::TenantScoped;
use crate::tenancy::ScopedTenant;

/// Dyn-safe port for session persistence.
#[async_trait]
pub trait SessionStore: Send + Sync + TenantScoped {
    /// Finds a session by its ID.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` if the lookup fails or the row
    /// is broken.
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &SessionId,
    ) -> Result<Option<Session<ResolvedTenant>>, DomainError>;

    /// Finds a session by the hash of its refresh token.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` if the lookup fails or the row
    /// is broken.
    async fn find_by_refresh_token_hash(
        &self,
        tenant_id: &ScopedTenant,
        hash: &TokenHash,
    ) -> Result<Option<Session<ResolvedTenant>>, DomainError>;

    /// Saves a new or updated session.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` if the write fails.
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        session: &Session<ResolvedTenant>,
    ) -> Result<(), DomainError>;

    /// Writes where `session` was last used, while the stored one is
    /// still active. Nothing else about the row changes, so a busy
    /// session's bookkeeping can never undo a freeze another request made.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` if the write fails.
    async fn keep_last_use(
        &self,
        tenant_id: &ScopedTenant,
        session: &Session<ResolvedTenant>,
    ) -> Result<(), DomainError>;

    /// Writes that `session` has stopped, only while the stored one is
    /// still active, and answers whether this call was the one that did
    /// it. Of two requests that both saw a session look taken over, only
    /// one gets `true`, and only that one records an event.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` if the write fails.
    async fn stop_if_active(
        &self,
        tenant_id: &ScopedTenant,
        session: &Session<ResolvedTenant>,
    ) -> Result<bool, DomainError>;

    /// Writes `parent`, just retired by a refresh, and keeps `child`, the
    /// session carrying it on, only while the stored parent is still
    /// active. Returns whether it was: of two refreshes presenting one
    /// token together, only one gets `true`, and the other learns the
    /// token was swapped already.
    ///
    /// Storage does it in one statement, such as
    /// `WITH retired AS (UPDATE sessions SET status = 'revoked' WHERE
    /// tenant_id = $1 AND id = $2 AND status = 'active' RETURNING id)
    /// INSERT INTO sessions (..) SELECT .. FROM retired`, so a child is
    /// never kept for a parent another refresh retired.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` if the write fails.
    async fn rotate(
        &self,
        tenant_id: &ScopedTenant,
        parent: &Session<ResolvedTenant>,
        child: &Session<ResolvedTenant>,
    ) -> Result<bool, DomainError>;

    /// Whether a refresh replaced the session `id` with a newer one: some
    /// session names it as its parent. A revoked session that was replaced
    /// had its token swapped out; one that was not was ended by logout.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` if the lookup fails.
    async fn was_rotated(
        &self,
        tenant_id: &ScopedTenant,
        id: &SessionId,
    ) -> Result<bool, DomainError>;

    /// The sessions `user_id` holds that are still active, newest sign-in
    /// first.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` if the lookup fails or a row
    /// is broken.
    async fn list_active_by_user(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<Vec<Session<ResolvedTenant>>, DomainError>;

    /// Every session of `user_id` still kept, open or ended, newest
    /// sign-in first. A refresh replaces a session with a new one, so only
    /// the last of each line of refreshes is listed: one session for each
    /// time the person signed in.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` if the lookup fails or a row
    /// is broken.
    async fn list_by_user(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<Vec<Session<ResolvedTenant>>, DomainError>;

    /// Removes the tenant's sessions over by `cutoff`, as the domain's
    /// retention rule says: those that expired before it, and those ended
    /// and last used before it that no later session replaced by a refresh.
    /// Answers how many went. A session in force is never removed.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` if the write fails; nothing is
    /// removed then.
    async fn purge_ended(
        &self,
        tenant_id: &ScopedTenant,
        cutoff: OffsetDateTime,
    ) -> Result<u64, DomainError>;

    /// Revokes all sessions for a user, and says how many it revoked.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` if the write fails.
    async fn revoke_all_by_user(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<u64, DomainError>;

    /// Revokes all active sessions in the tenant, and says how many it
    /// revoked.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` if the write fails.
    async fn revoke_all_by_tenant(&self, tenant_id: &ScopedTenant) -> Result<u64, DomainError>;
}
