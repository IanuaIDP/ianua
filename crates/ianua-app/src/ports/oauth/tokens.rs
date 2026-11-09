//! Issued access and refresh tokens.

use async_trait::async_trait;
use ianua_domain::domains::oauth::grants::access_token::AccessToken;
use ianua_domain::domains::oauth::grants::refresh_token::OAuthRefreshToken;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{OAuthClientId, RefreshFamilyId, SessionId, TokenHash, UserId};
use time::OffsetDateTime;

use crate::ports::TenantScoped;
use crate::tenancy::ScopedTenant;

/// Dyn-safe port for persisting and retrieving issued access tokens.
///
/// Without this the token endpoint's output is unverifiable, and every
/// OAuth-protected resource has to fall back to some other bearer credential.
#[async_trait]
pub trait AccessTokenStore: Send + Sync + TenantScoped {
    /// Finds an issued access token by its hash.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn find_by_hash(
        &self,
        tenant_id: &ScopedTenant,
        token_hash: &TokenHash,
    ) -> Result<Option<AccessToken<ResolvedTenant>>, DomainError>;

    /// Saves a newly issued or updated access token.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        token: &AccessToken<ResolvedTenant>,
    ) -> Result<(), DomainError>;

    /// Revokes, at `now`, every token still in force that `client` holds
    /// for `person`, as when the person withdraws their consent. A token
    /// revoked already keeps its time.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn revoke_grant(
        &self,
        tenant_id: &ScopedTenant,
        person: &UserId,
        client: &OAuthClientId,
        now: OffsetDateTime,
    ) -> Result<(), DomainError>;
}

/// How storage answered a rotation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshRotation {
    /// The used token was retired and the next one kept.
    Rotated,
    /// Another refresh rotated the used token first. Its family was revoked
    /// in the same transaction and nothing was kept.
    Reused,
    /// The used token was revoked or removed meanwhile. Nothing was kept.
    Ended,
}

/// Dyn-safe port for persisting refresh tokens and their families.
///
/// Each write that ends a token runs as one statement that only touches
/// tokens still active, as [`OAuthRefreshToken::revoke`] would leave them,
/// so a token rotated or revoked meanwhile keeps the time it stopped
/// working.
#[async_trait]
pub trait RefreshTokenStore: Send + Sync + TenantScoped {
    /// Finds a refresh token by its hash, whatever its state.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn find_by_hash(
        &self,
        tenant_id: &ScopedTenant,
        token_hash: &TokenHash,
    ) -> Result<Option<OAuthRefreshToken<ResolvedTenant>>, DomainError>;

    /// Keeps the first token of a new family.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn insert(
        &self,
        tenant_id: &ScopedTenant,
        token: &OAuthRefreshToken<ResolvedTenant>,
    ) -> Result<(), DomainError>;

    /// Writes `used`, just rotated, over the stored token only while that
    /// one is still active, and keeps `next` beside it, in one transaction.
    /// Of two refreshes with one token arriving together, only one gets the
    /// next token. The other found it rotated: a copy is in use, so the same
    /// transaction revokes every active token of its family, at the time
    /// `used` was rotated, and answers [`RefreshRotation::Reused`].
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn rotate(
        &self,
        tenant_id: &ScopedTenant,
        used: &OAuthRefreshToken<ResolvedTenant>,
        next: &OAuthRefreshToken<ResolvedTenant>,
    ) -> Result<RefreshRotation, DomainError>;

    /// Revokes, at `now`, every active token of `family`, as when one of
    /// its rotated tokens is presented again.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn revoke_family(
        &self,
        tenant_id: &ScopedTenant,
        family: &RefreshFamilyId,
        now: OffsetDateTime,
    ) -> Result<(), DomainError>;

    /// Revokes, at `now`, every active token whose grant was given in
    /// `session`, as when the person signs out of it.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn revoke_session(
        &self,
        tenant_id: &ScopedTenant,
        session: &SessionId,
        now: OffsetDateTime,
    ) -> Result<(), DomainError>;

    /// Revokes, at `now`, every active token `client` holds for `person`,
    /// as when the person withdraws their consent.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn revoke_grant(
        &self,
        tenant_id: &ScopedTenant,
        person: &UserId,
        client: &OAuthClientId,
        now: OffsetDateTime,
    ) -> Result<(), DomainError>;
}
