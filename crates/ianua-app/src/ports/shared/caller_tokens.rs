//! Turning a presented token into the caller behind it.

use async_trait::async_trait;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{Expiry, OrganizationId, TenantId, TokenHash};

use crate::context::{CallerIdentity, Credential};

/// Who a bearer token belongs to, and the stored credential it names.
///
/// It claims no permission. What the credential lets its holder do is worked
/// out by [`acting`](crate::acting) from the stored record.
///
/// For sessions and tenant API keys, `organization_id` and `tenant_id` are
/// both present. An organization API key or session carries its organization
/// but no tenant. For platform operators both are `None`, since operators
/// stand outside the organization and tenant hierarchy.
#[derive(Debug, Clone)]
pub struct ResolvedCaller {
    /// Who the caller is.
    pub identity: CallerIdentity,
    /// The stored credential the token names.
    pub credential: Credential,
    /// The organization the caller belongs to (`None` for operators).
    pub organization_id: Option<OrganizationId>,
    /// The tenant the caller belongs to (`None` for operators and
    /// organization members).
    pub tenant_id: Option<TenantId>,
    /// Until when a cache may serve this caller again without asking the
    /// store: the credential's end. For a session that is its absolute end.
    /// Its row holds when it was last used but not how long the tenant lets
    /// it sit idle, and the idle timeout is checked on every request where
    /// the session is loaded to act, never from a copy. `Expiry::Never`
    /// only for a key made without an end.
    pub kept_until: Expiry,
}

/// Dyn-safe port for resolving bearer tokens into caller identity.
///
/// The middleware calls this on every authenticated request.
/// Implementations may validate JWTs, look up sessions by refresh token
/// hash, or check API key prefixes. The middleware does not know which.
#[async_trait]
pub trait TokenResolver: Send + Sync {
    /// Resolves a bearer token into the caller's identity.
    ///
    /// Returns `Ok(None)` if the token is invalid, expired or revoked.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` if a lookup fails.
    async fn resolve(&self, token: &Secret) -> Result<Option<ResolvedCaller>, DomainError>;
}

/// Dyn-safe port for cross-tenant token lookups.
///
/// Used by [`TokenResolver`] implementations to look up sessions and API
/// keys by their hashed token. These lookups are cross-tenant because the
/// token itself decides which tenant it belongs to; the resolver does not
/// know the tenant yet.
///
/// This port is not [`TenantScoped`]: it works across all tenants by design.
#[async_trait]
pub trait TokenLookup: Send + Sync {
    /// Finds an active session by the hash of its refresh token.
    ///
    /// Returns `None` if the hash matches no session or the session is
    /// revoked or expired.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` if the lookup fails.
    async fn find_session_by_token_hash(
        &self,
        token_hash: &TokenHash,
    ) -> Result<Option<ResolvedCaller>, DomainError>;

    /// Finds an active organization session by the hash of its refresh
    /// token.
    ///
    /// Returns `None` if no active session matches.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` if the lookup fails.
    async fn find_org_session_by_token_hash(
        &self,
        token_hash: &TokenHash,
    ) -> Result<Option<ResolvedCaller>, DomainError>;

    /// Finds an active tenant API key by its hash.
    ///
    /// The caller is the key's creator. Returns `None` if the hash matches
    /// no key or the key is revoked or expired.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` if the lookup fails.
    async fn find_api_key_by_key_hash(
        &self,
        key_hash: &TokenHash,
    ) -> Result<Option<ResolvedCaller>, DomainError>;

    /// Finds an active organization API key by its hash.
    ///
    /// The caller is the member who made it. Returns `None` if the key is
    /// unknown, revoked or expired. Organization keys use the `oak_` prefix
    /// and live in `org_api_keys`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` if the lookup fails.
    async fn find_org_api_key_by_hash(
        &self,
        key_hash: &TokenHash,
    ) -> Result<Option<ResolvedCaller>, DomainError>;

    /// Finds an active operator API key by its hash.
    ///
    /// Returns `None` if no active key matches. Operator keys use the `opk_`
    /// prefix and live in the control plane database (`operator_api_keys`).
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` if the lookup fails.
    async fn find_operator_key_by_hash(
        &self,
        key_hash: &TokenHash,
    ) -> Result<Option<ResolvedCaller>, DomainError>;
}
