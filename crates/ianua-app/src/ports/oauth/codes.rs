//! Authorization codes, consent, and the hashing and PKCE checks behind them.

use async_trait::async_trait;
use ianua_domain::domains::oauth::clients::consent::OAuthConsent;
use ianua_domain::domains::oauth::grants::authorization_code::{
    AuthorizationCode, CodeChallenge, CodeChallengeMethod,
};
use ianua_domain::domains::oauth::grants::logout_notice::SignedOut;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{DeviceUserCode, OAuthClientId, SessionId, TokenHash, UserId};

use crate::ports::TenantScoped;
use crate::tenancy::ScopedTenant;

/// Dyn-safe port for persisting and retrieving authorization codes.
#[async_trait]
pub trait AuthCodeStore: Send + Sync + TenantScoped {
    /// Finds an authorization code by its hash.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn find_by_hash(
        &self,
        tenant_id: &ScopedTenant,
        code_hash: &TokenHash,
    ) -> Result<Option<AuthorizationCode<ResolvedTenant>>, DomainError>;

    /// Saves a new or updated authorization code.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        code: &AuthorizationCode<ResolvedTenant>,
    ) -> Result<(), DomainError>;

    /// Stores `code`, just used up, only if the stored code with its hash is
    /// still unused. Returns whether this call did: of two exchanges of one
    /// code arriving together, only one gets the tokens. Storage does it in
    /// one statement, such as an `UPDATE .. WHERE consumed_at IS NULL`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn redeem(
        &self,
        tenant_id: &ScopedTenant,
        code: &AuthorizationCode<ResolvedTenant>,
    ) -> Result<bool, DomainError>;

    /// The client/session pairs affected by `signed_out`, each once, from
    /// codes storage still keeps. A single-session sign-out reads only
    /// that person's selected session; signing out everywhere reads all
    /// their sessions in this tenant.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn consented_sessions(
        &self,
        tenant_id: &ScopedTenant,
        signed_out: SignedOut,
    ) -> Result<Vec<ConsentedSession>, DomainError>;
}

/// A client a person consented to, and the session they did it in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConsentedSession {
    /// The application granted access by this consent.
    pub client: OAuthClientId,
    /// The session the person consented in.
    pub session: SessionId,
}

/// Dyn-safe port for persisting and retrieving OAuth consent grants.
#[async_trait]
pub trait OAuthConsentStore: Send + Sync + TenantScoped {
    /// Finds the consent grant for a user/client pair.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn find(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
        client_id: &OAuthClientId,
    ) -> Result<Option<OAuthConsent<ResolvedTenant>>, DomainError>;

    /// Saves a new or updated consent grant.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        consent: &OAuthConsent<ResolvedTenant>,
    ) -> Result<(), DomainError>;

    /// Every consent `user_id` gave, to any client, newest first, including
    /// ones withdrawn since (they hold no scope).
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn list_for_user(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<Vec<OAuthConsent<ResolvedTenant>>, DomainError>;
}

/// Dyn-safe port for hashing authorization codes and device codes.
#[async_trait]
pub trait CodeHasher: Send + Sync {
    /// The hash of a raw code, as [`Self::generate_code`] would have made it.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` if the hash cannot be made.
    async fn hash_code(&self, raw_code: &Secret) -> Result<TokenHash, DomainError>;

    /// Generates a random raw code and returns `(raw_code, hash)`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the randomness source fails.
    async fn generate_code(&self) -> Result<(Secret, TokenHash), DomainError>;

    /// Generates a short user-facing code (e.g. `"ABCD-1234"`).
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the randomness source fails.
    async fn generate_user_code(&self) -> Result<DeviceUserCode, DomainError>;

    /// Generates a random device code and returns `(raw_code, hash)`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the randomness source fails.
    async fn generate_device_code(&self) -> Result<(Secret, TokenHash), DomainError>;
}

/// Dyn-safe port turning a PKCE code verifier into its challenge.
///
/// The authorization code compares the challenge with its own, so the
/// comparison stays in the domain and this port only hashes.
#[async_trait]
pub trait PkceVerifier: Send + Sync {
    /// The challenge `verifier` makes under `method`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Validation` if the verifier is not one RFC 7636
    /// allows.
    async fn challenge_for(
        &self,
        verifier: &Secret,
        method: CodeChallengeMethod,
    ) -> Result<CodeChallenge, DomainError>;
}
