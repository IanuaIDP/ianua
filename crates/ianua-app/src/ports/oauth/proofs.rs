//! Checking what a client signs to prove itself (`private_key_jwt`, RFC
//! 7523) and to prove it holds the key its tokens are bound to (`DPoP`,
//! RFC 9449), and that no signed proof is used twice.

use async_trait::async_trait;
use ianua_domain::domains::oauth::clients::credential::ClientKeys;
use ianua_domain::domains::oauth::grants::token_binding::JwkThumbprint;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{ClientId, Issuer, OAuthClientId, TokenId};
use time::OffsetDateTime;

use crate::ports::TenantScoped;
use crate::tenancy::ScopedTenant;

/// What a client assertion proved, once its signature checked out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAssertion {
    /// The client it was signed by: its `iss`, which is also its `sub`.
    pub client: ClientId,
    /// Its `jti`, by which a replay is spotted.
    pub jti: TokenId,
    /// When it stops being accepted, its `exp`.
    pub expires_at: OffsetDateTime,
}

/// Dyn-safe port checking a client assertion: a JWT a `private_key_jwt`
/// client signs with its own key to prove itself at the token endpoint.
///
/// The adapter checks the signature against `keys` with the algorithm the
/// key pins (never the one the header names, never `none`), that `iss`
/// and `sub` are the same client id, that `aud` is `issuer` or the
/// tenant's token endpoint under it, and `exp`, `nbf` and `iat` within a
/// small clock skew. Keys published at an address are fetched with a
/// timeout of a few seconds; a fetch that hangs fails the check.
#[async_trait]
pub trait ClientAssertionVerifier: Send + Sync {
    /// What `assertion` proves, checked against `keys` for `issuer`.
    ///
    /// # Errors
    ///
    /// - `DomainError::Unauthorized` when the assertion does not check out.
    /// - `DomainError::Infrastructure` when published keys cannot be
    ///   fetched in time.
    async fn verify(
        &self,
        assertion: &Secret,
        keys: &ClientKeys,
        issuer: &Issuer,
    ) -> Result<VerifiedAssertion, DomainError>;
}

/// Dyn-safe port remembering the client assertions already used, so a
/// copied one cannot prove its client a second time (RFC 7523 3).
#[async_trait]
pub trait AssertionReplayGuard: Send + Sync + TenantScoped {
    /// Records that `client` used the assertion `jti`, kept until `until`,
    /// and answers whether this was its first use. Storage does it in one
    /// insert that a second use of the same `jti` fails.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn first_use(
        &self,
        tenant_id: &ScopedTenant,
        client: &OAuthClientId,
        jti: &TokenId,
        until: OffsetDateTime,
    ) -> Result<bool, DomainError>;
}

/// The algorithms a `DPoP` proof may be signed with, and the only ones
/// discovery names (`dpop_signing_alg_values_supported`). Never `none`,
/// never a shared secret.
pub const DPOP_SIGNING_ALGORITHMS: [&str; 3] = ["ES256", "RS256", "EdDSA"];

/// What a `DPoP` proof is sent beside.
#[derive(Clone, Copy)]
pub enum DpopUse<'a> {
    /// A request for tokens at the token endpoint, which carries no access
    /// token for the proof to name.
    TokenRequest,
    /// An access token presented to a resource; the proof must name its
    /// hash (`ath`).
    AccessToken(&'a Secret),
}

/// A `DPoP` proof whose signature checked out, as its JWT reads (RFC 9449
/// 4.2). Whether it was made for this request, recently, and only once is
/// the application's question.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedDpopProof {
    /// The thumbprint of the public key in its `jwk` header (RFC 7638),
    /// which signed it.
    pub thumbprint: JwkThumbprint,
    /// Its `jti`, by which a replay is spotted.
    pub jti: TokenId,
    /// The method it was made for (`htm`).
    pub method: String,
    /// The address it was made for (`htu`), as written.
    pub url: String,
    /// When it was made (`iat`).
    pub issued_at: OffsetDateTime,
}

/// Dyn-safe port checking a `DPoP` proof: a JWT a client signs with the key
/// its tokens are bound to, sent in the `DPoP` header of each request.
///
/// The adapter checks that the header's `typ` is `dpop+jwt`, that `alg` is
/// one of [`DPOP_SIGNING_ALGORITHMS`] and suits the key in the `jwk`
/// header, which must be a public key and nothing more; that the signature
/// holds under that key with that algorithm; that `jti`, `htm`, `htu` and
/// `iat` are present; and, for [`DpopUse::AccessToken`], that `ath` is the
/// base64url SHA-256 of the access token. Nothing is fetched.
#[async_trait]
pub trait DpopProofVerifier: Send + Sync {
    /// What `proof`, sent for `sent_for`, says, once it checks out.
    ///
    /// # Errors
    ///
    /// - `DomainError::Unauthorized` when the proof is malformed, its type,
    ///   algorithm or key is refused, its signature does not hold, or its
    ///   `ath` does not name the access token.
    async fn verify(
        &self,
        proof: &Secret,
        sent_for: DpopUse<'_>,
    ) -> Result<SignedDpopProof, DomainError>;
}

/// Dyn-safe port remembering the `DPoP` proofs already used, so a copied one
/// cannot be sent again (RFC 9449 11.1).
#[async_trait]
pub trait DpopReplayGuard: Send + Sync + TenantScoped {
    /// Records that the key of `thumbprint` used the proof `jti`, kept until
    /// `until`, and answers whether this was its first use. Storage does it
    /// in one insert that a second use of the same pair fails.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn first_use(
        &self,
        tenant_id: &ScopedTenant,
        thumbprint: &JwkThumbprint,
        jti: &TokenId,
        until: OffsetDateTime,
    ) -> Result<bool, DomainError>;
}
