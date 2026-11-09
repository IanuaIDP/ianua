//! What only the signer's side can work out about the JWTs OAuth hands out
//! and takes back: the `at_hash` of an access token, and whether a JWT a
//! client presents was signed by the tenant.

use async_trait::async_trait;
use ianua_domain::domains::crypto::signing_key::{SigningAlgorithm, SigningKeySet};
use ianua_domain::domains::crypto::verifying_key::VerifyingKey;
use ianua_domain::domains::oauth::grants::id_token::AccessTokenHash;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{ClientId, Issuer, SessionId, TokenId, UserId};

/// Dyn-safe port working out the `at_hash` of an access token (OIDC Core
/// 3.1.3.6): the left half of its hash under the hash function of the
/// algorithm the ID token is signed with.
#[async_trait]
pub trait AtHashCalculator: Send + Sync {
    /// The `at_hash` of `access_token` for an ID token signed with
    /// `algorithm`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the hash cannot be made.
    async fn at_hash(
        &self,
        access_token: &Secret,
        algorithm: SigningAlgorithm,
    ) -> Result<AccessTokenHash, DomainError>;
}

/// The claims of an ID token the tenant signed, read back from an
/// `id_token_hint`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HintClaims {
    /// The client it was issued to, its `aud`.
    pub audience: ClientId,
    /// The person it is about, its `sub`.
    pub subject: UserId,
    /// The session it was issued in, its `sid`.
    pub session: SessionId,
}

/// Dyn-safe port reading an `id_token_hint` (OIDC Core 3.1.2.1,
/// RP-Initiated Logout 2).
///
/// The adapter checks the signature against `keys` with the algorithm the
/// key pins, never `none`, the `typ` of an ID token, and that `iss` is
/// `issuer`. It does not check `exp`: an app signing a person out often
/// holds an ID token that ran out long ago.
#[async_trait]
pub trait IdTokenHintVerifier: Send + Sync {
    /// The claims `hint` carries, once its signature and issuer checked
    /// out.
    ///
    /// # Errors
    ///
    /// - `DomainError::Unauthorized` when the hint was not signed by the
    ///   tenant for `issuer`, or lacks `aud`, `sub` or `sid`.
    async fn verify(
        &self,
        hint: &Secret,
        keys: &SigningKeySet<ResolvedTenant>,
        issuer: &Issuer,
    ) -> Result<HintClaims, DomainError>;
}

/// What a presented access token turned out to be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PresentedJwt {
    /// Not a JWT at all: an opaque token, found by its own hash.
    Opaque,
    /// A JWT access token the tenant signed, found by the hash of its
    /// `jti`.
    Signed(TokenId),
    /// A JWT the tenant did not sign, or not an access token: it works
    /// nowhere.
    Refused,
}

/// Dyn-safe port telling a JWT access token the tenant signed (RFC 9068)
/// from an opaque one, so its record can be found.
///
/// The adapter checks the signature against `keys` with the algorithm the
/// key pins, the `at+jwt` type and that `iss` is `issuer`. Expiry and
/// revocation are the record's to say.
#[async_trait]
pub trait AccessTokenJwtVerifier: Send + Sync {
    /// What `token` is.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the check itself fails.
    async fn classify(
        &self,
        token: &Secret,
        keys: &[VerifyingKey],
        issuer: &Issuer,
    ) -> Result<PresentedJwt, DomainError>;
}
