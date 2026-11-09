//! Finding the record of an access token a client or resource presents:
//! an opaque token by its own hash, a JWT access token the tenant signed by
//! the hash of its `jti`.
//!
//! Userinfo, introspection, revocation, token exchange and resolving a
//! token all start here. A JWT the tenant did not sign finds nothing, so it
//! works nowhere.

use std::sync::Arc;

use ianua_domain::domains::oauth::grants::access_token::AccessToken;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{TokenHash, TokenId};

use crate::error::{AppError, OrInternal};
use crate::input::validate_token;
use crate::ports::crypto::VerifyingKeyStore;
use crate::ports::oauth::{AccessTokenJwtVerifier, AccessTokenStore, CodeHasher, PresentedJwt};
use crate::use_cases::oauth::token::client_auth::Asking;

/// The ports finding a presented access token's record.
#[derive(ianua_macros::Fakes)]
pub struct PresentedTokenPorts {
    /// Where issued access tokens are kept.
    pub access_token_store: Arc<dyn AccessTokenStore>,
    /// Hashes the presented token, or a JWT's `jti`.
    pub code_hasher: Arc<dyn CodeHasher>,
    /// The public halves of the tenant's signing keys, to check a JWT
    /// against. Never the private halves: the gateway, which finds tokens
    /// here too, may not read them.
    pub key_store: Arc<dyn VerifyingKeyStore>,
    /// Tells a JWT the tenant signed from an opaque token.
    pub jwt_verifier: Arc<dyn AccessTokenJwtVerifier>,
}

/// The record of the access token `raw`, whatever its state, or `None`
/// when nothing the tenant issued is behind it. An empty or oversized
/// token finds nothing before anything is hashed.
///
/// # Errors
///
/// - `AppError::Internal` when hashing, a check or a lookup fails.
pub(crate) async fn presented_access_token(
    ports: &PresentedTokenPorts,
    asking: Asking<'_>,
    raw: &Secret,
) -> Result<Option<AccessToken<ResolvedTenant>>, AppError> {
    if validate_token("access_token", raw.expose()).is_err() {
        return Ok(None);
    }
    let Some(hash) = record_hash(ports, asking, raw).await? else {
        return Ok(None);
    };
    ports
        .access_token_store
        .find_by_hash(asking.tenant, &hash)
        .await
        .or_internal()
}

/// The hash `raw`'s record is kept under, or `None` for a JWT the tenant
/// did not sign.
async fn record_hash(
    ports: &PresentedTokenPorts,
    asking: Asking<'_>,
    raw: &Secret,
) -> Result<Option<TokenHash>, AppError> {
    let keys = ports.key_store.find(asking.tenant).await.or_internal()?;
    let presented = match keys.is_empty() {
        true => PresentedJwt::Opaque,
        false => ports
            .jwt_verifier
            .classify(raw, &keys, asking.issuer)
            .await
            .or_internal()?,
    };
    let hashed = match presented {
        PresentedJwt::Opaque => raw.clone(),
        PresentedJwt::Signed(jti) => jti_secret(&jti),
        PresentedJwt::Refused => return Ok(None),
    };
    let hash = ports.code_hasher.hash_code(&hashed).await.or_internal()?;
    Ok(Some(hash))
}

/// The value a JWT access token's record is hashed from: its `jti`.
pub(crate) fn jti_secret(jti: &TokenId) -> Secret {
    Secret::new(jti.as_str().to_owned())
}
