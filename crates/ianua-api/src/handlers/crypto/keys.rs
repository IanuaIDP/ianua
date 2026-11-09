//! Signing key handlers: a tenant's key set, rotating and revoking a key,
//! and the public JWKS document relying parties verify tokens with.

use axum::extract::{Path, State};
use ianua_app::use_case::{Command as _, Query as _};
use ianua_assembly::crypto::CryptoState;

use crate::dto::crypto::{JwksResponse, KeySetResponse, NewKeyResponse, RotateKeyBody};
use crate::error::{ApiError, ErrorBody};
use crate::extractors::callers::TenantCaller;
use crate::extractors::json::Json;
use crate::extractors::paths::crypto::SigningKeyPath;
use crate::extractors::public_tenant::PublicTenant;
use crate::response::NoContent;

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/crypto/keys",
    tag = "Crypto",
    responses(
        (status = 200, description = "Success", body = KeySetResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No key set yet", body = ErrorBody)
    )
)]
/// Tenant signing key set
///
/// Returns every signing key for this tenant with its `kid`, `algorithm`
/// (`RS256`, `ES256`, `EdDSA`), `status`, and timestamps. `active` keys
/// sign new tokens; `rotated` keys no longer sign but stay in JWKS through
/// the grace period so existing tokens keep verifying; `revoked` keys are
/// terminal and absent from JWKS. Returns `404` when the tenant has no key
/// set yet. Records nothing. Requires `Crypto(View)`.
pub(crate) async fn get_key_set(
    State(crypto): State<CryptoState>,
    tenant: TenantCaller,
) -> Result<Json<KeySetResponse>, ApiError> {
    let set = crypto.get_key_set.execute(&tenant.caller, ()).await?;
    Ok(Json(KeySetResponse::from(set)))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/crypto/keys/rotate",
    tag = "Crypto",
    request_body = RotateKeyBody,
    responses(
        (status = 200, description = "Success", body = NewKeyResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Rotate the active signing key
///
/// Mints a new key in the given `algorithm` and demotes the current active
/// key to `rotated`. The old key stays in JWKS for verification during the
/// grace period; the new key becomes the sole `active` signer. If the
/// tenant has no key set yet, this creates one. Returns the new key's
/// `key_id`. Rotation never revokes; use the revoke endpoint for that.
///
/// Records `crypto.key_rotated` (or `crypto.key_created` for a first key).
/// Requires `Crypto(Update)`.
pub(crate) async fn rotate_key(
    State(crypto): State<CryptoState>,
    tenant: TenantCaller,
    Json(body): Json<RotateKeyBody>,
) -> Result<Json<NewKeyResponse>, ApiError> {
    let key_id = crypto
        .rotate_key
        .execute(&tenant.caller, &tenant.auditor, body.algorithm)
        .await?;
    Ok(Json(NewKeyResponse { key_id }))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/crypto/keys/{id}/revoke",
    tag = "Crypto",
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such key", body = ErrorBody),
        (status = 409, description = "Already revoked, or the only active key", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Revoke a signing key
///
/// Permanently revokes a key by `id` (its `kid`): it goes
/// `active | rotated -> revoked` (terminal) and is removed from JWKS, so
/// tokens it signed can no longer be verified by relying parties.
///
/// Returns `404` if no key set exists or the `kid` is unknown, `409` if the
/// key is already revoked, and `409` if it is the only active key: a tenant
/// must always keep a key that can sign. Records `crypto.key_revoked`.
/// Requires `Crypto(Update)`.
pub(crate) async fn revoke_key(
    State(crypto): State<CryptoState>,
    tenant: TenantCaller,
    Path(path): Path<SigningKeyPath>,
) -> Result<NoContent, ApiError> {
    crypto
        .revoke_key
        .execute(&tenant.caller, &tenant.auditor, path.key()?)
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/.well-known/jwks.json",
    tag = "OIDC Provider",
    responses(
        (status = 200, description = "JWKS", body = JwksResponse),
        (status = 403, description = "The workspace is not available", body = ErrorBody),
        (status = 404, description = "No such tenant, or no keys", body = ErrorBody)
    )
)]
/// Tenant public signing keys (JWKS)
///
/// Serves the tenant's public signing keys as a JWKS document, so relying
/// parties can verify tokens this tenant issued. Includes every key still
/// published: active ones, and rotated ones through the grace period; never
/// revoked ones. Each entry gives `kty`, `kid`, `alg`, and the key
/// parameters (RSA `n`/`e`, EC `crv`/`x`/`y`, or EdDSA `crv`/`x`). A key
/// that fails to decode is skipped rather than failing the whole set.
///
/// Returns `404` if the tenant has no key set yet. Public: no
/// authentication. Records nothing.
pub(crate) async fn jwks(
    State(crypto): State<CryptoState>,
    tenant: PublicTenant,
) -> Result<Json<JwksResponse>, ApiError> {
    let components = crypto.get_jwks.execute(&tenant.tenant, ()).await?;
    Ok(Json(JwksResponse::from(components)))
}
