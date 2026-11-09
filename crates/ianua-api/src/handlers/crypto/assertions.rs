//! Assertion key handlers: the public key set upstreams check
//! `X-Ianua-Assertion` with.

use axum::extract::State;
use ianua_app::use_case::Query as _;
use ianua_assembly::crypto::CryptoState;

use crate::dto::crypto::JwksResponse;
use crate::error::{ApiError, ErrorBody};
use crate::extractors::json::Json;
use crate::extractors::public_tenant::PublicTenant;

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/.well-known/ianua-assertion-keys.json",
    tag = "Crypto",
    responses(
        (status = 200, description = "The assertion key set", body = JwksResponse),
        (status = 403, description = "The workspace is not available", body = ErrorBody),
        (status = 404, description = "No such tenant, or no assertion keys", body = ErrorBody)
    )
)]
/// Tenant assertion keys
///
/// Public JWK Set for checking `X-Ianua-Assertion`, separate from tenant
/// token-signing JWKS: neither kind of credential verifies against the other.
/// Includes the active key and keys rotated out within a day, never retired
/// keys; undecodable entries are skipped. Entries carry `kty`, `kid`, `alg`
/// (`ES256`) and key parameters. Refresh on an unknown `kid`; keys rotate
/// every thirty days. Returns `404` before keys exist. Records nothing.
pub(crate) async fn assertion_keys(
    State(crypto): State<CryptoState>,
    tenant: PublicTenant,
) -> Result<Json<JwksResponse>, ApiError> {
    let components = crypto
        .get_assertion_keys
        .execute(&tenant.tenant, ())
        .await?;
    Ok(Json(JwksResponse::from(components)))
}
