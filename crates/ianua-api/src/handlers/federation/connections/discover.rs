//! Home realm discovery: the connection a person's address is sent to sign
//! in through.

use axum::extract::State;
use ianua_app::use_case::Query as _;
use ianua_assembly::federation::FederationState;

use crate::dto::federation::discovery::{DiscoverRealmBody, HomeRealmResponse};
use crate::error::{ApiError, ErrorBody};
use crate::extractors::json::Json;
use crate::extractors::public_tenant::PublicTenant;

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/federation/discover",
    tag = "Federation",
    request_body = DiscoverRealmBody,
    responses(
        (status = 200, description = "Where the address signs in", body = HomeRealmResponse),
        (status = 403, description = "The workspace is not available", body = ErrorBody),
        (status = 404, description = "No such tenant", body = ErrorBody),
        (status = 422, description = "Not an email address", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Find where an address signs in
///
/// The sign-in page asks with the address a person typed. When its domain
/// is the domain hint of an active connection, the answer names that
/// connection (`routed: true`), and the page sends the person to its
/// `.../connections/{id}/login`; otherwise `routed` is `false` and they sign
/// in here. Public, limited per address; the address travels in the body so
/// it stays out of logs. Records nothing.
pub(crate) async fn discover_home_realm(
    State(federation): State<FederationState>,
    tenant: PublicTenant,
    Json(body): Json<DiscoverRealmBody>,
) -> Result<Json<HomeRealmResponse>, ApiError> {
    let realm = federation
        .connections
        .discover
        .execute(&tenant.tenant, body.try_into()?)
        .await?;
    Ok(Json(realm.into()))
}
