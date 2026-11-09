//! Group mapping handlers: which of a provider's groups give which roles
//! and groups here.

use axum::extract::{Path, State};
use ianua_app::use_case::Command as _;
use ianua_assembly::federation::FederationState;

use crate::dto::federation::groups::GroupMappingBody;
use crate::error::{ApiError, ErrorBody};
use crate::extractors::callers::TenantCaller;
use crate::extractors::json::Json;
use crate::extractors::paths::federation::ConnectionPath;
use crate::response::NoContent;

#[utoipa::path(
    put,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/federation/connections/{id}/group-mapping",
    tag = "Federation",
    request_body = GroupMappingBody,
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden, or a mapped role or group carries a permission the caller may not hand out", body = ErrorBody),
        (status = 404, description = "No such connection, role or group", body = ErrorBody),
        (status = 422, description = "No rule, more than 200, one twice, or the top group mapped", body = ErrorBody)
    )
)]
/// Map a provider's groups
///
/// Replaces the connection's group mapping: the `claim` the provider sends
/// its groups in, and one rule per provider group naming the role
/// (`{"role": "<id>"}`) or group (`{"group": "<id>"}`) it gives here. At
/// each sign-in a person gets what their groups map to, and loses what a
/// group they left gave. Every role and group mapped is checked as a grant
/// by the caller. Records `federation.connection_updated`.
pub(crate) async fn map_provider_groups(
    State(federation): State<FederationState>,
    tenant: TenantCaller,
    Path(path): Path<ConnectionPath>,
    Json(body): Json<GroupMappingBody>,
) -> Result<NoContent, ApiError> {
    federation
        .connections
        .map_groups
        .execute(
            &tenant.caller,
            &tenant.auditor,
            body.for_connection(path.connection())?,
        )
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    delete,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/federation/connections/{id}/group-mapping",
    tag = "Federation",
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such connection", body = ErrorBody)
    )
)]
/// Stop mapping a provider's groups
///
/// Turns the mapping off, so the provider hands out no more roles or
/// groups; the update right is enough, as in an incident. What people were
/// given through it stays until their next sign-in takes it back. Records
/// `federation.connection_updated`.
pub(crate) async fn stop_mapping_provider_groups(
    State(federation): State<FederationState>,
    tenant: TenantCaller,
    Path(path): Path<ConnectionPath>,
) -> Result<NoContent, ApiError> {
    federation
        .connections
        .stop_mapping_groups
        .execute(&tenant.caller, &tenant.auditor, path.connection())
        .await?;
    Ok(NoContent)
}
