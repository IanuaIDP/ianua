//! Organization API key handlers: listing, minting and revoking the keys
//! that act for the organization, and the permissions their scopes may
//! name.

use axum::extract::{Path, State};
use ianua_app::ports::organization::OrgApiKeySortField;
use ianua_app::use_case::{Command as _, Query as _};
use ianua_app::use_cases::organization::api_keys::{CreateOrgRequest, RevokeOrgRequest};
use ianua_assembly::organization::OrganizationState;

use crate::dto::organization::api_keys::{
    CreateOrgApiKeyBody, CreatedOrgApiKeyResponse, OrgApiKeyResponse, PermissionGroupResponse,
    key_listing,
};
use crate::error::{ApiError, ErrorBody};
use crate::extractors::callers::OrgMember;
use crate::extractors::json::Json;
use crate::extractors::organization::OrgSteward;
use crate::extractors::pagination::{PaginationParams, Paging};
use crate::extractors::paths::organization::OrgApiKeyPath;
use crate::extractors::sort::SortQuery;
use crate::response::{Created, NoContent, PageResponse};

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/api-keys",
    tag = "Organizations",
    params(SortQuery<OrgApiKeySortField>, PaginationParams),
    responses(
        (status = 200, description = "Org API keys", body = PageResponse<OrgApiKeyResponse>),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody)
    )
)]
/// List org API keys
///
/// The organization's API keys, sortable and paginated. Each entry carries
/// the display `name` and a `key_prefix` for identification; the raw key is
/// never included. Read-only. The key inventory is credential material, so
/// the app lets only those who may view keys read it.
pub(crate) async fn list_org_api_keys(
    State(organization): State<OrganizationState>,
    member: OrgMember,
    SortQuery(sort): SortQuery<OrgApiKeySortField>,
    Paging(pagination): Paging,
) -> Result<Json<PageResponse<OrgApiKeyResponse>>, ApiError> {
    let page = organization
        .api_keys
        .list
        .execute(&member.caller, key_listing(sort, pagination))
        .await?;
    Ok(Json(PageResponse::from_page(page, OrgApiKeyResponse::from)))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/api-keys",
    tag = "Organizations",
    request_body = CreateOrgApiKeyBody,
    responses(
        (status = 201, description = "Created", body = CreatedOrgApiKeyResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Create an org API key
///
/// Mints a new organization API key under a display `name`, carrying the
/// `scopes` it may act with and an optional `expires_at`. The **raw key is
/// returned once**: only its hash is stored, alongside the `key_prefix`
/// used to identify it later. A key reaches only what its scopes name and
/// never more than the member minting it holds. Returns `422` for an
/// invalid name or scope, or an expiry in the past.
pub(crate) async fn create_org_api_key(
    State(organization): State<OrganizationState>,
    member: OrgMember,
    Json(body): Json<CreateOrgApiKeyBody>,
) -> Result<Created<CreatedOrgApiKeyResponse>, ApiError> {
    let created = organization
        .api_keys
        .create
        .execute(
            &member.caller,
            &member.auditor,
            CreateOrgRequest::try_from(body)?,
        )
        .await?;
    Ok(Created(CreatedOrgApiKeyResponse::from(created)))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/api-keys/{key_id}/revoke",
    tag = "Organizations",
    responses(
        (status = 204, description = "Revoked"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody)
    )
)]
/// Revoke an org API key
///
/// Permanently revokes an org API key by its `key_id`, so it stops
/// authenticating at once. A member of the organization or the platform
/// may revoke one. Returns `404` if the key does not exist. Records
/// `organization.org_api_key_revoked`.
pub(crate) async fn revoke_org_api_key(
    State(organization): State<OrganizationState>,
    steward: OrgSteward,
    Path(path): Path<OrgApiKeyPath>,
) -> Result<NoContent, ApiError> {
    let request = RevokeOrgRequest {
        organization_id: steward.organization,
        key_id: path.key(),
    };
    organization
        .api_keys
        .revoke
        .execute(&steward.caller, &steward.auditor, request)
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/permissions",
    tag = "Organizations",
    responses(
        (status = 200, description = "Success", body = Vec<PermissionGroupResponse>),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody)
    )
)]
/// List available org permissions
///
/// The fixed catalog of permissions the org plane recognizes, grouped by
/// domain: the set an org API key's `scopes` may name. Send an entry's
/// `label` verbatim as a scope. A static enumeration with no stored data,
/// readable by any member of the organization.
pub(crate) async fn list_org_permissions(_member: OrgMember) -> Json<Vec<PermissionGroupResponse>> {
    Json(PermissionGroupResponse::org_catalog())
}
