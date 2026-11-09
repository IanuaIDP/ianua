//! SCIM group handlers: a directory listing, reading, creating, changing and
//! deleting the groups it keeps.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use ianua_app::use_case::{Command as _, Query as _};
use ianua_app::use_cases::scim::groups::{ReplaceScimRequest, UpdateScimRequest};
use ianua_assembly::scim::ScimState;

use crate::dto::scim::{ScimGroupBody, ScimGroupResource, ScimListResponse, ScimPatchBody};
use crate::error::scim::ScimApiError;
use crate::extractors::paths::scim::ScimResourcePath;
use crate::extractors::scim::{IfNoneMatch, ScimBody, ScimDirectory, ScimListQuery};
use crate::response::NoContent;
use crate::response::scim::{ScimJson, ScimResult};

#[utoipa::path(
    get,
    path = "/scim/v2/organizations/{org_slug}/tenants/{tenant_slug}/Groups",
    tag = "SCIM",
    responses(
        (status = 200, description = "A SCIM ListResponse of Group resources", content_type = "application/scim+json"),
        (status = 400, description = "A filter this service does not read (`invalidFilter`), or a `sortBy` (`invalidValue`)", content_type = "application/scim+json"),
        (status = 401, description = "No token, or not the tenant's current one", content_type = "application/scim+json")
    )
)]
/// List groups
///
/// The groups the directory keeps, with their members, as SCIM `Group`
/// resources, a page at a time (`startIndex`, `count`), optionally filtered
/// on `displayName` with `eq`, `co` or `sw`, joined by `and` and `or`.
/// Groups are listed in one order, so a `sortBy` is refused. Groups a
/// person keeps in the dashboard are not listed. Records nothing. Requires
/// the tenant's SCIM token while SCIM is switched on.
pub(crate) async fn list_groups(
    State(scim): State<ScimState>,
    directory: ScimDirectory,
    query: ScimListQuery,
) -> ScimResult<ScimListResponse<ScimGroupResource>> {
    let (request, matches) = query.groups()?;
    let page = scim.list_groups.execute(&directory.caller, request).await?;
    Ok(ScimJson::ok(ScimListResponse::of(
        &page,
        matches,
        query.start_index,
        ScimGroupResource::from,
    )))
}

#[utoipa::path(
    get,
    path = "/scim/v2/organizations/{org_slug}/tenants/{tenant_slug}/Groups/{id}",
    tag = "SCIM",
    responses(
        (status = 200, description = "A SCIM Group resource, its version as the `ETag`", content_type = "application/scim+json"),
        (status = 304, description = "The `If-None-Match` names the group's version: unchanged"),
        (status = 401, description = "No token, or not the tenant's current one", content_type = "application/scim+json"),
        (status = 404, description = "No group the directory keeps", content_type = "application/scim+json")
    )
)]
/// Get a group
///
/// One group the directory keeps, with its members. Its `meta.version` is
/// sent as the `ETag`; a directory sending it back in `If-None-Match` is
/// answered `304` while the group, its name and its members, is unchanged.
/// A group a person keeps in the dashboard is not found. Records nothing.
/// Requires the tenant's SCIM token while SCIM is switched on.
pub(crate) async fn get_group(
    State(scim): State<ScimState>,
    directory: ScimDirectory,
    Path(path): Path<ScimResourcePath>,
    held: IfNoneMatch,
) -> ScimResult<ScimGroupResource> {
    let group = scim
        .get_group
        .execute(&directory.caller, path.group())
        .await?;
    Ok(ScimJson::read(ScimGroupResource::from(&group), &held))
}

#[utoipa::path(
    post,
    path = "/scim/v2/organizations/{org_slug}/tenants/{tenant_slug}/Groups",
    tag = "SCIM",
    request_body(content = ScimGroupBody, content_type = "application/scim+json"),
    responses(
        (status = 201, description = "The SCIM Group resource created", content_type = "application/scim+json"),
        (status = 400, description = "A value that is not valid, or a member who is not a user of the tenant (`invalidValue`)", content_type = "application/scim+json"),
        (status = 401, description = "No token, or not the tenant's current one", content_type = "application/scim+json"),
        (status = 403, description = "The plan's group limit is reached", content_type = "application/scim+json"),
        (status = 409, description = "The name is taken (`uniqueness`)", content_type = "application/scim+json")
    )
)]
/// Create a group
///
/// Makes a group the directory keeps, under `displayName`, with the users
/// in `members`. Checked against the plan's group limit. Records the group
/// and each membership in the tenant's trail. Requires the tenant's SCIM
/// token while SCIM is switched on.
pub(crate) async fn create_group(
    State(scim): State<ScimState>,
    directory: ScimDirectory,
    ScimBody(body): ScimBody<ScimGroupBody>,
) -> ScimResult<ScimGroupResource> {
    let group = scim
        .create_group
        .execute(&directory.caller, &directory.auditor, body.fields()?)
        .await?;
    Ok(ScimJson::resource(
        StatusCode::CREATED,
        ScimGroupResource::from(&group),
    ))
}

#[utoipa::path(
    put,
    path = "/scim/v2/organizations/{org_slug}/tenants/{tenant_slug}/Groups/{id}",
    tag = "SCIM",
    request_body(content = ScimGroupBody, content_type = "application/scim+json"),
    responses(
        (status = 200, description = "The SCIM Group resource after the change", content_type = "application/scim+json"),
        (status = 400, description = "A value that is not valid, or a member who is not a user of the tenant (`invalidValue`)", content_type = "application/scim+json"),
        (status = 401, description = "No token, or not the tenant's current one", content_type = "application/scim+json"),
        (status = 404, description = "No group the directory keeps", content_type = "application/scim+json")
    )
)]
/// Replace a group
///
/// Gives a group the directory keeps the name and the members it sends,
/// and only those members. Records each change in the tenant's trail.
/// Requires the tenant's SCIM token while SCIM is switched on.
pub(crate) async fn replace_group(
    State(scim): State<ScimState>,
    directory: ScimDirectory,
    Path(path): Path<ScimResourcePath>,
    ScimBody(body): ScimBody<ScimGroupBody>,
) -> ScimResult<ScimGroupResource> {
    let group = scim
        .replace_group
        .execute(
            &directory.caller,
            &directory.auditor,
            ReplaceScimRequest {
                group_id: path.group(),
                fields: body.fields()?,
            },
        )
        .await?;
    Ok(ScimJson::resource(
        StatusCode::OK,
        ScimGroupResource::from(&group),
    ))
}

#[utoipa::path(
    patch,
    path = "/scim/v2/organizations/{org_slug}/tenants/{tenant_slug}/Groups/{id}",
    tag = "SCIM",
    request_body(content = ScimPatchBody, content_type = "application/scim+json"),
    responses(
        (status = 200, description = "The SCIM Group resource after the change", content_type = "application/scim+json"),
        (status = 400, description = "A value that is not valid, or a member who is not a user of the tenant (`invalidValue`)", content_type = "application/scim+json"),
        (status = 401, description = "No token, or not the tenant's current one", content_type = "application/scim+json"),
        (status = 404, description = "No group the directory keeps", content_type = "application/scim+json")
    )
)]
/// Change parts of a group
///
/// Applies a SCIM patch: renaming the group, and adding, removing or
/// replacing its members, including Entra ID's `members[value eq "id"]`
/// form of removal. Records each change in the tenant's trail. Requires the
/// tenant's SCIM token while SCIM is switched on.
pub(crate) async fn patch_group(
    State(scim): State<ScimState>,
    directory: ScimDirectory,
    Path(path): Path<ScimResourcePath>,
    ScimBody(body): ScimBody<ScimPatchBody>,
) -> ScimResult<ScimGroupResource> {
    let group = scim
        .update_group
        .execute(
            &directory.caller,
            &directory.auditor,
            UpdateScimRequest {
                group_id: path.group(),
                changes: body.group_changes()?,
            },
        )
        .await?;
    Ok(ScimJson::resource(
        StatusCode::OK,
        ScimGroupResource::from(&group),
    ))
}

#[utoipa::path(
    delete,
    path = "/scim/v2/organizations/{org_slug}/tenants/{tenant_slug}/Groups/{id}",
    tag = "SCIM",
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "No token, or not the tenant's current one", content_type = "application/scim+json"),
        (status = 404, description = "No group the directory keeps", content_type = "application/scim+json")
    )
)]
/// Delete a group
///
/// Deletes a group the directory keeps. Its members lose what the group
/// gave them. Records the deletion in the tenant's trail. Requires the
/// tenant's SCIM token while SCIM is switched on.
pub(crate) async fn delete_group(
    State(scim): State<ScimState>,
    directory: ScimDirectory,
    Path(path): Path<ScimResourcePath>,
) -> Result<NoContent, ScimApiError> {
    scim.remove_group
        .execute(&directory.caller, &directory.auditor, path.group())
        .await?;
    Ok(NoContent)
}
