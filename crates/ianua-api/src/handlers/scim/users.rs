//! SCIM user handlers: a directory listing, reading, creating, changing and
//! removing the tenant's users, and the `/Me` it is refused.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use ianua_app::use_case::{Command as _, Query as _};
use ianua_app::use_cases::scim::users::{ReplaceScimRequest, UpdateScimRequest};
use ianua_assembly::scim::ScimState;

use crate::dto::scim::{
    ScimErrorBody, ScimListResponse, ScimPatchBody, ScimUserBody, ScimUserResource,
};
use crate::error::scim::ScimApiError;
use crate::extractors::paths::scim::ScimResourcePath;
use crate::extractors::scim::{IfNoneMatch, ScimBody, ScimDirectory, ScimListQuery};
use crate::response::NoContent;
use crate::response::scim::{ScimJson, ScimResult};

#[utoipa::path(
    get,
    path = "/scim/v2/organizations/{org_slug}/tenants/{tenant_slug}/Users",
    tag = "SCIM",
    responses(
        (status = 200, description = "A SCIM ListResponse of User resources", content_type = "application/scim+json"),
        (status = 400, description = "A filter this service does not read (`invalidFilter`), or a `sortBy` or `sortOrder` it does not know (`invalidValue`)", content_type = "application/scim+json"),
        (status = 401, description = "No token, or not the tenant's current one", content_type = "application/scim+json")
    )
)]
/// List users
///
/// The tenant's users as SCIM `User` resources, a page at a time
/// (`startIndex`, `count`). A `filter` compares `userName` (or `emails`),
/// `displayName`, `externalId`, `name.givenName`, `name.familyName`, and
/// the enterprise `department` and `employeeNumber` with `eq`, `co` or
/// `sw`, joined by `and` and `or` and grouped in parentheses; `externalId`
/// and `employeeNumber` compare with case, the rest without. `sortBy` names
/// one of those attributes, `sortOrder` is `ascending` (the default) or
/// `descending`, and users with no value come last.
///
/// A comparison on an attribute this service does not keep matches nobody,
/// so a provider looking a user up that way goes on to create it. Records
/// nothing. Requires the tenant's SCIM token while SCIM is switched on.
pub(crate) async fn list_users(
    State(scim): State<ScimState>,
    directory: ScimDirectory,
    query: ScimListQuery,
) -> ScimResult<ScimListResponse<ScimUserResource>> {
    let (request, matches) = query.users()?;
    let page = scim.list_users.execute(&directory.caller, request).await?;
    Ok(ScimJson::ok(ScimListResponse::of(
        &page,
        matches,
        query.start_index,
        ScimUserResource::from,
    )))
}

#[utoipa::path(
    get,
    path = "/scim/v2/organizations/{org_slug}/tenants/{tenant_slug}/Users/{id}",
    tag = "SCIM",
    responses(
        (status = 200, description = "A SCIM User resource, its version as the `ETag`", content_type = "application/scim+json"),
        (status = 304, description = "The `If-None-Match` names the user's version: unchanged"),
        (status = 401, description = "No token, or not the tenant's current one", content_type = "application/scim+json"),
        (status = 404, description = "No such user", content_type = "application/scim+json")
    )
)]
/// Get a user
///
/// One of the tenant's users as a SCIM `User` resource. Its `meta.version`
/// is sent as the `ETag`; a directory sending it back in `If-None-Match` is
/// answered `304` while the user is unchanged. Records nothing. Requires
/// the tenant's SCIM token while SCIM is switched on.
pub(crate) async fn get_user(
    State(scim): State<ScimState>,
    directory: ScimDirectory,
    Path(path): Path<ScimResourcePath>,
    held: IfNoneMatch,
) -> ScimResult<ScimUserResource> {
    let user = scim
        .get_user
        .execute(&directory.caller, path.user())
        .await?;
    Ok(ScimJson::read(ScimUserResource::from(&user), &held))
}

#[utoipa::path(
    post,
    path = "/scim/v2/organizations/{org_slug}/tenants/{tenant_slug}/Users",
    tag = "SCIM",
    request_body(content = ScimUserBody, content_type = "application/scim+json"),
    responses(
        (status = 201, description = "The SCIM User resource created, its version as the `ETag`", content_type = "application/scim+json"),
        (status = 400, description = "A value that is not valid (`invalidValue`)", content_type = "application/scim+json"),
        (status = 401, description = "No token, or not the tenant's current one", content_type = "application/scim+json"),
        (status = 403, description = "The plan's user limit is reached", content_type = "application/scim+json"),
        (status = 409, description = "The address is taken (`uniqueness`)", content_type = "application/scim+json")
    )
)]
/// Create a user
///
/// Opens an account for the person the directory sends: `userName` (an
/// email address, or the primary one in `emails`), a display name, the
/// name's parts, `externalId`, the enterprise extension's `department`,
/// `manager` (a user of the tenant, by id) and `employeeNumber`, and
/// whether the account is `active`. The account starts with the tenant's
/// default roles and the role SCIM's settings name. The address always
/// stays unverified and is mailed a confirmation link. Checked against the
/// plan's user limit. Records the account's opening in the tenant's trail.
/// Requires the tenant's SCIM token while SCIM is switched on.
pub(crate) async fn create_user(
    State(scim): State<ScimState>,
    directory: ScimDirectory,
    ScimBody(body): ScimBody<ScimUserBody>,
) -> ScimResult<ScimUserResource> {
    let user = scim
        .create_user
        .execute(
            &directory.caller,
            &directory.auditor,
            body.fields(&scim.domain_limits)?,
        )
        .await?;
    Ok(ScimJson::resource(
        StatusCode::CREATED,
        ScimUserResource::from(&user),
    ))
}

#[utoipa::path(
    put,
    path = "/scim/v2/organizations/{org_slug}/tenants/{tenant_slug}/Users/{id}",
    tag = "SCIM",
    request_body(content = ScimUserBody, content_type = "application/scim+json"),
    responses(
        (status = 200, description = "The SCIM User resource after the change, its version as the `ETag`", content_type = "application/scim+json"),
        (status = 400, description = "A value that is not valid (`invalidValue`)", content_type = "application/scim+json"),
        (status = 401, description = "No token, or not the tenant's current one", content_type = "application/scim+json"),
        (status = 404, description = "No such user", content_type = "application/scim+json")
    )
)]
/// Replace a user
///
/// Replaces the user's record with the one the directory sends: address,
/// display name, the name's parts, `externalId`, the enterprise fields and
/// whether the account is active. A profile field left out is cleared.
/// Records each change in the tenant's trail. Requires the tenant's SCIM
/// token while SCIM is switched on.
pub(crate) async fn replace_user(
    State(scim): State<ScimState>,
    directory: ScimDirectory,
    Path(path): Path<ScimResourcePath>,
    ScimBody(body): ScimBody<ScimUserBody>,
) -> ScimResult<ScimUserResource> {
    let user = scim
        .replace_user
        .execute(
            &directory.caller,
            &directory.auditor,
            ReplaceScimRequest {
                user_id: path.user(),
                fields: body.fields(&scim.domain_limits)?,
            },
        )
        .await?;
    Ok(ScimJson::resource(
        StatusCode::OK,
        ScimUserResource::from(&user),
    ))
}

#[utoipa::path(
    patch,
    path = "/scim/v2/organizations/{org_slug}/tenants/{tenant_slug}/Users/{id}",
    tag = "SCIM",
    request_body(content = ScimPatchBody, content_type = "application/scim+json"),
    responses(
        (status = 200, description = "The SCIM User resource after the change, its version as the `ETag`", content_type = "application/scim+json"),
        (status = 400, description = "A value that is not valid (`invalidValue`)", content_type = "application/scim+json"),
        (status = 401, description = "No token, or not the tenant's current one", content_type = "application/scim+json"),
        (status = 404, description = "No such user", content_type = "application/scim+json")
    )
)]
/// Change parts of a user
///
/// Applies a SCIM patch: `active`, `userName`, `displayName`, `name` and
/// its parts, `emails`, `externalId` and the enterprise extension's
/// `department`, `manager` and `employeeNumber`, in the `path` form or the
/// pathless one, by short or fully qualified path. `remove` clears a
/// profile field. Attributes this service does not keep are ignored.
/// Switching an account off ends its sessions and the authority it lent its
/// agents. Records each change in the tenant's trail. Requires the tenant's
/// SCIM token while SCIM is switched on.
pub(crate) async fn patch_user(
    State(scim): State<ScimState>,
    directory: ScimDirectory,
    Path(path): Path<ScimResourcePath>,
    ScimBody(body): ScimBody<ScimPatchBody>,
) -> ScimResult<ScimUserResource> {
    let user = scim
        .update_user
        .execute(
            &directory.caller,
            &directory.auditor,
            UpdateScimRequest {
                user_id: path.user(),
                changes: body.user_changes(&scim.domain_limits)?,
            },
        )
        .await?;
    Ok(ScimJson::resource(
        StatusCode::OK,
        ScimUserResource::from(&user),
    ))
}

#[utoipa::path(
    delete,
    path = "/scim/v2/organizations/{org_slug}/tenants/{tenant_slug}/Users/{id}",
    tag = "SCIM",
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "No token, or not the tenant's current one", content_type = "application/scim+json"),
        (status = 404, description = "No such user", content_type = "application/scim+json")
    )
)]
/// Remove a user
///
/// Removes the person the directory no longer keeps: their account is
/// deactivated and kept, or deleted, as the tenant's SCIM settings say.
/// Their sessions and the authority they lent their agents end. Records
/// the removal in the tenant's trail. Requires the tenant's SCIM token
/// while SCIM is switched on.
pub(crate) async fn delete_user(
    State(scim): State<ScimState>,
    directory: ScimDirectory,
    Path(path): Path<ScimResourcePath>,
) -> Result<NoContent, ScimApiError> {
    scim.remove_user
        .execute(&directory.caller, &directory.auditor, path.user())
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    get,
    path = "/scim/v2/organizations/{org_slug}/tenants/{tenant_slug}/Me",
    tag = "SCIM",
    responses(
        (status = 501, description = "`/Me` is not offered, for any method", content_type = "application/scim+json")
    )
)]
/// The authenticated subject (`/Me`), not offered
///
/// RFC 7644 section 3.11 lets a service answer `/Me` with the resource of
/// whoever signed in. The SCIM token names the tenant's directory, not a
/// person, so every method on `/Me` is answered `501 Not Implemented` in
/// SCIM's error format, as the RFC says for a service without it. Records
/// nothing.
pub(crate) async fn me() -> ScimJson<ScimErrorBody> {
    ScimJson::with_status(StatusCode::NOT_IMPLEMENTED, ScimErrorBody::me_unsupported())
}
