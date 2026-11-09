//! Custom user attribute handlers.
//!
//! Two surfaces. The declarations are the shape of a tenant's user
//! directory: which extra fields exist and what may go in them. The values
//! are per person, and reach the same rights the rest of a person's record
//! does.

use axum::extract::{Path, State};
use ianua_app::use_case::{Command as _, Query as _};
use ianua_app::use_cases::identity::attributes::{
    DeleteRequest, SetStatusRequest, SetValueRequest, UpdateRequest,
};
use ianua_assembly::identity::IdentityState;

use crate::dto::identity::attributes::{
    AttributeDeletedResponse, AttributeKindResponse, AttributeListingParams, AttributeResponse,
    AttributeStatusBody, DeclareAttributeBody, SetAttributeValueBody, UpdateAttributeBody,
    UserAttributeValuesResponse,
};
use crate::error::{ApiError, ErrorBody};
use crate::extractors::callers::TenantCaller;
use crate::extractors::json::Json;
use crate::extractors::paths::identity::{AttributePath, AttributeValuePath, UserPath};
use crate::extractors::query::Query;
use crate::response::{Created, NoContent};

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/user-attributes/kinds",
    tag = "User attributes",
    responses(
        (status = 200, description = "The kinds a field may be declared as", body = [AttributeKindResponse]),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 404, description = "No such tenant", body = ErrorBody)
    )
)]
/// The kinds a custom field may be declared as
///
/// Each entry carries everything that follows from the choice: the control
/// to render, the others it may be rendered with, the comparisons a filter
/// may use, and whether it needs a list of options, a length limit or a
/// range. A client builds the "what kind of thing is this?" step from it,
/// so the list lives in one place. The catalogue is the platform's, the
/// same for every tenant. Requires a caller of the tenant.
pub(crate) async fn list_attribute_kinds(
    _tenant: TenantCaller,
) -> Json<Vec<AttributeKindResponse>> {
    Json(AttributeKindResponse::catalogue())
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/user-attributes",
    tag = "User attributes",
    params(AttributeListingParams),
    responses(
        (status = 200, description = "The declared fields", body = [AttributeResponse]),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 404, description = "No such tenant", body = ErrorBody)
    )
)]
/// List the tenant's declared custom fields
///
/// What a client renders a form, a filter bar or a column chooser from.
/// Withdrawn fields are left out unless `include_archived=true`. A caller
/// not cleared for sensitive fields is not told they exist: listing one and
/// refusing to fill it in would disclose that the tenant records a salary,
/// which is most of what the setting hides. Read-only.
pub(crate) async fn list_user_attributes(
    State(identity): State<IdentityState>,
    tenant: TenantCaller,
    Query(params): Query<AttributeListingParams>,
) -> Result<Json<Vec<AttributeResponse>>, ApiError> {
    let declared = identity
        .attributes
        .list
        .execute(&tenant.caller, params.into())
        .await?;
    Ok(Json(declared.into_iter().map(Into::into).collect()))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/user-attributes",
    tag = "User attributes",
    request_body = DeclareAttributeBody,
    responses(
        (status = 201, description = "Declared", body = AttributeResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden, or the plan allows no more", body = ErrorBody),
        (status = 409, description = "Already declared", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Declare a custom field on the tenant's users
///
/// `kind` is the only choice that has to be made: the control, the valid
/// values and the comparisons a filter may use all follow from it. The
/// internal name is derived from the display name when omitted, and is
/// fixed once declared because every stored value is filed under it.
///
/// Nothing is exposed that was not asked for: a new field is not returned
/// in listings, not filterable and not sortable until it is said to be. A
/// withdrawn field still holds its name. Records
/// `identity.attribute_declared`. Requires the right to change the schema.
pub(crate) async fn declare_user_attribute(
    State(identity): State<IdentityState>,
    tenant: TenantCaller,
    Json(body): Json<DeclareAttributeBody>,
) -> Result<Created<AttributeResponse>, ApiError> {
    let declared = identity
        .attributes
        .declare
        .execute(&tenant.caller, &tenant.auditor, body.try_into()?)
        .await?;
    Ok(Created(declared.into()))
}

#[utoipa::path(
    patch,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/user-attributes/{namespace}/{key}",
    tag = "User attributes",
    request_body = UpdateAttributeBody,
    responses(
        (status = 200, description = "Changed", body = AttributeResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 409, description = "The change would strand stored values", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Change a declared field
///
/// Widening is always allowed. Narrowing is allowed only while nothing
/// already sits outside the new bounds: withdrawing an option somebody
/// chose, shortening a limit past what somebody wrote, or requiring a field
/// somebody left empty are each refused, and the refusal says how many
/// people it concerns. Naming one visibility flag leaves the others as they
/// are. Making a sensitive field ordinary needs clearance for it.
///
/// The internal name and the kind cannot be changed; ask for a new field
/// instead. Records `identity.attribute_updated`. Requires the right to
/// change the schema.
pub(crate) async fn update_user_attribute(
    State(identity): State<IdentityState>,
    tenant: TenantCaller,
    Path(path): Path<AttributePath>,
    Json(body): Json<UpdateAttributeBody>,
) -> Result<Json<AttributeResponse>, ApiError> {
    let (namespace, key) = path.attribute()?;
    let schema = identity
        .attributes
        .schema
        .execute(&tenant.caller, ())
        .await?;
    let request = UpdateRequest {
        changes: body.changes(schema.find(namespace, &key))?,
        namespace,
        key,
    };
    let changed = identity
        .attributes
        .update
        .execute(&tenant.caller, &tenant.auditor, request)
        .await?;
    Ok(Json(changed.into()))
}

#[utoipa::path(
    put,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/user-attributes/{namespace}/{key}/status",
    tag = "User attributes",
    request_body = AttributeStatusBody,
    responses(
        (status = 200, description = "Changed", body = AttributeResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody)
    )
)]
/// Withdraw a field from use, or bring it back
///
/// Withdrawing takes the field off every form, listing, filter and sort
/// while keeping every value stored under it, so a mistake costs nothing to
/// undo. It is also the first of the two steps to deleting, which keeps
/// "remove this column" and "discard what a thousand people put in it" two
/// separate decisions. Asking for the state it is already in changes
/// nothing and succeeds. Records `identity.attribute_archived` or
/// `identity.attribute_restored`. Requires the right to change the schema.
pub(crate) async fn set_user_attribute_status(
    State(identity): State<IdentityState>,
    tenant: TenantCaller,
    Path(path): Path<AttributePath>,
    Json(body): Json<AttributeStatusBody>,
) -> Result<Json<AttributeResponse>, ApiError> {
    let (namespace, key) = path.attribute()?;
    let request = SetStatusRequest {
        namespace,
        key,
        status: body.status(),
    };
    let changed = identity
        .attributes
        .set_status
        .execute(&tenant.caller, &tenant.auditor, request)
        .await?;
    Ok(Json(changed.into()))
}

#[utoipa::path(
    delete,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/user-attributes/{namespace}/{key}",
    tag = "User attributes",
    responses(
        (status = 200, description = "Discarded", body = AttributeDeletedResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 409, description = "Still in use", body = ErrorBody)
    )
)]
/// Discard a field and every value stored under it
///
/// The only call here that destroys customer data, and the reason it is
/// not the first step: a field must already be withdrawn from use before
/// it can be deleted. The response says how many values went with it.
/// Records `identity.attribute_deleted`. Requires the right to change the
/// schema.
pub(crate) async fn delete_user_attribute(
    State(identity): State<IdentityState>,
    tenant: TenantCaller,
    Path(path): Path<AttributePath>,
) -> Result<Json<AttributeDeletedResponse>, ApiError> {
    let (namespace, key) = path.attribute()?;
    let values_discarded = identity
        .attributes
        .delete
        .execute(
            &tenant.caller,
            &tenant.auditor,
            DeleteRequest { namespace, key },
        )
        .await?;
    Ok(Json(AttributeDeletedResponse { values_discarded }))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/users/{id}/attributes",
    tag = "User attributes",
    responses(
        (status = 200, description = "The user's custom values", body = UserAttributeValuesResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such tenant", body = ErrorBody)
    )
)]
/// Read one user's custom field values
///
/// Keyed by `<namespace>.<key>`. A person reads all of their own declared
/// values. Someone else needs the right to view users, and sees a sensitive
/// value only with clearance for it; a value the caller may not see is left
/// out rather than nulled, so its absence says nothing about whether the
/// person holds one.
pub(crate) async fn get_user_attribute_values(
    State(identity): State<IdentityState>,
    tenant: TenantCaller,
    Path(path): Path<UserPath>,
) -> Result<Json<UserAttributeValuesResponse>, ApiError> {
    let values = identity
        .attributes
        .values
        .execute(&tenant.caller, path.whose(&tenant.caller))
        .await?;
    Ok(Json(values.into()))
}

#[utoipa::path(
    put,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/users/{id}/attributes/{namespace}/{key}",
    tag = "User attributes",
    request_body = SetAttributeValueBody,
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "No such field, or the value does not suit it", body = ErrorBody)
    )
)]
/// Set one of a user's custom values, or clear it
///
/// The value is checked against the declaration: a field nobody declared is
/// refused rather than stored, and so is a value of the wrong type, outside
/// the declared range, longer than the declared limit, or not among the
/// declared options. Sending `null` clears the value, which a required
/// field refuses.
///
/// A person keeps their own `user` fields from their own session; every
/// other write, `app` fields included, needs the right to edit the person's
/// profile. The record names who changed which field, never the value.
/// Records `identity.metadata_updated`.
pub(crate) async fn set_user_attribute_value(
    State(identity): State<IdentityState>,
    tenant: TenantCaller,
    Path(path): Path<AttributeValuePath>,
    Json(body): Json<SetAttributeValueBody>,
) -> Result<NoContent, ApiError> {
    let (namespace, key) = path.attribute()?;
    let request = SetValueRequest {
        whose: path.whose(&tenant.caller),
        namespace,
        key,
        value: body.value()?,
    };
    identity
        .attributes
        .set_value
        .execute(&tenant.caller, &tenant.auditor, request)
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    delete,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/users/{id}/attributes",
    tag = "User attributes",
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such tenant", body = ErrorBody)
    )
)]
/// Clear every custom value a user holds
///
/// Deletes the user's values in both namespaces at once. Records
/// `identity.metadata_deleted`. Requires the right to edit the user's
/// profile, and holding at least everything the user holds.
pub(crate) async fn delete_user_attribute_values(
    State(identity): State<IdentityState>,
    tenant: TenantCaller,
    Path(path): Path<UserPath>,
) -> Result<NoContent, ApiError> {
    identity
        .attributes
        .delete_values
        .execute(&tenant.caller, &tenant.auditor, path.user())
        .await?;
    Ok(NoContent)
}
