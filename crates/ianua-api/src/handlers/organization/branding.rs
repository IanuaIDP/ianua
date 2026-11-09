//! Organization branding handlers: how the organization's own dashboard
//! and mail look, and going back to the platform's look.

use axum::extract::State;
use ianua_app::use_case::{Command as _, Query as _};
use ianua_app::use_cases::organization::branding::ChangeOrgRequest;
use ianua_assembly::organization::OrganizationState;

use crate::dto::organization::branding::{OrgBrandingResponse, UpdateOrgBrandingBody};
use crate::error::{ApiError, ErrorBody};
use crate::extractors::callers::OrgMember;
use crate::extractors::json::Json;
use crate::response::NoContent;

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/branding",
    tag = "Organizations",
    responses(
        (status = 200, description = "The branding", body = OrgBrandingResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody)
    )
)]
/// Get the organization's branding
///
/// The logo, color and mail sender name of the organization's own
/// dashboard and mail. A part never set is `null`, and the platform's
/// applies. Read-only.
pub(crate) async fn get_branding(
    State(organization): State<OrganizationState>,
    member: OrgMember,
) -> Result<Json<OrgBrandingResponse>, ApiError> {
    let branding = organization
        .branding
        .get
        .execute(&member.caller, ())
        .await?;
    Ok(Json(OrgBrandingResponse::from(branding)))
}

#[utoipa::path(
    patch,
    path = "/api/v1/organizations/{org_slug}/branding",
    tag = "Organizations",
    request_body = UpdateOrgBrandingBody,
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Change the organization's branding
///
/// Changes only the parts the body names: absent leaves a part as it is,
/// `null` returns it to the platform's, a value replaces it. A change of
/// nothing records nothing. Records `organization.branding_updated` for
/// each part changed. The app decides whether the caller may change it.
pub(crate) async fn update_branding(
    State(organization): State<OrganizationState>,
    member: OrgMember,
    Json(body): Json<UpdateOrgBrandingBody>,
) -> Result<NoContent, ApiError> {
    organization
        .branding
        .change
        .execute(
            &member.caller,
            &member.auditor,
            ChangeOrgRequest::try_from(body)?,
        )
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    delete,
    path = "/api/v1/organizations/{org_slug}/branding",
    tag = "Organizations",
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody)
    )
)]
/// Reset the organization's branding
///
/// Returns every part to the platform's look at once. Records
/// `organization.branding_reset`.
pub(crate) async fn reset_branding(
    State(organization): State<OrganizationState>,
    member: OrgMember,
) -> Result<NoContent, ApiError> {
    organization
        .branding
        .reset
        .execute(&member.caller, &member.auditor, ())
        .await?;
    Ok(NoContent)
}
