//! Branding handlers: a tenant's look on its sign-in pages and its logo.
//! Its own versions of the platform's emails are in `templates`, the
//! provider its mail goes out through in `mail`.

pub mod mail;
pub mod templates;

use axum::extract::State;
use ianua_app::use_case::{Command as _, Query as _};
use ianua_assembly::branding::BrandingState;

use crate::dto::branding::{
    BrandingResponse, LogoUploadForm, LogoUploadedResponse, UpdateBrandingBody,
};
use crate::error::{ApiError, ErrorBody};
use crate::extractors::branding::LogoUpload;
use crate::extractors::callers::TenantCaller;
use crate::extractors::json::Json;
use crate::response::NoContent;

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/branding",
    tag = "Branding",
    responses(
        (status = 200, description = "Success", body = BrandingResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Tenant branding configuration
///
/// Returns the logo, colors, raw custom CSS and email sender settings.
/// Unset fields are `null`, meaning platform defaults; a tenant with no
/// customization receives `200`. Sign-in hosts are set through domains.
/// Requires `Branding(View)` and changes nothing.
pub(crate) async fn get_branding(
    State(branding): State<BrandingState>,
    tenant: TenantCaller,
) -> Result<Json<BrandingResponse>, ApiError> {
    let current = branding.get.execute(&tenant.caller, ()).await?;
    Ok(Json(BrandingResponse::from(&current)))
}

#[utoipa::path(
    patch,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/branding",
    tag = "Branding",
    request_body = UpdateBrandingBody,
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Update tenant branding (partial)
///
/// Absent fields stay unchanged, `null` restores defaults and values replace
/// them. An empty patch returns `204` without saving or recording an event.
/// Requires an HTTPS logo URL, `#RGB` or `#RRGGBB` colors, CSS that retains
/// renderable content after sanitization, a short sender name without control
/// characters and a valid sender address (`422` otherwise). An unverified
/// sender domain returns `403`. Requires `Branding(Update)` and records
/// one `branding.updated` per save, regardless of how many fields changed.
pub(crate) async fn update_branding(
    State(branding): State<BrandingState>,
    tenant: TenantCaller,
    Json(body): Json<UpdateBrandingBody>,
) -> Result<NoContent, ApiError> {
    branding
        .update
        .execute(&tenant.caller, &tenant.auditor, body.try_into()?)
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/branding/logo",
    tag = "Branding",
    request_body(content = LogoUploadForm, content_type = "multipart/form-data"),
    responses(
        (status = 200, description = "Where the logo is served", body = LogoUploadedResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 413, description = "Larger than the server takes"),
        (status = 422, description = "Not a logo the platform takes", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Upload the tenant's logo
///
/// Takes a logo as a `multipart/form-data` upload in its `logo` field and
/// shows it on the tenant's sign-in pages and in its mail, in place of any
/// logo before. The image is read from its own bytes, whatever the upload
/// says it is: a PNG or a JPEG of at most 512 KiB, each side between 16
/// and 4096 pixels (`422` otherwise). The platform keeps and serves it from
/// its own host; the answer and the branding's `logo_url` say where.
/// Records `branding.updated`, naming the logo and its format.
///
/// Requires `Branding(Update)`.
pub(crate) async fn upload_logo(
    State(branding): State<BrandingState>,
    tenant: TenantCaller,
    LogoUpload(logo): LogoUpload,
) -> Result<Json<LogoUploadedResponse>, ApiError> {
    let served_at = branding
        .upload_logo
        .execute(&tenant.caller, &tenant.auditor, logo)
        .await?;
    Ok(Json(LogoUploadedResponse::from(served_at)))
}
