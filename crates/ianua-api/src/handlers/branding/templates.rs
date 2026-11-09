//! Email template handlers: a tenant's own versions of the platform's
//! emails, for every locale or one, their previews and test sends.

use axum::extract::{Path, State};
use ianua_app::ports::branding::EmailTemplateSortField;
use ianua_app::use_case::{Command as _, Query as _};
use ianua_app::use_cases::branding::ListEmailTemplatesRequest;
use ianua_assembly::branding::BrandingState;

use crate::dto::branding::templates::{
    EmailTemplateResponse, RenderedEmailResponse, TemplateLocaleParams, TemplatePreviewBody,
    UpdateEmailTemplateBody,
};
use crate::error::{ApiError, ErrorBody};
use crate::extractors::branding::TemplateSelection;
use crate::extractors::callers::TenantCaller;
use crate::extractors::json::Json;
use crate::extractors::pagination::{PaginationParams, Paging};
use crate::extractors::paths::branding::TemplatePath;
use crate::extractors::query::Query;
use crate::extractors::sort::SortQuery;
use crate::response::{NoContent, PageResponse};

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/branding/email-templates",
    tag = "Branding",
    params(SortQuery<EmailTemplateSortField>, PaginationParams),
    responses(
        (status = 200, description = "Success", body = PageResponse<EmailTemplateResponse>),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// List customized email templates
///
/// Returns this tenant's **customized** emails: only the ones a tenant
/// admin has overridden. An email still on the platform's default is not
/// listed, so an empty page means "nothing customized yet". Sortable by
/// `template_type`, paginated with `after` / `limit`. Each entry carries
/// the `locale` it is written for (`null` for every locale without a
/// version of its own), `is_custom` and the overridden `subject`,
/// `body_html` and `body_text`, `null` for a part still on the default.
/// Read-only.
///
/// Requires `Branding(View)`.
pub(crate) async fn list_email_templates(
    State(branding): State<BrandingState>,
    tenant: TenantCaller,
    SortQuery(sort): SortQuery<EmailTemplateSortField>,
    Paging(pagination): Paging,
) -> Result<Json<PageResponse<EmailTemplateResponse>>, ApiError> {
    let page = branding
        .list_templates
        .execute(
            &tenant.caller,
            ListEmailTemplatesRequest {
                sort,
                page: pagination,
            },
        )
        .await?;
    Ok(Json(PageResponse::from_page(
        page,
        EmailTemplateResponse::from,
    )))
}

#[utoipa::path(
    put,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/branding/email-templates/{template_type}",
    tag = "Branding",
    params(TemplateLocaleParams),
    request_body = UpdateEmailTemplateBody,
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Customize an email template
///
/// Replaces the customization of the stored `template_type`, optionally for
/// `?locale=de-DE`. Recipients use their locale, language, all-locales version,
/// then platform default, in that order. This `PUT` is idempotent; omitted
/// parts use platform defaults. Requires a short, control-free `subject` and
/// nonempty, bounded `body_html` and `body_text`. Bodies accept text and their
/// declared bare `{{ name }}` placeholders only; filters, tags and unknown
/// names return `422`. Requires `Branding(Update)`; records `branding.updated`.
pub(crate) async fn update_email_template(
    State(branding): State<BrandingState>,
    tenant: TenantCaller,
    TemplateSelection { path, locale }: TemplateSelection,
    Json(body): Json<UpdateEmailTemplateBody>,
) -> Result<NoContent, ApiError> {
    let slot = locale.slot(path.template())?;
    branding
        .update_template
        .execute(&tenant.caller, &tenant.auditor, body.into_request(slot)?)
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    delete,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/branding/email-templates/{template_type}",
    tag = "Branding",
    params(TemplateLocaleParams),
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Reset an email template to the default
///
/// Returns a customized email to the platform's default by removing this
/// tenant's version of it: the one for `?locale=` when given, else the one
/// for every locale. The versions for other locales stay.
///
/// **State.** `Customized → Default`, the only way back. Returns `404` if
/// this version is not customized. Records `branding.updated`.
///
/// Requires `Branding(Update)`.
pub(crate) async fn reset_email_template(
    State(branding): State<BrandingState>,
    tenant: TenantCaller,
    Path(path): Path<TemplatePath>,
    Query(locale): Query<TemplateLocaleParams>,
) -> Result<NoContent, ApiError> {
    branding
        .reset_template
        .execute(
            &tenant.caller,
            &tenant.auditor,
            locale.slot(path.template())?,
        )
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/branding/email-templates/{template_type}/preview",
    tag = "Branding",
    params(TemplateLocaleParams),
    request_body = TemplatePreviewBody,
    responses(
        (status = 200, description = "The email as it reads", body = RenderedEmailResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Preview an email template
///
/// How one of the tenant's emails reads, filled with sample values and no
/// working link, exactly as the mailer renders it: its `subject`, `html`
/// and `text`. With no `draft` it shows the version the tenant keeps for
/// `?locale=` (or the platform's when it keeps none); with a `draft` it
/// shows a version not saved yet, checked as a saved one would be. Nothing
/// is saved or sent.
///
/// Requires `Branding(View)`, and `Branding(Update)` to preview a draft.
pub(crate) async fn preview_email_template(
    State(branding): State<BrandingState>,
    tenant: TenantCaller,
    TemplateSelection { path, locale }: TemplateSelection,
    Json(body): Json<TemplatePreviewBody>,
) -> Result<Json<RenderedEmailResponse>, ApiError> {
    let slot = locale.slot(path.template())?;
    let rendered = branding
        .preview_template
        .execute(&tenant.caller, body.into_request(slot)?)
        .await?;
    Ok(Json(RenderedEmailResponse::from(&rendered)))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/branding/email-templates/{template_type}/test-send",
    tag = "Branding",
    params(TemplateLocaleParams),
    request_body = TemplatePreviewBody,
    responses(
        (status = 204, description = "Sent"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody),
        (status = 502, description = "The mail provider did not take it", body = ErrorBody)
    )
)]
/// Send a test email
///
/// Mails one of the tenant's emails, the version the preview would show,
/// filled with sample values and no working link, to the caller's own
/// address, never one they type, through the provider the tenant's mail
/// goes out through now. An operator has no address to send to (`403`).
/// A provider that does not take the mail is `502`. Records nothing.
///
/// Requires `Branding(View)`, and `Branding(Update)` to send a draft.
pub(crate) async fn send_test_email(
    State(branding): State<BrandingState>,
    tenant: TenantCaller,
    TemplateSelection { path, locale }: TemplateSelection,
    Json(body): Json<TemplatePreviewBody>,
) -> Result<NoContent, ApiError> {
    let slot = locale.slot(path.template())?;
    branding
        .send_test_email
        .execute(&tenant.caller, body.into_request(slot)?)
        .await?;
    Ok(NoContent)
}
