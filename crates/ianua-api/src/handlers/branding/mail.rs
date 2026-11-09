//! Mail provider handlers: which provider a tenant's mail goes out
//! through, switching it, and a test send through it.

use axum::extract::State;
use ianua_app::use_case::{Command as _, Query as _};
use ianua_assembly::branding::BrandingState;

use crate::dto::branding::mail::{
    MailProviderResponse, MailProviderTestResponse, SwitchMailProviderBody,
};
use crate::error::{ApiError, ErrorBody};
use crate::extractors::callers::TenantCaller;
use crate::extractors::json::Json;
use crate::response::NoContent;

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/branding/mail-provider",
    tag = "Branding",
    responses(
        (status = 200, description = "The tenant's mail provider", body = MailProviderResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// The tenant's mail provider
///
/// Which provider the tenant named for its mail (`kind`: `platform`,
/// `smtp`, `sendgrid`, `ses`, `postmark` or `mailgun`) with where it
/// points, how the last test send through it went (`check`), and which
/// provider the mail goes out through now (`delivers_through`): the one
/// named once a test send through it worked, the platform's until then.
/// A tenant that never named one reads `platform`. Credentials are never
/// shown. Read-only.
///
/// Requires `Branding(View)`.
pub(crate) async fn get_mail_provider(
    State(branding): State<BrandingState>,
    tenant: TenantCaller,
) -> Result<Json<MailProviderResponse>, ApiError> {
    let named = branding.mail.get.execute(&tenant.caller, ()).await?;
    Ok(Json(MailProviderResponse::from(&named)))
}

#[utoipa::path(
    put,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/branding/mail-provider",
    tag = "Branding",
    request_body = SwitchMailProviderBody,
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Switch the tenant's mail provider
///
/// Selects `provider.kind`: SMTP (public host, port, `starttls` or
/// `implicit_tls`, username and password), SendGrid, SES, Postmark, Mailgun
/// or `platform`. Credentials are sealed and never returned. Mail uses the
/// platform until the selected provider passes a test send.
/// Requires `Branding(Update)` and fresh sign-in `proof`, because mail carries
/// sign-in and reset links. API keys and invalid proofs return `403`;
/// a missing second-factor code is requested. Records only provider kinds
/// in `branding.mail_provider_changed`.
pub(crate) async fn switch_mail_provider(
    State(branding): State<BrandingState>,
    tenant: TenantCaller,
    Json(body): Json<SwitchMailProviderBody>,
) -> Result<NoContent, ApiError> {
    branding
        .mail
        .switch
        .execute(&tenant.caller, &tenant.auditor, body.try_into()?)
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/branding/mail-provider/test",
    tag = "Branding",
    responses(
        (status = 200, description = "How the test send went", body = MailProviderTestResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 409, description = "The tenant sends through the platform's mail", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Test the tenant's mail provider
///
/// Sends one test mail through the provider the tenant named, to the
/// caller's own address, and keeps how it went: `delivered`, after which
/// the tenant's mail goes out through it, or `refused`, after which the
/// mail stays with the platform, so a mistyped key never stops anyone
/// getting their reset link. What the provider said is never shown. The
/// platform's own mail is not tested per tenant (`409`), and an operator
/// has no address to send to (`403`). Records
/// `branding.mail_provider_tested`.
///
/// Requires `Branding(Update)`.
pub(crate) async fn test_mail_provider(
    State(branding): State<BrandingState>,
    tenant: TenantCaller,
) -> Result<Json<MailProviderTestResponse>, ApiError> {
    let outcome = branding
        .mail
        .test
        .execute(&tenant.caller, &tenant.auditor, ())
        .await?;
    Ok(Json(MailProviderTestResponse::from(outcome)))
}
