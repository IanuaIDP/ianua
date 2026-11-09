//! Branding endpoints: a tenant's look and logo, its own versions of the
//! platform's emails with their previews and test sends, and the provider
//! its mail goes out through.

use axum::Router;
use utoipa::OpenApi;

use crate::dto::branding::mail::{
    MailProviderBody, MailProviderResponse, MailProviderTestResponse, MailgunRegionBody,
    SmtpSecurityBody, SwitchMailProviderBody,
};
use crate::dto::branding::templates::{
    EmailTemplateResponse, RenderedEmailResponse, TemplatePreviewBody, UpdateEmailTemplateBody,
};
use crate::dto::branding::{
    BrandingResponse, LogoUploadForm, LogoUploadedResponse, UpdateBrandingBody,
};
use crate::handlers::branding as handlers;
use crate::handlers::branding::{mail, templates};
use crate::method::{get, post, put, shared};
use crate::state::ApiState;

/// The branding endpoints.
pub(crate) fn routes() -> Router<ApiState> {
    let branding = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/branding";
    let template = format!("{branding}/email-templates/{{template_type}}");
    let provider = format!("{branding}/mail-provider");
    Router::new()
        .route(
            branding,
            get(handlers::get_branding).patch(shared(handlers::update_branding)),
        )
        .route(&format!("{branding}/logo"), post(handlers::upload_logo))
        .route(
            &format!("{branding}/email-templates"),
            get(templates::list_email_templates),
        )
        .route(
            &template,
            put(templates::update_email_template).delete(shared(templates::reset_email_template)),
        )
        .route(
            &format!("{template}/preview"),
            post(templates::preview_email_template),
        )
        .route(
            &format!("{template}/test-send"),
            post(templates::send_test_email),
        )
        .route(
            &provider,
            get(mail::get_mail_provider).put(shared(mail::switch_mail_provider)),
        )
        .route(&format!("{provider}/test"), post(mail::test_mail_provider))
}

/// The branding part of the OpenAPI document.
#[derive(OpenApi)]
#[openapi(
    paths(
        handlers::get_branding,
        handlers::update_branding,
        handlers::upload_logo,
        templates::list_email_templates,
        templates::update_email_template,
        templates::reset_email_template,
        templates::preview_email_template,
        templates::send_test_email,
        mail::get_mail_provider,
        mail::switch_mail_provider,
        mail::test_mail_provider,
    ),
    components(schemas(
        BrandingResponse,
        UpdateBrandingBody,
        LogoUploadForm,
        LogoUploadedResponse,
        EmailTemplateResponse,
        UpdateEmailTemplateBody,
        TemplatePreviewBody,
        RenderedEmailResponse,
        MailProviderResponse,
        SwitchMailProviderBody,
        MailProviderBody,
        SmtpSecurityBody,
        MailgunRegionBody,
        MailProviderTestResponse,
    ))
)]
pub(crate) struct Document;
