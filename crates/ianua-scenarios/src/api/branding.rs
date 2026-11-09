//! A tenant's branding: its look, logo and mail sender, and its own
//! versions of the platform's emails, written, previewed, test-sent and
//! reset.

use super::{Request, TenantPath};
use crate::net::Call;
use crate::wire::Page;
use crate::wire::branding::{
    Branding, BrandingChange, CustomEmail, EmailWording, LogoFile, LogoUploaded, PageLook,
    PreviewAsked, RenderedEmail,
};

/// `GET …/branding`.
#[must_use]
pub fn get(tenant: &TenantPath) -> Request<Branding> {
    Request::of(Call::get(tenant.at("/branding")))
}

/// `PATCH …/branding`.
#[must_use]
pub fn change(tenant: &TenantPath, change: &BrandingChange) -> Request<()> {
    Request::of(Call::patch(tenant.at("/branding")).json(change))
}

/// `GET …/branding/email-templates`: the emails the tenant wrote its own
/// version of.
#[must_use]
pub fn custom_emails(tenant: &TenantPath) -> Request<Page<CustomEmail>> {
    Request::of(Call::get(tenant.at("/branding/email-templates")))
}

/// `PUT …/branding/email-templates/{email}`: the tenant's own words for
/// the email `email`, such as `Welcome`.
#[must_use]
pub fn write_email(tenant: &TenantPath, email: &str, wording: &EmailWording) -> Request<()> {
    let path = tenant.at(&format!("/branding/email-templates/{email}"));
    Request::of(Call::put(path).json(wording))
}

/// `DELETE …/branding/email-templates/{email}`: back to the platform's
/// words.
#[must_use]
pub fn reset_email(tenant: &TenantPath, email: &str) -> Request<()> {
    let path = tenant.at(&format!("/branding/email-templates/{email}"));
    Request::of(Call::delete(path))
}

/// `POST …/branding/email-templates/{email}/preview`.
#[must_use]
pub fn preview_email(
    tenant: &TenantPath,
    email: &str,
    asked: &PreviewAsked,
) -> Request<RenderedEmail> {
    let path = tenant.at(&format!("/branding/email-templates/{email}/preview"));
    Request::of(Call::post(path).json(asked))
}

/// `POST …/branding/email-templates/{email}/test-send`: mails the email to
/// the caller's own address.
#[must_use]
pub fn test_send_email(tenant: &TenantPath, email: &str, asked: &PreviewAsked) -> Request<()> {
    let path = tenant.at(&format!("/branding/email-templates/{email}/test-send"));
    Request::of(Call::post(path).json(asked))
}

/// The boundary between the parts of a logo upload's form.
const FORM_BOUNDARY: &str = "ianua-scenario-logo-form";

/// `PATCH …/branding`: how the sign-in pages look.
#[must_use]
pub fn change_look(tenant: &TenantPath, look: &PageLook) -> Request<()> {
    Request::of(Call::patch(tenant.at("/branding")).json(look))
}

/// `POST …/branding/logo`: `file` in the form's `logo` field, sent as a
/// browser's upload form sends it.
#[must_use]
pub fn upload_logo(tenant: &TenantPath, file: &LogoFile) -> Request<LogoUploaded> {
    let content_type = format!("multipart/form-data; boundary={FORM_BOUNDARY}");
    let call = Call::post(tenant.at("/branding/logo")).bytes(&content_type, logo_form(file));
    Request::of(call)
}

/// `file` as the one part of a `multipart/form-data` body, in its `logo`
/// field.
fn logo_form(file: &LogoFile) -> Vec<u8> {
    let head = format!(
        "--{FORM_BOUNDARY}\r\nContent-Disposition: form-data; name=\"logo\"; filename=\"{}\"\r\nContent-Type: {}\r\n\r\n",
        file.file_name, file.content_type
    );
    let mut body = head.into_bytes();
    body.extend_from_slice(&file.bytes);
    body.extend_from_slice(format!("\r\n--{FORM_BOUNDARY}--\r\n").as_bytes());
    body
}
