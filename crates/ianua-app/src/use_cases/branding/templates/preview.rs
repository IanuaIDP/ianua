//! What a template preview shows: the template a tenant keeps, or a version
//! not saved yet, rendered with sample values the way the mailer sends it.

use ianua_domain::domains::authorization::authority::TenantAuthority;
use ianua_domain::domains::authorization::permission::{BrandingAction, SystemPermission};
use ianua_domain::domains::branding::control::BrandingControl;
use ianua_domain::domains::branding::email_template::{
    EmailHtmlBody, EmailTemplate, EmailTextBody, TemplateSlot,
};
use ianua_domain::domains::branding::renderer::RenderedEmail;
use ianua_domain::types::{Label, Preference};

use crate::error::{AppError, OrInternal};
use crate::ports::branding::{EmailTemplateStore, TemplateRenderer};
use crate::tenancy::ScopedTenant;

/// Which version of a template to preview.
pub enum TemplateDraft {
    /// The one the tenant keeps in the slot, or the platform's when it
    /// keeps none.
    Saved,
    /// A version not saved yet, as the editor holds it.
    Unsaved {
        /// Its subject line, or the platform's.
        subject: Preference<Label>,
        /// Its HTML body, or the platform's.
        body_html: Preference<EmailHtmlBody>,
        /// Its plain-text body, or the platform's.
        body_text: Preference<EmailTextBody>,
    },
}

/// The template to preview: which email, for which recipients, and which
/// version of it.
pub struct TemplatePreviewRequest {
    /// The email and the recipients it is written for.
    pub slot: TemplateSlot,
    /// Which version.
    pub draft: TemplateDraft,
}

/// Where a preview reads and renders from.
#[derive(Clone, Copy)]
pub(in crate::use_cases::branding) struct PreviewSources<'a> {
    /// The tenant's custom templates.
    pub(in crate::use_cases::branding) templates: &'a dyn EmailTemplateStore,
    /// Renders an email with sample values.
    pub(in crate::use_cases::branding) renderer: &'a dyn TemplateRenderer,
}

/// `request`'s template rendered for `tenant` with sample values, as
/// `authority` may see it.
///
/// A saved template needs the right to view branding. A version not saved
/// yet is checked as any template being written is, so it needs the right
/// to change branding.
///
/// # Errors
///
/// - `AppError::Forbidden` when the caller may not view branding, or may
///   not change it for a version not saved yet.
/// - `AppError::Domain` when an unsaved version holds template code beyond
///   the placeholders the email fills.
/// - `AppError::Internal` when the template cannot be read or rendered.
pub(in crate::use_cases::branding) async fn rendered_preview(
    sources: PreviewSources<'_>,
    tenant: &ScopedTenant,
    authority: &TenantAuthority,
    request: TemplatePreviewRequest,
) -> Result<RenderedEmail, AppError> {
    let template_type = request.slot.template_type;
    let template = previewed_template(sources.templates, tenant, authority, request).await?;
    let custom = template
        .as_ref()
        .map_or(Preference::Inherited, Preference::Own);
    sources
        .renderer
        .render_sample(tenant, template_type, custom)
        .await
        .or_internal()
}

/// The template `request` names, or `None` for the platform's own.
///
/// # Errors
///
/// As [`rendered_preview`].
async fn previewed_template(
    templates: &dyn EmailTemplateStore,
    tenant: &ScopedTenant,
    authority: &TenantAuthority,
    request: TemplatePreviewRequest,
) -> Result<Option<EmailTemplate>, AppError> {
    let TemplateDraft::Unsaved {
        subject,
        body_html,
        body_text,
    } = request.draft
    else {
        authority
            .ensure_holds(SystemPermission::Branding(BrandingAction::View))
            .map_err(AppError::from_domain)?;
        return templates.find(tenant, &request.slot).await.or_internal();
    };
    EmailTemplate::custom(
        request.slot,
        subject,
        body_html,
        body_text,
        &BrandingControl::new(authority),
    )
    .map(Some)
    .map_err(AppError::from_domain)
}
