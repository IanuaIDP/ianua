//! Email template bodies: a tenant's own versions of the platform's
//! emails, for every locale or one, and how one reads filled with sample
//! values.

use ianua_app::use_cases::branding::{
    TemplateDraft, TemplatePreviewRequest, UpdateEmailTemplateRequest,
};
use ianua_domain::domains::branding::email_template::{
    EmailHtmlBody, EmailTemplate, EmailTemplateType, EmailTextBody, TemplateLocale, TemplateSlot,
};
use ianua_domain::domains::branding::renderer::RenderedEmail;
use ianua_domain::types::{Label, Locale, Preference};
use serde::{Deserialize, Serialize};

use crate::error::ApiError;

/// A tenant's own version of one email. A part still on the platform's
/// default is `null`.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct EmailTemplateResponse {
    /// Which email, such as `PasswordReset`.
    #[schema(schema_with = crate::dto::schemas::email_template_type)]
    pub template_type: EmailTemplateType,
    /// The recipients' locale it is written for, such as `de-DE`, or
    /// `null` for every locale without a version of its own.
    pub locale: Option<String>,
    /// The subject, when the tenant set one.
    pub subject: Option<String>,
    /// The HTML body, when the tenant set one.
    pub body_html: Option<String>,
    /// The plain-text body, when the tenant set one.
    pub body_text: Option<String>,
    /// Whether any part is the tenant's own.
    pub is_custom: bool,
}

impl From<EmailTemplate> for EmailTemplateResponse {
    fn from(template: EmailTemplate) -> Self {
        Self {
            template_type: template.template_type(),
            locale: template
                .locale()
                .locale()
                .map(|locale| locale.as_str().to_owned()),
            subject: own(template.subject(), Label::as_str),
            body_html: own(template.body_html(), EmailHtmlBody::as_str),
            body_text: own(template.body_text(), EmailTextBody::as_str),
            is_custom: template.has_customization(),
        }
    }
}

/// Which recipients' version of an email a request names.
#[derive(Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct TemplateLocaleParams {
    /// The recipients' locale, such as `de-DE`; the version for every
    /// locale when omitted.
    pub locale: Option<String>,
}

impl TemplateLocaleParams {
    /// The version of `template_type` this query names.
    ///
    /// # Errors
    ///
    /// A validation error for a locale that is not a BCP 47 tag.
    pub(crate) fn slot(&self, template_type: EmailTemplateType) -> Result<TemplateSlot, ApiError> {
        let locale = self
            .locale
            .clone()
            .map(Locale::new)
            .transpose()
            .map_err(ApiError::validation)?;
        Ok(TemplateSlot {
            template_type,
            locale: TemplateLocale::from_stored(locale),
        })
    }
}

/// The parts of one email the tenant writes. An omitted part follows the
/// platform's default.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct UpdateEmailTemplateBody {
    /// The subject, at most 100 characters.
    pub subject: Option<String>,
    /// The tenant's markup, or `null` to use the platform's email content.
    pub body_html: Option<String>,
    /// The plain-text body.
    pub body_text: Option<String>,
}

impl UpdateEmailTemplateBody {
    /// The tenant's version of the email in `slot` this body describes.
    ///
    /// # Errors
    ///
    /// A validation error for a subject or body that is not a valid one.
    pub(crate) fn into_request(
        self,
        slot: TemplateSlot,
    ) -> Result<UpdateEmailTemplateRequest, ApiError> {
        Ok(UpdateEmailTemplateRequest {
            template_type: slot.template_type,
            locale: slot.locale,
            subject: preference(self.subject, |subject| Label::new("subject", subject))?,
            body_html: preference(self.body_html, EmailHtmlBody::new)?,
            body_text: preference(self.body_text, EmailTextBody::new)?,
        })
    }

    /// This body as a version of an email not saved yet.
    ///
    /// # Errors
    ///
    /// As [`Self::into_request`].
    fn into_draft(self) -> Result<TemplateDraft, ApiError> {
        Ok(TemplateDraft::Unsaved {
            subject: preference(self.subject, |subject| Label::new("subject", subject))?,
            body_html: preference(self.body_html, EmailHtmlBody::new)?,
            body_text: preference(self.body_text, EmailTextBody::new)?,
        })
    }
}

/// Which version of an email to preview or send as a test: the one the
/// tenant keeps, or one being written.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct TemplatePreviewBody {
    /// A version not saved yet, as the editor holds it; the saved one
    /// (or the platform's, when the tenant keeps none) when omitted or
    /// `null`.
    #[serde(default)]
    pub draft: Option<UpdateEmailTemplateBody>,
}

impl TemplatePreviewBody {
    /// The preview of the email in `slot` this body asks for.
    ///
    /// # Errors
    ///
    /// A validation error for a draft subject or body that is not a valid
    /// one.
    pub(crate) fn into_request(
        self,
        slot: TemplateSlot,
    ) -> Result<TemplatePreviewRequest, ApiError> {
        let draft = match self.draft {
            None => TemplateDraft::Saved,
            Some(draft) => draft.into_draft()?,
        };
        Ok(TemplatePreviewRequest { slot, draft })
    }
}

/// An email as the mailer sends it, filled with sample values and no
/// working link.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct RenderedEmailResponse {
    /// The subject line.
    pub subject: String,
    /// The HTML body, when the email has one.
    pub html: Option<String>,
    /// The plain-text body.
    pub text: String,
}

impl From<&RenderedEmail> for RenderedEmailResponse {
    fn from(email: &RenderedEmail) -> Self {
        Self {
            subject: email.subject().to_owned(),
            html: email.html().map(ToOwned::to_owned),
            text: email.text().to_owned(),
        }
    }
}

/// The tenant's own value of a part, as text, when it has one.
fn own<T>(part: &Preference<T>, text: impl Fn(&T) -> &str) -> Option<String> {
    part.value().map(|value| text(value).to_owned())
}

/// `value` checked by `parse` as the tenant's own, or the platform's when
/// none is given.
fn preference<T, E: Into<ianua_domain::shared::errors::DomainError>>(
    value: Option<String>,
    parse: impl FnOnce(String) -> Result<T, E>,
) -> Result<Preference<T>, ApiError> {
    value
        .map(parse)
        .transpose()
        .map(Preference::from_stored)
        .map_err(ApiError::validation)
}
