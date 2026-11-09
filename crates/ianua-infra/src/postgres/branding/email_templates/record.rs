//! An email template as its row holds it: read back into the template, and
//! written out from it.

use ianua_domain::domains::branding::email_template::{
    EmailHtmlBody, EmailTemplate, EmailTemplateRow, EmailTemplateType, EmailTextBody,
    MAX_SUBJECT_LENGTH, TemplateLocale, TemplateSlot,
};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{Label, Locale, Preference};
use uuid::Uuid;

use crate::postgres::foundation::stored::{Stored, StoredWord as _};

const TEMPLATE: Stored = Stored("email template");

/// A template as it is read, with the id its row keeps. The store's
/// checked queries fill it.
pub(super) struct TemplateRecord {
    pub(super) id: Uuid,
    pub(super) template_type: String,
    pub(super) locale: Option<String>,
    pub(super) subject: Option<String>,
    pub(super) body_html: Option<String>,
    pub(super) body_text: Option<String>,
}

impl TemplateRecord {
    /// The template the record holds, rebuilt through the domain's checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a part no longer passes
    /// its rules, the type is unknown, or the template holds more than the
    /// placeholders its type fills.
    pub(super) fn into_template(self) -> Result<EmailTemplate, DomainError> {
        let locale = self
            .locale
            .map(|tag| TEMPLATE.value("locale", Locale::new(tag)))
            .transpose()?;
        let subject = self
            .subject
            .map(|text| {
                TEMPLATE.value(
                    "subject",
                    Label::with_max_length("email_subject", text, MAX_SUBJECT_LENGTH),
                )
            })
            .transpose()?;
        let body_html = self
            .body_html
            .map(|body| TEMPLATE.value("HTML body", EmailHtmlBody::new(body)))
            .transpose()?;
        let body_text = self
            .body_text
            .map(|body| TEMPLATE.value("text body", EmailTextBody::new(body)))
            .transpose()?;
        EmailTemplate::reconstitute(EmailTemplateRow {
            template_type: TEMPLATE.choice(&self.template_type)?,
            locale: TemplateLocale::from_stored(locale),
            subject: Preference::from_stored(subject),
            body_html: Preference::from_stored(body_html),
            body_text: Preference::from_stored(body_text),
        })
    }

    /// The template the record holds, with the id its row keeps, which a
    /// list breaks ties by.
    ///
    /// # Errors
    ///
    /// As [`into_template`](Self::into_template).
    pub(super) fn into_listed(self) -> Result<(Uuid, EmailTemplate), DomainError> {
        let id = self.id;
        self.into_template().map(|template| (id, template))
    }
}

/// A slot's columns: the type's word, and the locale or none for every
/// locale.
pub(super) fn slot_columns(slot: &TemplateSlot) -> (&'static str, Option<&str>) {
    (
        slot.template_type.word(),
        slot.locale.locale().map(Locale::as_str),
    )
}

/// The word `template_type` is stored as.
pub(super) fn type_word(template_type: EmailTemplateType) -> &'static str {
    template_type.word()
}

/// A template's columns, as they are written.
pub(super) struct TemplateColumns<'a> {
    pub(super) template_type: &'static str,
    pub(super) locale: Option<&'a str>,
    pub(super) subject: Option<&'a str>,
    pub(super) body_html: Option<&'a str>,
    pub(super) body_text: Option<&'a str>,
}

impl<'a> TemplateColumns<'a> {
    /// The columns `template` is written to.
    pub(super) fn of(template: &'a EmailTemplate) -> Self {
        Self {
            template_type: template.template_type().word(),
            locale: template.locale().locale().map(Locale::as_str),
            subject: template.subject().value().map(Label::as_str),
            body_html: template.body_html().value().map(EmailHtmlBody::as_str),
            body_text: template.body_text().value().map(EmailTextBody::as_str),
        }
    }
}
