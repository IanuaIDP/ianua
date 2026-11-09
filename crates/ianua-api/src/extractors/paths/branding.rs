//! The email template a branding request names.

use ianua_domain::domains::branding::email_template::EmailTemplateType;
use serde::Deserialize;

/// `.../branding/email-templates/{template_type}`, the type spelled as it
/// is stored, such as `PasswordReset`.
#[derive(Deserialize)]
pub(crate) struct TemplatePath {
    template_type: EmailTemplateType,
}

impl TemplatePath {
    /// The email named.
    #[must_use]
    pub(crate) fn template(&self) -> EmailTemplateType {
        self.template_type
    }
}
