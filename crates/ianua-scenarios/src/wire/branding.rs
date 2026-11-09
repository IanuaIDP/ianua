//! How a tenant looks and writes: its colours and mail sender, and its own
//! versions of the platform's emails, previewed and test-sent.

use serde::{Deserialize, Serialize};

/// `GET …/branding`: the tenant's look; an unset part is `None`, the
/// platform's default.
#[derive(Debug, Clone, Deserialize)]
pub struct Branding {
    /// The main colour, such as `#0A84FF`.
    #[serde(default)]
    pub primary_color: Option<String>,
    /// The name mail from the tenant is sent under.
    #[serde(default)]
    pub email_from_name: Option<String>,
    /// Where the logo on its sign-in pages and mail is served.
    #[serde(default)]
    pub logo_url: Option<String>,
    /// The sign-in pages' background colour.
    #[serde(default)]
    pub background_color: Option<String>,
}

/// `PATCH …/branding`: how the tenant's sign-in pages look; the parts not
/// named stay as they are.
#[derive(Debug, Clone, Default, Serialize)]
pub struct PageLook {
    /// A new colour for buttons and links, `#RGB` or `#RRGGBB`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub primary_color: Option<String>,
    /// A new background colour.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub background_color: Option<String>,
    /// CSS of the tenant's own for its sign-in pages, cleaned before any
    /// page wears it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub custom_css: Option<String>,
}

/// A file uploaded as the tenant's logo, as a browser's form sends it:
/// the name and type the uploader claims, and the bytes themselves.
#[derive(Debug, Clone)]
pub struct LogoFile {
    /// The file's name, such as `acme.png`.
    pub file_name: String,
    /// The type the uploader claims, such as `image/png`.
    pub content_type: String,
    /// What the file holds.
    pub bytes: Vec<u8>,
}

/// `POST …/branding/logo`: where the logo is served now.
#[derive(Debug, Clone, Deserialize)]
pub struct LogoUploaded {
    /// The logo's address, now the branding's `logo_url`.
    pub logo_url: String,
}

/// `PATCH …/branding`: the parts that change; the others stay.
#[derive(Debug, Clone, Default, Serialize)]
pub struct BrandingChange {
    /// A new main colour, `#RGB` or `#RRGGBB`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub primary_color: Option<String>,
    /// A new sender name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_from_name: Option<String>,
}

/// `PUT …/branding/email-templates/{type}`, and a draft to preview: the
/// tenant's words for one email, placeholders such as `{{ user_name }}`
/// and the link as `{{ action_link }}`.
#[derive(Debug, Clone, Serialize)]
pub struct EmailWording {
    /// The subject line.
    pub subject: String,
    /// What a mail reader that shows HTML displays.
    pub body_html: String,
    /// The plain-text body.
    pub body_text: String,
}

/// `POST …/preview` and `…/test-send`: the saved version when `draft` is
/// `None`, else the words being written.
#[derive(Debug, Clone, Serialize)]
pub struct PreviewAsked {
    /// Words not saved yet.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub draft: Option<EmailWording>,
}

/// One email as the mailer renders it, filled with sample values.
#[derive(Debug, Clone, Deserialize)]
pub struct RenderedEmail {
    /// The subject line.
    pub subject: String,
    /// The plain-text body.
    pub text: String,
}

/// One email the tenant wrote its own version of, from
/// `GET …/branding/email-templates`.
#[derive(Debug, Clone, Deserialize)]
pub struct CustomEmail {
    /// Which email, such as `Welcome`.
    pub template_type: String,
    /// The tenant's subject, when it set one.
    #[serde(default)]
    pub subject: Option<String>,
    /// Whether any part is the tenant's own.
    pub is_custom: bool,
}
