//! Rows of the branding context: a tenant's look, its email templates and
//! its mail provider.

use ianua_domain::domains::branding::config::TenantBrandingRow;
use ianua_domain::domains::branding::email_template::{
    EmailHtmlBody, EmailTemplateRow, EmailTemplateType, EmailTextBody, MAX_SUBJECT_LENGTH,
    TemplateLocale,
};
use ianua_domain::domains::branding::mail_provider::{
    MailProvider, ProviderCheck, SmtpPort, SmtpSecurity, SmtpServer, SmtpServerParams,
    SmtpUsername, TenantMailProviderRow,
};
use ianua_domain::types::{
    HexColor, HostName, HttpsUrl, Label, Locale, Preference, PublicHost, SealedSecret, Setting,
};

use crate::test_support::rows::at;

/// A branding with its own logo, colors and sender name, sending from the
/// platform's address, with no custom CSS.
///
/// # Panics
///
/// Never: every value is a fixed, valid one.
#[must_use]
pub fn tenant_branding_row() -> TenantBrandingRow {
    TenantBrandingRow {
        logo_url: Setting::Set(HttpsUrl::new("https://cdn.acme.example/logo.png").expect("a URL")),
        primary_color: Setting::Set(HexColor::new("#FF5733").expect("a color")),
        background_color: Setting::Set(HexColor::new("#FFFFFF").expect("a color")),
        custom_css: Setting::Unset,
        email_from_name: Setting::Set(
            Label::new("email_from_name", "Acme Support").expect("a name"),
        ),
        email_from_address: Setting::Unset,
    }
}

/// The locale `tag`.
///
/// # Panics
///
/// When `tag` is not a locale, which is a mistake in the test.
#[must_use]
pub fn locale(tag: &str) -> TemplateLocale {
    TemplateLocale::For(Locale::new(tag).expect("a valid locale"))
}

/// A template of `template_type` for `locale`, with its own subject and
/// text body and the platform's HTML body.
///
/// # Panics
///
/// Never: every value is a fixed, valid one.
#[must_use]
pub fn email_template_row(
    template_type: EmailTemplateType,
    locale: TemplateLocale,
) -> EmailTemplateRow {
    EmailTemplateRow {
        template_type,
        locale,
        subject: Preference::Own(
            Label::with_max_length("email_subject", "Hello from Acme", MAX_SUBJECT_LENGTH)
                .expect("a subject"),
        ),
        body_html: Preference::Inherited,
        body_text: Preference::Own(EmailTextBody::new("Hello {{ user_name }}").expect("a body")),
    }
}

/// An HTML body holding only text.
///
/// # Panics
///
/// Never: the body is a fixed, valid one.
#[must_use]
pub fn html_body() -> EmailHtmlBody {
    EmailHtmlBody::new("<p>Hello</p>").expect("a body")
}

/// A sealed credential, as the crypto adapter hands it over.
///
/// # Panics
///
/// Never: the value is a fixed, valid one.
#[must_use]
pub fn sealed(value: &str) -> SealedSecret {
    SealedSecret::new(format!("v1.{value}")).expect("a sealed secret")
}

/// An SMTP server at `mail.acme.example` on 587, upgraded with STARTTLS.
///
/// # Panics
///
/// Never: every value is a fixed, valid one.
#[must_use]
pub fn smtp_provider() -> MailProvider {
    MailProvider::Smtp(SmtpServer::new(SmtpServerParams {
        host: PublicHost::new(HostName::new("mail.acme.example").expect("a host"))
            .expect("a public host"),
        port: SmtpPort::new(587).expect("a port"),
        security: SmtpSecurity::StartTls,
        username: SmtpUsername::new("mailer").expect("a user name"),
        password: sealed("password"),
    }))
}

/// `provider`, named at the fixed moment and not yet tested.
#[must_use]
pub fn mail_provider_row(provider: MailProvider) -> TenantMailProviderRow {
    TenantMailProviderRow {
        provider,
        check: ProviderCheck::Unverified,
        updated_at: at(0),
    }
}
