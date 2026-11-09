//! The platform's own mail: one subject, HTML body and text body for every
//! type of mail, the bodies kept as files under `templates/mail/`, one
//! folder per topic and the shared layout in `layout/`.
//!
//! Every mail is also shipped in each translated language, generated into
//! `locales/<tag>/templates/mail/` by `ianua-translate write-fluent`, with
//! its subject beside its bodies. Each language is rendered in an engine
//! of its own, since every language's bodies extend a layout of the same
//! name.

use ianua_domain::domains::branding::email_template::EmailTemplateType;
use ianua_domain::shared::errors::DomainError;
use minijinja::{Environment, UndefinedBehavior};

use crate::language::Language;
use crate::mail::compose::{Part, escape_for};

/// Every type of mail, each loaded once when the composer is made.
pub(super) const EVERY_TYPE: [EmailTemplateType; 30] = [
    EmailTemplateType::Verification,
    EmailTemplateType::PasswordReset,
    EmailTemplateType::MagicLink,
    EmailTemplateType::Invitation,
    EmailTemplateType::AccountLocked,
    EmailTemplateType::MfaEnrolled,
    EmailTemplateType::RecoveryCodes,
    EmailTemplateType::DeviceTrusted,
    EmailTemplateType::SessionSuspended,
    EmailTemplateType::BreachedPassword,
    EmailTemplateType::ErasureConfirmation,
    EmailTemplateType::ErasureCompleted,
    EmailTemplateType::Welcome,
    EmailTemplateType::EmailChangeVerification,
    EmailTemplateType::EmailChanged,
    EmailTemplateType::EmailChangeRequested,
    EmailTemplateType::AccountLinked,
    EmailTemplateType::SignInCode,
    EmailTemplateType::ExportReady,
    EmailTemplateType::ImpersonationRequested,
    EmailTemplateType::OrgVerification,
    EmailTemplateType::OrgInvitation,
    EmailTemplateType::OrgWelcome,
    EmailTemplateType::OrgMfaReset,
    EmailTemplateType::OrgEmailChangeRequested,
    EmailTemplateType::SignupVerification,
    EmailTemplateType::SignupWelcome,
    EmailTemplateType::SignupAccountExists,
    EmailTemplateType::ActivationWelcome,
    EmailTemplateType::ActivityNotice,
];

/// One type's mail: the name its files carry, and its English and
/// translated parts.
struct PlatformTemplate {
    key: &'static str,
    english: Parts,
    translated: [(Language, Parts); 7],
}

/// The subject line and the two bodies of one mail in one language.
#[derive(Clone, Copy)]
struct Parts {
    subject: &'static str,
    html: &'static str,
    text: &'static str,
}

impl PlatformTemplate {
    /// The parts written in `language`, or the English ones.
    fn parts_in(&self, language: Language) -> Parts {
        self.translated
            .iter()
            .find(|(translated, _)| *translated == language)
            .map_or(self.english, |(_, parts)| *parts)
    }
}

/// The translated parts of the mail `key` in the language of folder `tag`,
/// its subject read from the file beside its bodies unless given.
macro_rules! translated {
    ($tag:literal, $key:literal) => {
        translated!(
            $tag,
            $key,
            include_str!(concat!(
                "../../../locales/",
                $tag,
                "/templates/mail/",
                $key,
                ".subject"
            ))
        )
    };
    ($tag:literal, $key:literal, $subject:expr) => {
        Parts {
            subject: $subject,
            html: include_str!(concat!(
                "../../../locales/",
                $tag,
                "/templates/mail/",
                $key,
                ".html"
            )),
            text: include_str!(concat!(
                "../../../locales/",
                $tag,
                "/templates/mail/",
                $key,
                ".txt"
            )),
        }
    };
}

/// The mail `key` in every translated language.
macro_rules! every_translation {
    ($key:literal $(, $subject:expr)?) => {
        [
            (Language::German, translated!("de", $key $(, $subject)?)),
            (Language::Spanish, translated!("es", $key $(, $subject)?)),
            (Language::French, translated!("fr", $key $(, $subject)?)),
            (Language::Japanese, translated!("ja", $key $(, $subject)?)),
            (Language::Georgian, translated!("ka", $key $(, $subject)?)),
            (Language::Ukrainian, translated!("uk", $key $(, $subject)?)),
            (Language::SimplifiedChinese, translated!("zh-Hans", $key $(, $subject)?)),
        ]
    };
}

/// The platform's template kept under `key`, with `subject`. A subject
/// that is only a value, with no words, is the same in every language.
macro_rules! template {
    ($key:literal, $subject:literal) => {
        PlatformTemplate {
            key: $key,
            english: english!($key, $subject),
            translated: every_translation!($key),
        }
    };
    ($key:literal, $subject:literal, same_in_every_language) => {
        PlatformTemplate {
            key: $key,
            english: english!($key, $subject),
            translated: every_translation!($key, $subject),
        }
    };
}

/// The English parts of the mail `key`, with `subject`.
macro_rules! english {
    ($key:literal, $subject:literal) => {
        Parts {
            subject: $subject,
            html: include_str!(concat!("../../../templates/mail/", $key, ".html")),
            text: include_str!(concat!("../../../templates/mail/", $key, ".txt")),
        }
    };
}

/// The layout every HTML body in `language` extends, and the parts it is
/// built from.
/// The exhaustive table keeps every supported language tied to both embedded layout files.
#[allow(clippy::too_many_lines)]
fn layout_of(language: Language) -> (&'static str, &'static str) {
    match language {
        Language::English => (
            include_str!("../../../templates/mail/layout/page.html"),
            include_str!("../../../templates/mail/layout/parts.html"),
        ),
        Language::German => (
            include_str!("../../../locales/de/templates/mail/layout/page.html"),
            include_str!("../../../locales/de/templates/mail/layout/parts.html"),
        ),
        Language::Spanish => (
            include_str!("../../../locales/es/templates/mail/layout/page.html"),
            include_str!("../../../locales/es/templates/mail/layout/parts.html"),
        ),
        Language::French => (
            include_str!("../../../locales/fr/templates/mail/layout/page.html"),
            include_str!("../../../locales/fr/templates/mail/layout/parts.html"),
        ),
        Language::Japanese => (
            include_str!("../../../locales/ja/templates/mail/layout/page.html"),
            include_str!("../../../locales/ja/templates/mail/layout/parts.html"),
        ),
        Language::Georgian => (
            include_str!("../../../locales/ka/templates/mail/layout/page.html"),
            include_str!("../../../locales/ka/templates/mail/layout/parts.html"),
        ),
        Language::Ukrainian => (
            include_str!("../../../locales/uk/templates/mail/layout/page.html"),
            include_str!("../../../locales/uk/templates/mail/layout/parts.html"),
        ),
        Language::SimplifiedChinese => (
            include_str!("../../../locales/zh-Hans/templates/mail/layout/page.html"),
            include_str!("../../../locales/zh-Hans/templates/mail/layout/parts.html"),
        ),
    }
}

/// The name the files and templates of `template_type` are kept under.
pub(super) fn key_of(template_type: EmailTemplateType) -> &'static str {
    template_of(template_type).key
}

/// The platform's template of `template_type`.
// One arm per type, with no catch-all: a new type of mail does not build
// until the platform has written it. Splitting it would bring one back.
#[allow(clippy::too_many_lines)]
fn template_of(template_type: EmailTemplateType) -> PlatformTemplate {
    match template_type {
        EmailTemplateType::Verification => {
            template!("account/verification", "Verify your email address")
        }
        EmailTemplateType::PasswordReset => {
            template!("sign_in/password_reset", "Reset your password")
        }
        EmailTemplateType::MagicLink => template!("sign_in/magic_link", "Your sign-in link"),
        EmailTemplateType::Invitation => template!(
            "joining/invitation",
            "You are invited to join {{ tenant_name | default(\"a team\") }}"
        ),
        EmailTemplateType::AccountLocked => {
            template!("sign_in/account_locked", "Your account was locked")
        }
        EmailTemplateType::MfaEnrolled => {
            template!("security/mfa_enrolled", "Two-step sign-in turned on")
        }
        EmailTemplateType::RecoveryCodes => {
            template!("security/recovery_codes", "New recovery codes made")
        }
        EmailTemplateType::DeviceTrusted => {
            template!("security/device_trusted", "A new device is trusted")
        }
        EmailTemplateType::SessionSuspended => {
            template!("security/session_suspended", "A session was stopped")
        }
        EmailTemplateType::BreachedPassword => {
            template!(
                "sign_in/breached_password",
                "Your password was found in a breach"
            )
        }
        EmailTemplateType::ErasureConfirmation => {
            template!(
                "privacy/erasure_confirmation",
                "We have your deletion request"
            )
        }
        EmailTemplateType::ErasureCompleted => {
            template!("privacy/erasure_completed", "Your data was deleted")
        }
        EmailTemplateType::Welcome => template!(
            "account/welcome",
            "Welcome to {{ tenant_name | default(\"IANUA\") }}"
        ),
        EmailTemplateType::EmailChangeVerification => {
            template!(
                "account/email_change_verification",
                "Verify your new email address"
            )
        }
        EmailTemplateType::EmailChanged => {
            template!("account/email_changed", "Your email address was changed")
        }
        EmailTemplateType::EmailChangeRequested => {
            template!(
                "account/email_change_requested",
                "Someone asked to move your account"
            )
        }
        EmailTemplateType::AccountLinked => template!(
            "sign_in/account_linked",
            "Your account was linked to {{ provider_name | default(\"a sign-in provider\") }}"
        ),
        EmailTemplateType::SignInCode => template!("sign_in/sign_in_code", "Your sign-in code"),
        EmailTemplateType::ExportReady => {
            template!("privacy/export_ready", "Your copy of your data is ready")
        }
        EmailTemplateType::ImpersonationRequested => {
            template!(
                "activity/impersonation_requested",
                "An administrator asks to act as you"
            )
        }
        EmailTemplateType::OrgVerification => {
            template!("organization/verification", "Verify your email address")
        }
        EmailTemplateType::OrgInvitation => template!(
            "organization/invitation",
            "You are invited to join {{ organization_name | default(\"an organization\") }}"
        ),
        EmailTemplateType::OrgWelcome => template!(
            "organization/welcome",
            "Welcome to {{ organization_name | default(\"IANUA\") }}"
        ),
        EmailTemplateType::OrgMfaReset => {
            template!("organization/mfa_reset", "Your second factor was reset")
        }
        EmailTemplateType::OrgEmailChangeRequested => {
            template!(
                "organization/email_change_requested",
                "Someone asked to move your account"
            )
        }
        EmailTemplateType::SignupVerification => {
            template!("joining/signup_verification", "Verify your email address")
        }
        EmailTemplateType::SignupWelcome => {
            template!("joining/signup_welcome", "Your organization is ready")
        }
        EmailTemplateType::SignupAccountExists => {
            template!(
                "joining/signup_account_exists",
                "You already have an account"
            )
        }
        EmailTemplateType::ActivationWelcome => {
            template!("account/activation_welcome", "Your account is ready")
        }
        EmailTemplateType::ActivityNotice => template!(
            "activity/notice",
            "{{ notice_title }}",
            same_in_every_language
        ),
    }
}

/// The engine the platform's mail in `language` is rendered in, every
/// type's three parts loaded and parsed, undefined values refused.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when a template does not parse.
pub(super) fn environment(language: Language) -> Result<Environment<'static>, DomainError> {
    let mut engine = Environment::new();
    engine.set_undefined_behavior(UndefinedBehavior::Strict);
    engine.set_auto_escape_callback(escape_for);
    let (layout, components) = layout_of(language);
    engine
        .add_template("layout/page.html", layout)
        .map_err(DomainError::infra)?;
    engine
        .add_template("layout/parts.html", components)
        .map_err(DomainError::infra)?;
    for template in EVERY_TYPE.map(template_of) {
        let parts = template.parts_in(language);
        for (part, source) in [
            (Part::Subject, parts.subject),
            (Part::Html, parts.html),
            (Part::Text, parts.text),
        ] {
            engine
                .add_template_owned(part.platform_name(template.key), source)
                .map_err(DomainError::infra)?;
        }
    }
    Ok(engine)
}
