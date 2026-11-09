//! Which recipients a tenant's email template is written for, and which
//! template a recipient gets.
//!
//! A tenant writes each email once for every locale, and may write it again
//! for a locale of its own, such as `de-DE`. A recipient gets the template
//! of their own locale, else one written for another locale of their
//! language, else the tenant's template for every locale, else the
//! platform's mail.

use crate::domains::branding::email_template::{EmailTemplate, EmailTemplateType};
use crate::types::{Locale, Preference};

/// Which recipients a template is written for.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub enum TemplateLocale {
    /// Every recipient whose language has no template of its own.
    Fallback,
    /// Recipients of this locale, and those of its language whose own
    /// locale has none.
    For(Locale),
}

impl TemplateLocale {
    /// The locale it is written for, when it is one. Storage keeps it this
    /// way.
    #[must_use]
    pub fn locale(&self) -> Option<&Locale> {
        match self {
            Self::Fallback => None,
            Self::For(locale) => Some(locale),
        }
    }

    /// The locale a stored value records. No locale stored is the template
    /// for every locale.
    #[must_use]
    pub fn from_stored(locale: Option<Locale>) -> Self {
        locale.map_or(Self::Fallback, Self::For)
    }

    /// Whether it is written for another locale of `recipient`'s language.
    fn shares_language_with(&self, recipient: &Locale) -> bool {
        self.locale()
            .is_some_and(|locale| language_of(locale) == language_of(recipient))
    }
}

/// The email and the recipients a template is written for. A tenant keeps
/// one template per slot.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TemplateSlot {
    /// Which email.
    pub template_type: EmailTemplateType,
    /// Which recipients.
    pub locale: TemplateLocale,
}

impl From<EmailTemplateType> for TemplateSlot {
    /// The template of an email for every locale without one of its own.
    fn from(template_type: EmailTemplateType) -> Self {
        Self {
            template_type,
            locale: TemplateLocale::Fallback,
        }
    }
}

/// The tenant template a recipient of `recipient`'s locale gets for
/// `template_type`, out of the tenant's `templates`, or that the platform's
/// mail goes out.
///
/// The template of their own locale wins. Then one for another locale of
/// their language, the first by its tag when there are several, so Ann in
/// `de-AT` gets Acme's `de-DE` mail. Then the tenant's template for every
/// locale.
#[must_use]
pub fn template_for<'a>(
    templates: &'a [EmailTemplate],
    template_type: EmailTemplateType,
    recipient: &Locale,
) -> Preference<&'a EmailTemplate> {
    let of_type = || {
        templates
            .iter()
            .filter(move |template| template.template_type() == template_type)
    };
    let own = of_type().find(|template| template.locale().locale() == Some(recipient));
    let same_language = || {
        of_type()
            .filter(|template| template.locale().shares_language_with(recipient))
            .min_by_key(|template| template.locale().locale().map(Locale::as_str))
    };
    let fallback = || of_type().find(|template| *template.locale() == TemplateLocale::Fallback);
    own.or_else(same_language)
        .or_else(fallback)
        .map_or(Preference::Inherited, Preference::Own)
}

/// The language part of a locale tag: `de` of `de-AT`.
fn language_of(locale: &Locale) -> &str {
    let tag = locale.as_str();
    tag.split_once('-').map_or(tag, |(language, _)| language)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::authorization::permission::{BrandingAction, SystemPermission};
    use crate::domains::branding::control::BrandingControl;
    use crate::domains::branding::email_template::EmailHtmlBody;
    use crate::test_support::authority::anyone_holding;
    use crate::test_support::builders::label;

    fn locale(tag: &str) -> Locale {
        Locale::new(tag).unwrap()
    }

    /// Acme's welcome mail for `for_locale`, its subject naming the locale.
    fn welcome(for_locale: TemplateLocale, subject: &str) -> EmailTemplate {
        let editor = BrandingControl::new(anyone_holding(&[SystemPermission::Branding(
            BrandingAction::Update,
        )]));
        EmailTemplate::custom(
            TemplateSlot {
                template_type: EmailTemplateType::Welcome,
                locale: for_locale,
            },
            Preference::Own(label(subject)),
            Preference::Own(EmailHtmlBody::new("<p>Welcome</p>").unwrap()),
            Preference::Inherited,
            &editor,
        )
        .unwrap()
    }

    fn subject_of(chosen: Preference<&EmailTemplate>) -> Option<String> {
        chosen
            .value()
            .and_then(|template| template.subject().value())
            .map(|subject| subject.as_str().to_owned())
    }

    fn acme() -> Vec<EmailTemplate> {
        vec![
            welcome(TemplateLocale::Fallback, "Welcome"),
            welcome(TemplateLocale::For(locale("de-DE")), "Willkommen"),
            welcome(TemplateLocale::For(locale("fr-FR")), "Bienvenue"),
        ]
    }

    /// Ann reads French. She gets Acme's French welcome mail.
    #[test]
    fn a_recipient_gets_the_template_of_their_own_locale() {
        let templates = acme();

        let chosen = template_for(&templates, EmailTemplateType::Welcome, &locale("fr-FR"));

        assert_eq!(subject_of(chosen).as_deref(), Some("Bienvenue"));
    }

    /// Bob reads Austrian German, which Acme wrote no mail for. He gets the
    /// German one before the mail for every locale.
    #[test]
    fn a_recipient_gets_their_language_before_the_fallback() {
        let templates = acme();

        let chosen = template_for(&templates, EmailTemplateType::Welcome, &locale("de-AT"));

        assert_eq!(subject_of(chosen).as_deref(), Some("Willkommen"));
    }

    /// Carol reads Japanese. She gets Acme's welcome mail for every locale.
    #[test]
    fn a_recipient_of_another_language_gets_the_fallback() {
        let templates = acme();

        let chosen = template_for(&templates, EmailTemplateType::Welcome, &locale("ja-JP"));

        assert_eq!(subject_of(chosen).as_deref(), Some("Welcome"));
    }

    /// Acme wrote no password reset mail. The platform's goes out, in any
    /// locale.
    #[test]
    fn an_email_the_tenant_never_wrote_comes_from_the_platform() {
        let templates = acme();

        let chosen = template_for(
            &templates,
            EmailTemplateType::PasswordReset,
            &locale("fr-FR"),
        );

        assert!(chosen.value().is_none());
    }

    /// A template for an email type alone is the one for every locale.
    #[test]
    fn an_email_type_alone_names_the_template_for_every_locale() {
        let slot = TemplateSlot::from(EmailTemplateType::Welcome);

        assert_eq!(slot.locale, TemplateLocale::Fallback);
    }
}
