//! Filling a mail with its values, field by field: the subject, the HTML
//! body and the text body, each from the tenant's own part when it wrote
//! one, else from the platform's.
//!
//! Values are inert data. The engine never reads a value as template code,
//! so `{{ 7 * 7 }}` in a name is sent as written, and every value in an
//! HTML body is escaped, so markup in a name is shown, not run. Undefined
//! values fail the render rather than leaving a gap.
//!
//! A tenant's own parts are rendered in an engine with nothing in it: no
//! filter, no function, no other template and no loader, so nothing a
//! tenant writes can reach a file, the environment or the network. The
//! domain already holds them to bare placeholders; this is the second
//! wall. They never see the bare link address either, only the finished
//! link the platform writes for them.

mod platform;
mod previews;
mod samples;

use std::collections::HashMap;

use ianua_domain::domains::branding::email_template::{
    EmailHtmlBody, EmailTemplate, EmailTemplateType, EmailTextBody, MAX_SUBJECT_LENGTH,
    TemplateVariable,
};
use ianua_domain::domains::branding::renderer::RenderedEmail;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{HttpsUrl, Label, Preference};
use minijinja::value::Value;
use minijinja::{AutoEscape, Environment, HtmlEscape, UndefinedBehavior};
pub use previews::JinjaTemplateRenderer;
pub(crate) use samples::sample_values;

use crate::language::Language;

/// The most bytes one rendered part may hold. A template is bounded by
/// the domain and the values by their sources; this bounds what the two
/// make together.
const MOST_PART_BYTES: usize = 524_288;

/// What the platform's own mail shows of the deployment.
#[derive(Debug, Clone)]
pub struct PlatformLook {
    /// Where the logo at the top of the platform's mail is served. Mail
    /// clients drop inline images, so it is a hosted address.
    pub logo_url: HttpsUrl,
}

/// One part of a mail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Part {
    /// The subject line.
    Subject,
    /// The HTML body.
    Html,
    /// The plain-text body.
    Text,
}

impl Part {
    /// The name the platform's template of `key` for this part is kept
    /// under.
    fn platform_name(self, key: &str) -> String {
        [key, self.suffix()].concat()
    }

    /// The name a tenant's own part is rendered under, which decides its
    /// escaping.
    fn custom_name(self) -> &'static str {
        match self {
            Self::Subject => "custom.subject",
            Self::Html => "custom.html",
            Self::Text => "custom.txt",
        }
    }

    /// The end of the names this part's templates are kept under.
    fn suffix(self) -> &'static str {
        match self {
            Self::Subject => ".subject",
            Self::Html => ".html",
            Self::Text => ".txt",
        }
    }
}

/// How a value reads where it is put.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Markup {
    /// In an HTML body.
    Html,
    /// In a subject or a text body.
    Text,
}

/// Whether a template of `name` escapes what it prints: an HTML one does.
fn escape_for(name: &str) -> AutoEscape {
    if name.ends_with(".html") {
        return AutoEscape::Html;
    }
    AutoEscape::None
}

/// One mail to compose: which one, the tenant's template or the
/// platform's, and its values.
pub(crate) struct Composition<'a> {
    /// Which mail it is.
    pub(crate) template_type: EmailTemplateType,
    /// The tenant's template, or the platform's mail.
    pub(crate) custom: Preference<&'a EmailTemplate>,
    /// The language the platform's parts are rendered in. A tenant's own
    /// parts are already the ones written for the recipient's locale.
    pub(crate) language: Language,
    /// The values it is filled with.
    pub(crate) values: &'a HashMap<TemplateVariable, String>,
}

/// Renders mail from the platform's templates and the parts tenants wrote.
#[derive(Debug)]
pub struct MailComposer {
    platform: HashMap<Language, Environment<'static>>,
    custom: Environment<'static>,
    logo_url: String,
}

impl MailComposer {
    /// A composer with every platform template loaded and checked, its
    /// mail showing `look`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a platform template does
    /// not parse, which a test of every one rules out.
    pub fn new(look: &PlatformLook) -> Result<Self, DomainError> {
        let platform = Language::ALL
            .into_iter()
            .map(|language| Ok((language, platform::environment(language)?)))
            .collect::<Result<_, DomainError>>()?;
        Ok(Self {
            platform,
            custom: custom_environment(),
            logo_url: look.logo_url.as_str().to_owned(),
        })
    }

    /// `mail`, rendered.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a part uses a value the
    /// mail was not given, or renders longer than allowed.
    pub(crate) fn compose(&self, mail: &Composition<'_>) -> Result<RenderedEmail, DomainError> {
        let custom = mail.custom.value().copied();
        let subject = self.part(
            Part::Subject,
            mail,
            custom.and_then(|template| template.subject().value().map(Label::as_str)),
        )?;
        let html = self.part(
            Part::Html,
            mail,
            custom.and_then(|template| template.body_html().value().map(EmailHtmlBody::as_str)),
        )?;
        let text = self.part(
            Part::Text,
            mail,
            custom.and_then(|template| template.body_text().value().map(EmailTextBody::as_str)),
        )?;
        Ok(RenderedEmail::multipart(one_line(&subject), html, text))
    }

    /// `part` of `mail`: from `written`, the tenant's own, when there is
    /// one, else from the platform's template in the mail's language.
    fn part(
        &self,
        part: Part,
        mail: &Composition<'_>,
        written: Option<&str>,
    ) -> Result<String, DomainError> {
        let rendered = match written {
            Some(source) => self.custom.render_named_str(
                part.custom_name(),
                source,
                custom_context(mail.values, markup_of(part)),
            ),
            None => self
                .platform_in(mail.language)?
                .get_template(&part.platform_name(platform::key_of(mail.template_type)))
                .and_then(|template| template.render(self.platform_context(mail.values))),
        };
        within_bounds(rendered.map_err(DomainError::infra)?)
    }

    /// The engine of the platform's mail in `language`.
    fn platform_in(&self, language: Language) -> Result<&Environment<'static>, DomainError> {
        self.platform.get(&language).ok_or_else(|| {
            DomainError::infra_msg("the platform's mail is not loaded in this language")
        })
    }

    /// The values the platform's templates see: every one the mail was
    /// given, the logo and the year.
    fn platform_context(&self, values: &HashMap<TemplateVariable, String>) -> Value {
        values
            .iter()
            .filter(|(variable, _)| **variable != TemplateVariable::Year)
            .map(|(variable, value)| (variable.key(), Value::from(value.as_str())))
            .chain([
                ("logo_url", Value::from(self.logo_url.as_str())),
                (
                    TemplateVariable::Year.key(),
                    Value::from(clock::now().year()),
                ),
            ])
            .collect()
    }
}

/// How a value reads in `part`.
fn markup_of(part: Part) -> Markup {
    match part {
        Part::Html => Markup::Html,
        Part::Subject | Part::Text => Markup::Text,
    }
}

/// The values a tenant's own part sees, read as `markup`: every one but
/// the bare link address, and the finished link the platform writes in its
/// place.
fn custom_context(values: &HashMap<TemplateVariable, String>, markup: Markup) -> Value {
    let link = values.get(&TemplateVariable::ActionUrl).map(|url| {
        (
            TemplateVariable::ActionLink.key(),
            finished_link(url, markup),
        )
    });
    values
        .iter()
        .filter(|(variable, _)| shown_to_tenants(**variable))
        .map(|(variable, value)| (variable.key(), Value::from(value.as_str())))
        .chain(link)
        .collect()
}

/// Whether a tenant's own part may see `variable`. The bare link address
/// is held back, so it can only ever stand as the finished link.
fn shown_to_tenants(variable: TemplateVariable) -> bool {
    !matches!(
        variable,
        TemplateVariable::ActionUrl | TemplateVariable::ActionLink | TemplateVariable::Year
    )
}

/// The link to `url` as the platform writes it: a whole anchor in HTML,
/// the address itself in text.
fn finished_link(url: &str, markup: Markup) -> Value {
    match markup {
        Markup::Html => {
            let escaped = HtmlEscape(url).to_string();
            Value::from_safe_string(format!("<a href=\"{escaped}\">{escaped}</a>"))
        }
        Markup::Text => Value::from(url),
    }
}

/// The engine a tenant's own parts are rendered in: no filter, function,
/// global, other template or loader, undefined values refused.
fn custom_environment() -> Environment<'static> {
    let mut engine = Environment::empty();
    engine.set_undefined_behavior(UndefinedBehavior::Strict);
    engine.set_auto_escape_callback(escape_for);
    engine
}

/// `rendered`, refused when it is longer than [`MOST_PART_BYTES`].
fn within_bounds(rendered: String) -> Result<String, DomainError> {
    if rendered.len() > MOST_PART_BYTES {
        return Err(DomainError::infra_msg(
            "a rendered mail part is longer than allowed",
        ));
    }
    Ok(rendered)
}

/// `subject` as one header line: control characters and runs of spaces
/// made one space, at most as long as a subject may be.
fn one_line(subject: &str) -> String {
    subject
        .split(|c: char| c.is_control() || c.is_whitespace())
        .filter(|word| !word.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(MAX_SUBJECT_LENGTH)
        .collect()
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{BrandingAction, SystemPermission};
    use ianua_domain::domains::branding::control::BrandingControl;
    use ianua_domain::test_support::authority::anyone_holding;

    use super::*;
    use crate::mail::audience::AudienceNames;

    fn composer() -> MailComposer {
        MailComposer::new(&PlatformLook {
            logo_url: HttpsUrl::new("https://ianua.test/logo.png").unwrap(),
        })
        .unwrap()
    }

    fn values(pairs: &[(TemplateVariable, &str)]) -> HashMap<TemplateVariable, String> {
        pairs
            .iter()
            .map(|(variable, value)| (*variable, (*value).to_owned()))
            .collect()
    }

    fn reset_values() -> HashMap<TemplateVariable, String> {
        values(&[
            (TemplateVariable::UserName, "Ann"),
            (TemplateVariable::TenantName, "Acme"),
            (
                TemplateVariable::ActionUrl,
                "https://acme.test/reset?token=t0k&next=/home",
            ),
            (TemplateVariable::ExpiresAt, "30 minutes"),
        ])
    }

    fn compose(
        template_type: EmailTemplateType,
        custom: Option<&EmailTemplate>,
        values: &HashMap<TemplateVariable, String>,
    ) -> Result<RenderedEmail, DomainError> {
        composer().compose(&Composition {
            template_type,
            custom: custom.map_or(Preference::Inherited, Preference::Own),
            language: Language::English,
            values,
        })
    }

    fn acme_reset(subject: &str, html: &str, text: &str) -> EmailTemplate {
        EmailTemplate::custom(
            EmailTemplateType::PasswordReset,
            Preference::Own(Label::new("subject", subject).unwrap()),
            Preference::Own(EmailHtmlBody::new(html).unwrap()),
            Preference::Own(EmailTextBody::new(text).unwrap()),
            &BrandingControl::new(anyone_holding(&[SystemPermission::Branding(
                BrandingAction::Update,
            )])),
        )
        .unwrap()
    }

    /// Ann's reset mail is the platform's: her name, Acme's name, the link
    /// and its expiry in both bodies, the link's `&` written as HTML wants
    /// it in the HTML body and as it is in the text body.
    #[test]
    fn the_platforms_mail_carries_every_value() {
        let rendered = compose(EmailTemplateType::PasswordReset, None, &reset_values()).unwrap();

        let html = rendered.html().unwrap();
        assert_eq!(rendered.subject(), "Reset your password");
        assert!(html.contains("Ann") && html.contains("Acme") && html.contains("30 minutes"));
        assert!(html.contains("token=t0k&amp;next="));
        assert!(
            rendered
                .text()
                .contains("https://acme.test/reset?token=t0k&next=/home")
        );
    }

    /// A name's script markup is escaped in the rendered mail, and its template
    /// expression stays unevaluated.
    #[test]
    fn a_value_is_inert_data() {
        let mut given = reset_values();
        given.insert(
            TemplateVariable::UserName,
            "<script>x</script> {{ 7 * 7 }}".to_owned(),
        );

        let rendered = compose(EmailTemplateType::PasswordReset, None, &given).unwrap();

        let html = rendered.html().unwrap();
        assert!(!html.contains("<script>"));
        assert!(html.contains("&lt;script&gt;"));
        assert!(html.contains("{{ 7 * 7 }}") && !html.contains("49"));
    }

    /// A password-reset template given only the person's name fails to render
    /// because required values are absent.
    #[test]
    fn a_missing_value_fails_the_render() {
        let given = values(&[(TemplateVariable::UserName, "Ann")]);

        let rendered = compose(EmailTemplateType::PasswordReset, None, &given);

        assert!(matches!(rendered, Err(DomainError::Infrastructure(_))));
    }

    /// Acme wrote its own reset mail. Its subject and bodies are sent, the
    /// link standing as the finished anchor in HTML and as the address in
    /// text.
    #[test]
    fn a_tenants_own_parts_are_sent_with_the_finished_link() {
        let template = acme_reset(
            "Acme: reset for {{ user_name }}",
            "<p>Hi {{ user_name }}</p><p>{{ action_link }}</p>",
            "Hi {{ user_name }}, reset: {{ action_link }}",
        );

        let rendered = compose(
            EmailTemplateType::PasswordReset,
            Some(&template),
            &reset_values(),
        )
        .unwrap();

        assert_eq!(rendered.subject(), "Acme: reset for Ann");
        assert!(rendered.html().unwrap().contains(
            "<a href=\"https:&#x2f;&#x2f;acme.test&#x2f;reset?token=t0k&amp;next=&#x2f;home\">"
        ));
        assert!(
            rendered
                .text()
                .ends_with("reset: https://acme.test/reset?token=t0k&next=/home")
        );
    }

    /// A tenant template cannot render the bare action URL from its context.
    #[test]
    fn a_tenants_part_never_sees_the_bare_link() {
        let given = reset_values();

        let rendered = composer().custom.render_named_str(
            "custom.html",
            "{{ action_url }}",
            custom_context(&given, Markup::Html),
        );

        assert!(rendered.is_err());
    }

    /// Tenant templates fail when they call a filter or function or include
    /// another template.
    #[test]
    fn a_tenants_part_reaches_nothing_but_its_values() {
        let given = reset_values();
        let engine = composer();

        for source in [
            "{{ user_name | upper }}",
            "{{ range(3) }}",
            "{% include 'layout/page.html' %}",
        ] {
            let rendered = engine.custom.render_named_str(
                "custom.html",
                source,
                custom_context(&given, Markup::Html),
            );
            assert!(rendered.is_err(), "{source}");
        }
    }

    /// A subject containing a carriage return and newline becomes one line.
    #[test]
    fn a_subject_is_one_line() {
        assert_eq!(
            one_line("Reset\r\nBcc: eve@evil.test"),
            "Reset Bcc: eve@evil.test"
        );
    }

    /// Every type of mail the platform sends renders from its own template
    /// with the sample values, so none waits to fail on a real send.
    #[test]
    fn every_platform_template_renders_with_samples() {
        let engine = composer();
        let names = AudienceNames::default();

        for (template_type, language) in platform::EVERY_TYPE
            .into_iter()
            .flat_map(|template_type| Language::ALL.map(|language| (template_type, language)))
        {
            let given = sample_values(template_type, &names);
            let rendered = engine.compose(&Composition {
                template_type,
                custom: Preference::Inherited,
                language,
                values: &given,
            });
            assert!(
                rendered.is_ok(),
                "{} in {}: {:?}",
                template_type.name(),
                language.tag(),
                rendered.err()
            );
        }
    }

    /// Ann reads German. Acme wrote no reset mail of its own, so she gets
    /// the platform's in German, with her name, the link and its expiry.
    #[test]
    fn the_platforms_mail_is_written_in_the_recipients_language() {
        let rendered = composer()
            .compose(&Composition {
                template_type: EmailTemplateType::PasswordReset,
                custom: Preference::Inherited,
                language: Language::German,
                values: &reset_values(),
            })
            .unwrap();

        let html = rendered.html().unwrap();
        assert_eq!(rendered.subject(), "Setzen Sie Ihr Passwort zurück");
        assert!(html.contains("lang=\"de\""));
        assert!(html.contains("Ann") && html.contains("30 minutes"));
        assert!(
            rendered
                .text()
                .contains("https://acme.test/reset?token=t0k&next=/home")
        );
    }

    /// Selecting Japanese leaves the tenant's custom subject unchanged.
    #[test]
    fn a_tenants_own_parts_are_not_replaced_by_a_translation() {
        let template = acme_reset(
            "Acme reset",
            "<p>{{ action_link }}</p>",
            "{{ action_link }}",
        );

        let rendered = composer()
            .compose(&Composition {
                template_type: EmailTemplateType::PasswordReset,
                custom: Preference::Own(&template),
                language: Language::Japanese,
                values: &reset_values(),
            })
            .unwrap();

        assert_eq!(rendered.subject(), "Acme reset");
    }
}
