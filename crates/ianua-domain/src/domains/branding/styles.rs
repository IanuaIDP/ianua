//! Checks on the styles of a tenant's own HTML email that carries the
//! one-time link or a one-time code.
//!
//! A style can read the mail it styles. `a[href*="token=ab"]` matches only
//! when the link holds `token=ab`, and a background fetched from Eve's
//! server then tells her so. A few hundred such rules spell out the whole
//! link to any mail client that applies styles. So such an email may fetch
//! nothing from a style, load no stylesheet from elsewhere, and hold no
//! attribute selector once it has a `<style>` block.
//!
//! The checks read the whole body, not only what one browser would take for
//! a style. Mail clients read HTML in many ways, and a check that follows one
//! reading can be walked around with another.

use crate::domains::branding::placeholders::{tag_names, writes_secret};
use crate::message;
use crate::shared::errors::DomainError;

/// What a style fetches an address or a stylesheet with, and the escape that
/// could spell any of them in other letters.
const FETCHES: &[&str] = &["url(", "image-set(", "src(", "@import", "\\"];

/// Named character references that stand for a character a fetch or a
/// selector is written with. No other name stands for one.
const NAMED: &[(&str, char)] = &[
    ("lpar", '('),
    ("lsqb", '['),
    ("lbrack", '['),
    ("bsol", '\\'),
    ("commat", '@'),
];

/// Refuses, in an HTML body that writes the one-time link or a one-time
/// code, anything a style could fetch with, a stylesheet linked from
/// elsewhere, and an attribute selector once the body has a `<style>` block.
pub(super) fn ensure_styles_cannot_read_link(html: &str) -> Result<(), DomainError> {
    if !writes_secret(html) {
        return Ok(());
    }
    let read = decoded(html).to_ascii_lowercase();
    ensure_no_fetch(&read)?;
    ensure_no_linked_stylesheet(html)?;
    ensure_no_attribute_selector(html, &read)
}

/// Refuses `read`, the lower-cased body with its references replaced, when
/// it holds anything in [`FETCHES`].
fn ensure_no_fetch(read: &str) -> Result<(), DomainError> {
    let Some(fetch) = FETCHES.iter().find(|fetch| read.contains(**fetch)) else {
        return Ok(());
    };
    Err(DomainError::invalid(message!(
        "branding-an-email-that-carries-or-may-2",
        format!(
            "an email that carries {{{{ action_link }}}} or {{{{ one_time_code }}}} may not hold `{fetch}`, which lets a style fetch an address"
        )
    )))
}

/// Refuses a `<link>` tag, which can load a stylesheet from anywhere.
fn ensure_no_linked_stylesheet(html: &str) -> Result<(), DomainError> {
    if !tag_names(html).any(|name| name.eq_ignore_ascii_case("link")) {
        return Ok(());
    }
    Err(DomainError::invalid(message!(
        "branding-an-email-that-carries-or-may",
        "an email that carries {{ action_link }} or {{ one_time_code }} may not hold a <link> tag"
    )))
}

/// Refuses a square bracket anywhere in `read` when `html` has a `<style>`
/// block, where it writes an attribute selector that can match parts of the
/// link.
fn ensure_no_attribute_selector(html: &str, read: &str) -> Result<(), DomainError> {
    let styled = tag_names(html).any(|name| name.eq_ignore_ascii_case("style"));
    if !styled || !without_conditionals(read).contains('[') {
        return Ok(());
    }
    Err(DomainError::invalid(message!(
        "branding-an-email-that-carries-or-and",
        "an email that carries {{ action_link }} or {{ one_time_code }} and has a <style> block may not hold square brackets, which write a selector that reads the link"
    )))
}

/// `read` without the bracketed tests of Outlook's conditional comments,
/// such as `<!--[if mso]>` and `<![endif]-->`, which nearly every mail
/// layout holds and which select nothing. A test is cut up to its first
/// `]`; one never closed loses only its opening.
fn without_conditionals(read: &str) -> String {
    let mut out = String::with_capacity(read.len());
    let mut rest = read;
    while let Some((before, after)) = rest.split_once("[if ") {
        out.push_str(before);
        rest = after.split_once(']').map_or(after, |(_, tail)| tail);
    }
    out.push_str(rest);
    out.replace("[endif]", "")
}

/// `text` with each character reference replaced by the character it stands
/// for, so a reference cannot spell a fetch or a selector in other letters.
/// A reference this does not know is kept as written.
fn decoded(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some((before, after)) = rest.split_once('&') {
        out.push_str(before);
        let (character, next) = reference(after);
        out.push(character);
        rest = next;
    }
    out.push_str(rest);
    out
}

/// The character the reference at the start of `after_amp`, the text after
/// a `&`, stands for, and the text after the reference. A `&` that starts no
/// known reference stands for itself.
fn reference(after_amp: &str) -> (char, &str) {
    let known = match after_amp.strip_prefix('#') {
        Some(number) => numeric(number),
        None => named(after_amp),
    };
    known.unwrap_or(('&', after_amp))
}

/// The character a numeric reference stands for, read from `after_hash`,
/// the text after `&#`, and the text after it. A number past the last
/// character stands for the replacement character, as browsers read it.
fn numeric(after_hash: &str) -> Option<(char, &str)> {
    let (radix, digits) = match after_hash.strip_prefix(['x', 'X']) {
        Some(hex) => (16, hex),
        None => (10, after_hash),
    };
    let (number, rest) = split_where(digits, |c| !c.is_digit(radix));
    if number.is_empty() {
        return None;
    }
    let character = u32::from_str_radix(number, radix)
        .ok()
        .and_then(char::from_u32)
        .unwrap_or(char::REPLACEMENT_CHARACTER);
    Some((character, rest.strip_prefix(';').unwrap_or(rest)))
}

/// The character a reference in [`NAMED`] stands for, read from `after_amp`,
/// and the text after it.
fn named(after_amp: &str) -> Option<(char, &str)> {
    let (name, rest) = split_where(after_amp, |c| !c.is_ascii_alphanumeric());
    let (_, character) = NAMED.iter().find(|(known, _)| *known == name)?;
    Some((*character, rest.strip_prefix(';').unwrap_or(rest)))
}

/// `text` split before its first character that `stop` accepts, or whole
/// when there is none.
fn split_where(text: &str, stop: impl Fn(char) -> bool) -> (&str, &str) {
    let at = text.find(stop).unwrap_or(text.len());
    text.split_at_checked(at).unwrap_or((text, ""))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An email carrying a reset link rejects a style rule that selects
    /// an attribute by part of its token, even without a remote fetch.
    #[test]
    fn an_attribute_selector_in_a_style_block_is_refused() {
        let html = "<style>a[href*=\"token=ab\"]{background:red}</style><p>{{ action_link }}</p>";

        assert!(ensure_styles_cannot_read_link(html).is_err());
    }

    /// Mail carrying a one-time code rejects style fetches in blocks and
    /// attributes, including case changes, character references and CSS escapes.
    #[test]
    fn a_fetch_from_a_style_is_refused_however_it_is_spelled() {
        for html in [
            "<style>p{background:url(https://eve.test/a)}</style>",
            "<p style=\"background:URL(https://eve.test/a)\">Hi</p>",
            "<p style=\"background:u&#114;l(https://eve.test/a)\">Hi</p>",
            "<p style=\"background:url&lpar;https://eve.test/a)\">Hi</p>",
            "<p style=\"background:u\\72 l(https://eve.test/a)\">Hi</p>",
            "<style>@import 'https://eve.test/x.css';</style>",
            "<p style=\"background:image-set('https://eve.test/a' 1x)\">Hi</p>",
        ] {
            let html = format!("{html}<p>Your code: {{{{ one_time_code }}}}</p>");

            assert!(ensure_styles_cannot_read_link(&html).is_err(), "{html}");
        }
    }

    /// An email carrying an action link rejects an external stylesheet,
    /// including an uppercase link tag.
    #[test]
    fn a_linked_stylesheet_is_refused() {
        let html =
            "<LINK rel=\"stylesheet\" href=\"https://eve.test/x.css\"><p>{{ action_link }}</p>";

        assert!(ensure_styles_cannot_read_link(html).is_err());
    }

    /// An SVG style cannot hide an attribute selector behind an encoded
    /// bracket in an email carrying an action link.
    #[test]
    fn a_bracket_written_as_a_reference_is_refused() {
        let html = "<svg><style>a&#91;href^=x]{fill:red}</style></svg><p>{{ action_link }}</p>";

        assert!(ensure_styles_cannot_read_link(html).is_err());
    }

    /// A reset email with plain styles, colours and a block of rules without
    /// selectors on attributes, keeps its look.
    #[test]
    fn plain_styles_are_kept_in_an_email_with_the_link() {
        let html = "<style>p{color:#333;font-family:&quot;Inter&quot;,sans-serif}</style><p style=\"margin:0\">Reset: {{ action_link }} &amp; more</p>";

        assert!(ensure_styles_cannot_read_link(html).is_ok());
    }

    /// A reset email laid out for Outlook, its styles inside conditional
    /// comments, keeps them: the comments' tests select nothing. A selector
    /// on an attribute inside them is still refused.
    #[test]
    fn outlooks_conditional_comments_are_not_selectors() {
        let layout = "<!--[if mso]><style>p{margin:0}</style><![endif]--><p>{{ action_link }}</p>";
        let probing =
            "<!--[if mso]><style>a[href^=x]{color:red}</style><![endif]--><p>{{ action_link }}</p>";

        assert!(ensure_styles_cannot_read_link(layout).is_ok());
        assert!(ensure_styles_cannot_read_link(probing).is_err());
    }

    /// A welcome email with no link or code may use background images and
    /// selectors on attributes: there is nothing in it for them to read.
    #[test]
    fn styles_are_free_in_an_email_without_the_link_or_code() {
        let html = "<style>a[href]{background:url(https://acme.test/bg.png)}</style><p>Hi {{ user_name }}</p>";

        assert!(ensure_styles_cannot_read_link(html).is_ok());
    }
}
