//! A whole mail message as a step's body, as Gmail takes it: an RFC 5322
//! message, base64url, in a JSON object's `raw`.
//!
//! Each body input whose service name starts with a capital is a header,
//! such as `To` or `Subject`; the input named `text` is the plain-text
//! body; any other body input sits beside `raw` in the object, such as
//! Gmail's `threadId`. A header holding a line break is refused, so a
//! subject or an address can never add a header of its own. A header
//! holding more than plain ASCII is written as an RFC 2047 word. The body
//! is sent in base64 under UTF-8, so any text arrives as it was given.

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use ianua_domain::domains::workflows::execution::step::ActionOutcome;
use serde_json::{Map, Value};

use crate::answer::failed;

/// The input that is the message's body.
const BODY: &str = "text";

/// How long a line of the body's base64 is.
const LINE: usize = 76;

/// The JSON object for `entries`, each a body input's service name and its
/// value.
///
/// # Errors
///
/// A failed outcome when a header holds a line break, or a value is not
/// text or a list of text.
pub(crate) fn mail(entries: Vec<(&str, Value)>) -> Result<Value, ActionOutcome> {
    let mut headers = vec![
        "MIME-Version: 1.0".to_owned(),
        "Content-Type: text/plain; charset=UTF-8".to_owned(),
        "Content-Transfer-Encoding: base64".to_owned(),
    ];
    let mut text = String::new();
    let mut object = Map::new();
    for (name, value) in entries {
        if name == BODY {
            text = plain(&value)?;
            continue;
        }
        if !name.starts_with(|first: char| first.is_ascii_uppercase()) {
            object.insert(name.to_owned(), value);
            continue;
        }
        headers.push(format!("{name}: {}", header_value(&plain(&value)?)?));
    }
    let message = format!(
        "{}\r\n\r\n{}",
        headers.join("\r\n"),
        wrapped(&STANDARD.encode(text))
    );
    object.insert(
        "raw".to_owned(),
        Value::String(URL_SAFE_NO_PAD.encode(message)),
    );
    Ok(Value::Object(object))
}

/// `value` as one line of text: a list joined as addresses are, with
/// commas.
fn plain(value: &Value) -> Result<String, ActionOutcome> {
    match value {
        Value::String(text) => Ok(text.clone()),
        Value::Array(items) => items
            .iter()
            .map(|item| item.as_str().map(str::to_owned))
            .collect::<Option<Vec<_>>>()
            .map(|items| items.join(", "))
            .ok_or_else(|| failed("a mail's header takes text or a list of text")),
        _ => Err(failed("a mail's header takes text or a list of text")),
    }
}

/// `text` as a header's value: refused when it holds a line break, and an
/// RFC 2047 word when it holds more than plain ASCII.
fn header_value(text: &str) -> Result<String, ActionOutcome> {
    if text.contains(['\r', '\n']) {
        return Err(failed("a mail's header may not hold a line break"));
    }
    if text.chars().all(|c| c.is_ascii() && !c.is_ascii_control()) {
        return Ok(text.to_owned());
    }
    Ok(format!("=?UTF-8?B?{}?=", STANDARD.encode(text)))
}

/// `encoded` broken into lines of [`LINE`] characters.
fn wrapped(encoded: &str) -> String {
    encoded
        .as_bytes()
        .chunks(LINE)
        .map(|line| String::from_utf8_lossy(line).into_owned())
        .collect::<Vec<_>>()
        .join("\r\n")
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn message(body: &Value) -> String {
        let raw = body["raw"].as_str().unwrap();
        String::from_utf8(URL_SAFE_NO_PAD.decode(raw).unwrap()).unwrap()
    }

    /// Ann's mail to two people: its headers, a subject with an umlaut as
    /// an RFC 2047 word, its body in base64, and the thread beside `raw`.
    #[test]
    fn a_mail_is_one_message_in_raw() {
        let body = mail(vec![
            ("To", json!(["bob@acme.test", "cy@acme.test"])),
            ("Subject", json!("Grüße from the build")),
            ("text", json!("It passed.\n")),
            ("threadId", json!("t-1")),
        ])
        .unwrap();

        let message = message(&body);
        assert!(message.contains("To: bob@acme.test, cy@acme.test\r\n"));
        assert!(message.contains(&format!(
            "Subject: =?UTF-8?B?{}?=\r\n",
            STANDARD.encode("Grüße from the build")
        )));
        assert!(message.ends_with(&format!("\r\n\r\n{}", STANDARD.encode("It passed.\n"))));
        assert_eq!(body["threadId"], "t-1");
    }

    /// A subject containing a line break and an injected Bcc header fails
    /// mail construction.
    #[test]
    fn a_header_with_a_line_break_is_refused() {
        let built = mail(vec![
            ("To", json!("bob@acme.test")),
            ("Subject", json!("Hello\r\nBcc: mallory@evil.test")),
        ]);

        assert!(matches!(built, Err(ActionOutcome::Failed(_))));
    }
}
