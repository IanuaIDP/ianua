//! Credentials taken out of what a failed scenario prints: headers that
//! carry them, JSON fields named for them, and query parameters named for
//! them.

use std::sync::{OnceLock, PoisonError, RwLock};

use serde_json::Value;

/// What stands in for a credential.
const REDACTED: &str = "[redacted]";

/// Headers that carry credentials, in lowercase.
const SECRET_HEADERS: [&str; 6] = [
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "dpop",
    "x-api-key",
];

/// Words that mark a field or parameter as a credential, in lowercase.
const SECRET_WORDS: [&str; 17] = [
    "password",
    "token",
    "secret",
    "cookie",
    "authorization",
    "code",
    "proof",
    "key",
    "fingerprint",
    "link",
    "otpauth",
    "assertion",
    "signature",
    "binding",
    "saml_response",
    "state",
    "redirect_url",
];

/// Whether a field, parameter or header called `name` holds a credential.
fn is_secret(name: &str) -> bool {
    let lowered = name.to_ascii_lowercase();
    SECRET_HEADERS.contains(&lowered.as_str())
        || SECRET_WORDS.iter().any(|word| lowered.contains(word))
}

/// The values taken out wherever they appear, whatever carries them: the
/// secrets a run reads from its environment, such as a model provider's
/// key, registered once and read by every printing.
fn secret_values() -> &'static RwLock<Vec<String>> {
    static VALUES: OnceLock<RwLock<Vec<String>>> = OnceLock::new();
    VALUES.get_or_init(|| RwLock::new(Vec::new()))
}

/// Takes `value` out of everything printed from now on, wherever it
/// appears. An empty value is not taken, since it would match anything.
pub(crate) fn secret_value(value: &str) {
    if value.is_empty() {
        return;
    }
    let mut values = secret_values()
        .write()
        .unwrap_or_else(PoisonError::into_inner);
    if !values.iter().any(|kept| kept == value) {
        values.push(value.to_owned());
    }
}

/// `text` with every registered secret value taken out.
fn scrubbed(text: String) -> String {
    let values = secret_values()
        .read()
        .unwrap_or_else(PoisonError::into_inner);
    values
        .iter()
        .fold(text, |text, value| text.replace(value.as_str(), REDACTED))
}

/// A header's value as printed.
pub(crate) fn header(name: &str, value: &str) -> String {
    if is_secret(name) {
        return REDACTED.to_owned();
    }
    scrubbed(value.to_owned())
}

/// `path`, a URL or a path, with the values of credential parameters in
/// its query taken out.
pub(crate) fn path(path: &str) -> String {
    let Some((before, query)) = path.split_once('?') else {
        return scrubbed(path.to_owned());
    };
    let pairs: Vec<String> = query
        .split('&')
        .map(|pair| match pair.split_once('=') {
            Some((name, _)) if is_secret(name) => format!("{name}={REDACTED}"),
            _ => pair.to_owned(),
        })
        .collect();
    scrubbed(format!("{before}?{}", pairs.join("&")))
}

/// `value` as JSON text, every field named for a credential taken out, at
/// any depth.
pub(crate) fn json(value: &Value) -> String {
    scrubbed(redacted(value).to_string())
}

/// A body as printed: as JSON redacted when it is JSON, as it is
/// otherwise.
pub(crate) fn body(bytes: &[u8]) -> String {
    match serde_json::from_slice::<Value>(bytes) {
        Ok(value) => json(&value),
        Err(_) => scrubbed(String::from_utf8_lossy(bytes).into_owned()),
    }
}

/// `value` with every field named for a credential replaced.
fn redacted(value: &Value) -> Value {
    match value {
        Value::Object(fields) => Value::Object(
            fields
                .iter()
                .map(|(name, field)| (name.clone(), redacted_field(name, field)))
                .collect(),
        ),
        Value::Array(items) => Value::Array(items.iter().map(redacted).collect()),
        other => other.clone(),
    }
}

/// The field `name` holding `field`, replaced when it is a credential.
fn redacted_field(name: &str, field: &Value) -> Value {
    if is_secret(name) && !field.is_null() {
        return Value::String(REDACTED.to_owned());
    }
    redacted(field)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A refresh token and a nested password are removed from printed JSON,
    /// while Ann's name remains readable.
    #[test]
    fn credential_fields_are_taken_out_at_any_depth() {
        let body = serde_json::json!({
            "status": "authenticated",
            "refresh_token": "rt-live",
            "nested": [{ "admin_password": "Scenario harbour 1234", "name": "Ann" }],
        });

        let printed = json(&body);

        assert!(!printed.contains("rt-live"));
        assert!(!printed.contains("harbour"));
        assert!(printed.contains("Ann"));
    }

    /// The token in a link's query is taken out, the rest kept.
    #[test]
    fn the_token_in_a_query_is_taken_out() {
        assert_eq!(
            path("/signup/confirm?org=acme&token=t0k"),
            "/signup/confirm?org=acme&token=[redacted]"
        );
    }

    /// Printed JSON hides both the authenticator setup secret and the
    /// mailed sign-in link.
    #[test]
    fn otpauth_links_and_mailed_links_are_taken_out() {
        let body = serde_json::json!({
            "otpauth_uri": "otpauth://totp/x?secret=ANNSPHONESEED",
            "link": "mailed-link-value",
        });

        let printed = json(&body);

        assert!(!printed.contains("ANNSPHONESEED"));
        assert!(!printed.contains("mailed-link-value"));
    }

    /// The bearer token is never printed.
    #[test]
    fn the_authorization_header_is_taken_out() {
        assert_eq!(header("Authorization", "Bearer rt-live"), REDACTED);
        assert_eq!(header("Accept", "application/json"), "application/json");
    }

    /// A registered secret is removed from an ordinary JSON field and a URL
    /// path, even when neither name identifies a credential.
    #[test]
    fn a_registered_value_is_taken_out_wherever_it_appears() {
        secret_value("scenario-registered-value-7");

        let printed = json(&serde_json::json!({"note": "sent scenario-registered-value-7 along"}));

        assert!(!printed.contains("scenario-registered-value-7"));
        assert!(path("/x/scenario-registered-value-7").ends_with(REDACTED));
    }
}
