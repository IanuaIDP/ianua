//! Nothing secret in what came back: tokens, cookies, keys and passwords
//! never appear in answers, records or logs.

/// Fails when any of `secrets` appears in `haystack`. The failure names
/// which secret by its place in the list and its length, never its value.
///
/// # Panics
///
/// When a secret appears, or one of `secrets` is empty, which would match
/// anything and prove nothing.
pub fn no_secret_leaked(haystack: &str, secrets: &[&str]) {
    for (place, secret) in secrets.iter().enumerate() {
        assert!(
            !secret.is_empty(),
            "secret #{place} is empty, so finding it would prove nothing"
        );
        assert!(
            !haystack.contains(secret),
            "secret #{place} ({} characters) appears in what came back",
            secret.chars().count()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A text holding none of the secrets passes.
    #[test]
    fn a_text_holding_no_secret_passes() {
        no_secret_leaked(
            r#"{"status":"authenticated"}"#,
            &["rt-live", "Scenario harbour"],
        );
    }

    /// A text holding one fails, without repeating it.
    #[test]
    #[should_panic(expected = "secret #1 (7 characters) appears")]
    fn a_text_holding_a_secret_fails_without_repeating_it() {
        no_secret_leaked(r#"{"refresh_token":"rt-live"}"#, &["unused", "rt-live"]);
    }
}
