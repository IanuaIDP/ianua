use crate::shared::validation::{TextValue, Validator, text_value};

/// The longest `User-Agent` accepted, in characters.
const MAX_USER_AGENT_LENGTH: usize = 512;

text_value! {
    /// An HTTP `User-Agent` string.
    ///
    /// The client sets it, so it is untrusted. A client may send control
    /// characters, null bytes or megabytes of junk. This type refuses them.
    ///
    /// Rules:
    /// - Not empty.
    /// - ASCII only, as HTTP requires.
    /// - At most 512 characters.
    /// - No control characters, such as null bytes, escape sequences or
    ///   tabs.
    pub struct UserAgent;
}

impl TextValue for UserAgent {
    const FIELD: &'static str = "user_agent";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check
            .not_empty()
            .ascii_only()
            .length(1..=MAX_USER_AGENT_LENGTH)
            .no_control_chars()
    }
}

impl UserAgent {
    /// The value recorded when a client sent no `User-Agent` at all.
    ///
    /// Clients other than browsers often send no header, and that is no
    /// reason to refuse the request. Recording `unknown` says so, instead of
    /// making up a browser that never named itself.
    #[must_use]
    pub fn unknown() -> Self {
        Self("unknown".to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A Safari-style `Mozilla/5.0 (Macintosh; ...)` string is accepted as
    /// sent.
    #[test]
    fn accepts_typical_browser() {
        let ua = UserAgent::new("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)").unwrap();
        assert!(ua.as_str().starts_with("Mozilla"));
    }

    /// A command-line client's `curl/7.88.1` is accepted.
    #[test]
    fn curl_client_identification_is_accepted() {
        assert!(UserAgent::new("curl/7.88.1").is_ok());
    }

    /// A crawler's `Googlebot/2.1 (+http://...)` string is accepted.
    #[test]
    fn crawler_identification_is_accepted() {
        assert!(UserAgent::new("Googlebot/2.1 (+http://www.google.com/bot.html)").is_ok());
    }

    /// An empty `User-Agent` is refused. [`UserAgent::unknown`] stands in
    /// when a client sends none.
    #[test]
    fn empty_client_identification_is_refused() {
        assert!(UserAgent::new("").is_err());
    }

    /// A client sends `Mozilla\0/5.0` with a NUL byte inside. It is refused.
    #[test]
    fn rejects_null_byte() {
        assert!(UserAgent::new("Mozilla\x00/5.0").is_err());
    }

    /// A `User-Agent` with a tab inside it is refused.
    #[test]
    fn tabs_in_client_identification_are_refused() {
        assert!(UserAgent::new("Mozilla\t/5.0").is_err());
    }

    /// A line break in client identification is refused before it can split
    /// an access-log entry into multiple lines.
    #[test]
    fn newlines_in_client_identification_are_refused() {
        assert!(UserAgent::new("Mozilla\n/5.0").is_err());
    }

    /// `Mozillä/5.0` holds a non-ASCII letter, which HTTP does not allow. It
    /// is refused.
    #[test]
    fn rejects_non_ascii() {
        assert!(UserAgent::new("Mozillä/5.0").is_err());
    }

    /// A 513-character `User-Agent` is refused, so a client cannot send
    /// megabytes of junk.
    #[test]
    fn rejects_over_max_length() {
        assert!(UserAgent::new("a".repeat(513)).is_err());
    }

    /// A `User-Agent` of exactly 512 characters is still accepted.
    #[test]
    fn accepts_at_max_length() {
        assert!(UserAgent::new("a".repeat(512)).is_ok());
    }

    /// `curl/7.0` prints as `curl/7.0`.
    #[test]
    fn display_returns_value() {
        let ua = UserAgent::new("curl/7.0").unwrap();
        assert_eq!(ua.to_string(), "curl/7.0");
    }
}
