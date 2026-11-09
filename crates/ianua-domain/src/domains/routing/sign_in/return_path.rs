//! Where to send a person back to once they have signed in.

use crate::message;
use crate::shared::validation::{Rule, TextValue, ValidationError, Validator, text_value};
use crate::shared::web::percent;

text_value! {
    /// A path on the same host to send a person back to after signing in, such
    /// as `/projects?tab=open`.
    ///
    /// It arrives from the address bar, so it is taken to be hostile. Only a
    /// path is accepted, never anything a browser would read as another host.
    /// It must start with a single `/` and may not hold a backslash or control
    /// character. It is checked again after percent-decoding, so
    /// `/%2F%2Fevil.example` is refused like `//evil.example`. Whoever
    /// redirects puts the host in front of it, from configuration.
    ///
    /// Sam sends Ann a sign-in link ending in `?return_to=//evil.example`.
    /// Without this check, Ann signs in and lands on Sam's page.
    pub struct ReturnPath;
}

impl TextValue for ReturnPath {
    const FIELD: &'static str = "return_to";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check
            .not_empty()
            .ascii_only()
            .length(1..=2048)
            .no_control_chars()
            .rule(&StaysOnHost)
    }
}

/// Whether a browser would read `path` as a path on the current host.
fn stays_on_host(path: &str) -> bool {
    path.starts_with('/')
        && !path.starts_with("//")
        && !path.contains('\\')
        && !path.chars().any(char::is_control)
}

/// Accepts only a path on the host it was given on, before and after
/// percent-decoding. It refuses `//host`, a backslash a browser reads as a
/// slash, and a scheme.
struct StaysOnHost;

impl Rule for StaysOnHost {
    fn check(&self, field: &'static str, value: &str) -> Option<ValidationError> {
        let decoded = percent::decode_lenient(value);
        if stays_on_host(value) && stays_on_host(&decoded) {
            return None;
        }
        Some(ValidationError::Custom {
            field,
            code: "invalid_return_path".to_owned(),
            message: message!(
                "routing-a-return-path-must-be-a",
                "a return path must be a path on the same host"
            ),
        })
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    /// `/projects?tab=open` is accepted and kept as written, and so is `/`.
    #[test]
    fn a_plain_path_with_a_query_is_accepted() {
        assert_eq!(
            ReturnPath::new("/projects?tab=open").unwrap().as_str(),
            "/projects?tab=open"
        );
        assert!(ReturnPath::new("/").is_ok());
    }

    /// Return paths reject missing leading slashes, full URLs, schemes and
    /// host-changing forms, including percent-encoded slashes, backslashes
    /// and control characters.
    #[test]
    fn anything_a_browser_reads_as_another_host_is_refused() {
        for value in [
            "",
            "projects",
            "https://evil.example/",
            "//evil.example",
            "/\\evil.example",
            "/%2F%2Fevil.example",
            "/%2f/evil.example",
            "/%5Cevil.example",
            "/\t/evil.example",
            "/%09/evil.example",
            "javascript:alert(1)",
        ] {
            assert!(ReturnPath::new(value).is_err(), "{value:?} must be refused");
        }
    }

    /// A return path of 2049 characters is refused as too long.
    #[test]
    fn an_overlong_path_is_refused() {
        assert!(ReturnPath::new(format!("/{}", "a".repeat(2048))).is_err());
    }

    proptest! {
        /// For any short printable text, an accepted return path starts with
        /// one `/` and holds no backslash. That holds both as written and
        /// after decoding.
        #[test]
        fn an_accepted_path_never_leaves_the_host(value in "\\PC{0,64}") {
            if let Ok(path) = ReturnPath::new(value) {
                let decoded = percent::decode_lenient(path.as_str());
                for form in [path.as_str(), decoded.as_str()] {
                    prop_assert!(form.starts_with('/'));
                    prop_assert!(!form.starts_with("//"));
                    prop_assert!(!form.contains('\\'));
                }
            }
        }

        /// For paths built from `%`, slashes, backslashes, letters and
        /// digits, an accepted one never decodes to something starting `//`.
        #[test]
        fn an_accepted_path_survives_a_leading_escape(rest in "[%/\\\\a-z0-9]{0,24}") {
            if let Ok(path) = ReturnPath::new(format!("/{rest}")) {
                prop_assert!(!percent::decode_lenient(path.as_str()).starts_with("//"));
            }
        }
    }
}
