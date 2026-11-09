/// Text recorded because it is not trusted.
///
/// Examples are what someone typed into a sign-in form, a path an attacker
/// requested, or a description built from such input. It is never refused,
/// since refusing it would drop the record of the attempt worth keeping. It
/// is made safe to store and show instead. It is cut to
/// [`MAX_UNTRUSTED_CHARS`] characters, so one request cannot bloat the
/// audit log. Its control characters are replaced, so it cannot forge a log
/// line or drive a terminal.
///
/// It is read back from JSON through the same step, so a stored value is as
/// safe as a recorded one.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(from = "String", into = "String"))]
pub struct UntrustedText(String);

impl From<String> for UntrustedText {
    fn from(value: String) -> Self {
        Self::record(&value)
    }
}

impl From<UntrustedText> for String {
    fn from(text: UntrustedText) -> Self {
        text.0
    }
}

/// The longest an untrusted value is kept, in characters.
pub const MAX_UNTRUSTED_CHARS: usize = 512;

impl UntrustedText {
    /// Records `value`, shortened and with control characters replaced.
    #[must_use]
    pub fn record(value: &str) -> Self {
        Self(made_safe(value))
    }

    /// The recorded text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// `value` cut to [`MAX_UNTRUSTED_CHARS`] characters, with every character
/// that could forge a log line or hide what the text says replaced.
///
/// The result can be stored and shown whatever the input held.
pub(crate) fn made_safe(value: &str) -> String {
    crate::shared::validation::safe_text::made_safe(value, MAX_UNTRUSTED_CHARS)
}

impl std::fmt::Display for UntrustedText {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Someone types `bob@` into the sign-in form. It is recorded exactly as
    /// typed.
    #[test]
    fn ordinary_text_is_kept_as_typed() {
        assert_eq!(UntrustedText::record("bob@").as_str(), "bob@");
    }

    /// Recording text replaces its newline and terminal escape character,
    /// retaining the surrounding text without executable control characters.
    #[test]
    fn control_characters_are_replaced() {
        let text = UntrustedText::record("a\nb\u{1b}[31m");

        assert_eq!(text.as_str(), "a\u{FFFD}b\u{FFFD}[31m");
    }

    /// A 10000-character input is recorded, cut to [`MAX_UNTRUSTED_CHARS`].
    #[test]
    fn long_text_is_cut_to_the_limit() {
        let text = UntrustedText::record(&"x".repeat(10_000));

        assert_eq!(text.as_str().chars().count(), MAX_UNTRUSTED_CHARS);
    }

    mod properties {
        use proptest::prelude::*;

        use super::*;

        proptest! {
            /// Whatever text comes in, the recorded form is at most
            /// [`MAX_UNTRUSTED_CHARS`] long and holds no control character.
            #[test]
            fn whatever_comes_in_is_bounded_and_free_of_control_characters(raw in ".*") {
                let text = UntrustedText::record(&raw);

                prop_assert!(text.as_str().chars().count() <= MAX_UNTRUSTED_CHARS);
                prop_assert!(!text.as_str().chars().any(char::is_control));
            }
        }
    }
}
