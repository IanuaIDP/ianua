//! Secret values that redact their contents when formatted for debugging.

use std::fmt;

/// A resolved secret.
///
/// It has no `Display`, and its `Debug` says only that it exists. A secret
/// that can be formatted ends up in a log line. The only way to the value is
/// [`Secret::expose`].
///
/// It is wiped on drop, so the plaintext does not stay in freed memory for a
/// core dump or a swapped page to carry off. It has no `==`. Comparing
/// secrets byte by byte with early exit leaks how much of a guess was right.
#[derive(Clone, zeroize::ZeroizeOnDrop)]
pub struct Secret(String);

impl Secret {
    /// Wraps a value that is not to be printed.
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// The value, for the one place that has to send it somewhere.
    ///
    /// The name stands out at the call site, so a reviewer sees every place
    /// that reads a secret.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Whether there is nothing here.
    ///
    /// A store that answers with an empty value has almost certainly answered
    /// with the wrong thing. An empty credential sent upstream fails in a way
    /// nobody can read.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(redacted)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A secret holding `sk-live-123` prints as `Secret(redacted)` in
    /// `Debug`, so it cannot reach a log line. `expose` still gives the value.
    #[test]
    fn a_secret_does_not_print_itself() {
        let secret = Secret::new("sk-live-123");

        assert_eq!(format!("{secret:?}"), "Secret(redacted)");
        assert!(!format!("{secret:?}").contains("sk-live"));
        assert_eq!(secret.expose(), "sk-live-123");
    }

    /// An empty secret reports itself empty and `x` does not. The caller can
    /// then refuse an empty answer from a store before sending it upstream.
    #[test]
    fn an_empty_secret_says_so() {
        assert!(Secret::new("").is_empty());
        assert!(!Secret::new("x").is_empty());
    }
}
