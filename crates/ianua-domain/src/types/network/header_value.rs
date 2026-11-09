use crate::shared::validation::{TextValue, Validator, text_value};

/// The longest value a header may carry.
const MAX_HEADER_VALUE_BYTES: usize = 8192;

text_value! {
    redacted
    /// A value the gateway writes into an HTTP header.
    ///
    /// ASCII with no control character, at most 8192 bytes. So a line break
    /// can never end the header and start another one the sender chose.
    ///
    /// A header value is often a credential. It may be an API key a tenant
    /// typed into a transform, a secret from a store, or a bearer token or
    /// signed assertion a stage made. So it never prints. A header entry, a
    /// request or response change, or a stage's decision that holds one
    /// cannot leak it through a debug print or an error. The code that
    /// writes it to the wire reads it with `as_str`.
    pub struct HeaderValue;
}

impl TextValue for HeaderValue {
    const FIELD: &'static str = "header_value";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.ascii_only().header_value(MAX_HEADER_VALUE_BYTES)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `Bearer abc.def` is kept as written. An empty value is allowed too.
    #[test]
    fn an_ordinary_value_is_kept_as_written() {
        assert_eq!(
            HeaderValue::new("Bearer abc.def").unwrap().as_str(),
            "Bearer abc.def"
        );
        assert!(HeaderValue::new("").is_ok());
    }

    /// Line breaks, NUL, non-ASCII text and values over 8192 bytes are refused,
    /// including a value that would introduce another header.
    #[test]
    fn a_value_that_would_start_another_header_is_refused() {
        for value in ["a\r\nSet-Cookie: x=1", "a\nb", "a\0b", "caf\u{e9}"] {
            assert!(HeaderValue::new(value).is_err(), "{value:?} was accepted");
        }
        assert!(HeaderValue::new("a".repeat(MAX_HEADER_VALUE_BYTES + 1)).is_err());
    }
}
