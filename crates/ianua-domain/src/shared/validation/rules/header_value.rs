//! Values the gateway writes into an HTTP header.

use crate::shared::validation::validator::Validator;

impl Validator<'_> {
    /// Validates a header value of at most `max_bytes`.
    ///
    /// Rules applied:
    /// - At most `max_bytes`
    /// - No control characters: a line break would end the header and start
    ///   another one the sender chose, and a null byte ends it early
    #[must_use]
    pub fn header_value(self, max_bytes: usize) -> Self {
        self.max_bytes(max_bytes).no_control_chars()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn value(text: &str) -> bool {
        Validator::new("header", text)
            .header_value(32)
            .validate_first()
            .is_ok()
    }

    /// A content type with a charset passes, and so does an empty value.
    /// Neither holds a byte that could break the header line.
    #[test]
    fn an_ordinary_value_is_accepted() {
        assert!(value("text/html; charset=utf-8"));
        assert!(value(""));
    }

    /// Header-value validation rejects CRLF, null bytes, and values exceeding the configured limit.
    #[test]
    fn a_value_that_would_start_another_header_is_refused() {
        assert!(!value("text/html\r\nSet-Cookie: a=b"));
        assert!(!value("text\0html"));
        assert!(!value(&"a".repeat(33)));
    }
}
