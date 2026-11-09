//! PEM-encoded certificates and keys.

use crate::message;
use crate::shared::validation::error::ValidationError;
use crate::shared::validation::validator::Validator;

impl Validator<'_> {
    /// Checks PEM text that holds at least one block labelled `label`, such
    /// as `CERTIFICATE`.
    ///
    /// The rules:
    /// - not empty, at most `max_bytes`, ASCII only
    /// - holds `-----BEGIN {label}-----` followed by `-----END {label}-----`
    /// - every other line is base64 or blank, so only encoded data reaches a
    ///   document the value is written into
    ///
    /// The contents are not decoded here. The adapter that reads them does
    /// that, and refuses a block it cannot parse.
    #[must_use]
    pub fn pem(mut self, label: &'static str, max_bytes: usize) -> Self {
        self = self.not_empty().max_bytes(max_bytes).ascii_only();
        if holds_block(self.value, label) && only_armour_and_base64(self.value) {
            return self;
        }
        self.errors.push(ValidationError::Custom {
            field: self.field,
            code: "invalid_pem".to_owned(),
            message: message!(
                "values-must-be-pem-encoded-holding-a",
                format!(
                    "{} must be PEM-encoded, holding a {label} block.",
                    self.field
                )
            ),
        });
        self
    }
}

fn only_armour_and_base64(text: &str) -> bool {
    text.lines()
        .map(str::trim)
        .all(|line| is_armour(line) || is_base64(line))
}

fn is_base64(line: &str) -> bool {
    line.bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='))
}

/// Whether `line` is a `-----BEGIN LABEL-----` or `-----END LABEL-----` line.
///
/// The label holds uppercase letters, digits and single spaces, as RFC 7468
/// writes them. Any other line starting with dashes is plain text, not
/// armour.
fn is_armour(line: &str) -> bool {
    let Some(inner) = line
        .strip_prefix("-----")
        .and_then(|rest| rest.strip_suffix("-----"))
    else {
        return false;
    };
    let Some(label) = inner
        .strip_prefix("BEGIN ")
        .or_else(|| inner.strip_prefix("END "))
    else {
        return false;
    };
    !label.is_empty()
        && !label.starts_with(' ')
        && !label.ends_with(' ')
        && !label.contains("  ")
        && label
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b' ')
}

fn holds_block(text: &str, label: &str) -> bool {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    text.split_once(&begin)
        .is_some_and(|(_, after)| after.contains(&end))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn certificate(text: &str) -> bool {
        Validator::new("certificate", text)
            .pem("CERTIFICATE", 1024)
            .validate_first()
            .is_ok()
    }

    /// A `CERTIFICATE` block with one base64 line between its armour lines
    /// passes.
    #[test]
    fn a_certificate_block_is_accepted() {
        assert!(certificate(
            "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
        ));
    }

    /// Certificate PEM validation rejects embedded markup, missing or reversed
    /// delimiters, and blocks with another label.
    #[test]
    fn text_without_a_whole_block_of_that_kind_is_refused() {
        for text in [
            "",
            "MIIB",
            "-----BEGIN CERTIFICATE-----\nMIIB",
            "-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----",
            "-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----",
            "-----BEGIN CERTIFICATE-----\nMII</ds:X509Certificate>\n-----END CERTIFICATE-----",
            "-----BEGIN CERTIFICATE-----\n-----<script>alert(1)</script>\nMIIB\n-----END CERTIFICATE-----",
            "-----BEGIN CERTIFICATE-----\n----- anything at all -----\nMIIB\n-----END CERTIFICATE-----",
        ] {
            assert!(!certificate(text), "{text:?} was accepted");
        }
    }
}
