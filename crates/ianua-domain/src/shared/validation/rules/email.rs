//! Email addresses.

use crate::shared::validation::boundary::Boundary;
use crate::shared::validation::charset::Charset;
use crate::shared::validation::error::ValidationError;
use crate::shared::validation::validator::Validator;

impl Validator<'_> {
    /// Checks a whole email address, in the plain subset of RFC 5321 that
    /// real mail uses.
    ///
    /// It checks the whole string first, then the local part and the domain
    /// each by their own rules. The rules:
    /// - not empty, ASCII only, at most 254 characters
    /// - exactly one `@`
    /// - local part: 1 to 64 characters of lowercase letters, digits and
    ///   `.+-_`, no two dots in a row, starting and ending with a lowercase
    ///   letter or digit
    /// - domain: 3 to 255 characters of lowercase letters, digits, `.` and
    ///   `-`, with at least one dot
    /// - each domain label 1 to 63 characters, not starting or ending with a
    ///   hyphen
    #[must_use]
    pub fn email(mut self) -> Self {
        self = self
            .not_empty()
            .ascii_only()
            .length(1..=254)
            .contains_once(b'@');

        if !self.errors.is_empty() {
            return self;
        }

        let field = self.field;
        let Some((local, domain)) = self.value.split_once('@') else {
            return self;
        };

        self.errors.extend(email_local_part_errors(field, local));
        self.errors.extend(email_domain_errors(field, domain));
        self
    }
}

fn email_local_part_errors(field: &'static str, local: &str) -> Vec<ValidationError> {
    Validator::new(field, local)
        .length(1..=64)
        .charset(
            Charset::LOWERCASE
                | Charset::DIGIT
                | Charset::DOT
                | Charset::HYPHEN
                | Charset::UNDERSCORE
                | Charset::PLUS,
        )
        .no_consecutive(b'.')
        .boundaries(Boundary::LowercaseAlphanumeric)
        .validate()
}

fn email_domain_errors(field: &'static str, domain: &str) -> Vec<ValidationError> {
    Validator::new(field, domain)
        .length(3..=255)
        .charset(Charset::LOWERCASE | Charset::DIGIT | Charset::HYPHEN | Charset::DOT)
        .domain_labels()
        .validate()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `alice@example.com` passes.
    #[test]
    fn email_accepts_simple_address() {
        assert!(
            Validator::new("email", "alice@example.com")
                .email()
                .validate()
                .is_empty()
        );
    }

    /// `alice.bob@example.com` passes. A single dot inside the local part is
    /// allowed.
    #[test]
    fn email_accepts_dots_in_local() {
        assert!(
            Validator::new("email", "alice.bob@example.com")
                .email()
                .validate()
                .is_empty()
        );
    }

    /// `alice+tag@example.com` passes, so people can use plus addressing.
    #[test]
    fn email_accepts_plus_addressing() {
        assert!(
            Validator::new("email", "alice+tag@example.com")
                .email()
                .validate()
                .is_empty()
        );
    }

    /// A domain of four labels, `mail.example.co.uk`, passes.
    #[test]
    fn email_accepts_subdomain() {
        assert!(
            Validator::new("email", "alice@mail.example.co.uk")
                .email()
                .validate()
                .is_empty()
        );
    }

    /// `alice@my-company.com` passes. A hyphen inside a label is allowed.
    #[test]
    fn email_accepts_hyphens_in_domain() {
        assert!(
            Validator::new("email", "alice@my-company.com")
                .email()
                .validate()
                .is_empty()
        );
    }

    /// `123@example.com` passes. A local part of only digits is allowed.
    #[test]
    fn email_accepts_numeric_local() {
        assert!(
            Validator::new("email", "123@example.com")
                .email()
                .validate()
                .is_empty()
        );
    }

    /// `alice_bob@example.com` passes. An underscore inside the local part
    /// is allowed.
    #[test]
    fn email_accepts_underscores_in_local() {
        assert!(
            Validator::new("email", "alice_bob@example.com")
                .email()
                .validate()
                .is_empty()
        );
    }

    /// An empty address is refused with `required`.
    #[test]
    fn email_rejects_empty() {
        let err = Validator::new("email", "")
            .email()
            .validate_first()
            .unwrap_err();
        assert_eq!(err.code(), "required");
    }

    /// `aliceexample.com` has no `@` and is refused with `invalid_format`.
    #[test]
    fn email_rejects_no_at() {
        let err = Validator::new("email", "aliceexample.com")
            .email()
            .validate_first()
            .unwrap_err();
        assert_eq!(err.code(), "invalid_format");
    }

    /// `alice@@example.com` has two `@` signs and is refused with
    /// `invalid_format`.
    #[test]
    fn email_rejects_multiple_at() {
        let err = Validator::new("email", "alice@@example.com")
            .email()
            .validate_first()
            .unwrap_err();
        assert_eq!(err.code(), "invalid_format");
    }

    /// `@example.com` has an empty local part and is refused.
    #[test]
    fn email_rejects_at_at_start() {
        assert!(
            Validator::new("email", "@example.com")
                .email()
                .validate_first()
                .is_err()
        );
    }

    /// `alice@` has an empty domain and is refused.
    #[test]
    fn email_rejects_at_at_end() {
        assert!(
            Validator::new("email", "alice@")
                .email()
                .validate_first()
                .is_err()
        );
    }

    /// `alice..bob@example.com` is refused with `consecutive_character`.
    #[test]
    fn email_rejects_consecutive_dots_in_local() {
        let err = Validator::new("email", "alice..bob@example.com")
            .email()
            .validate_first()
            .unwrap_err();
        assert_eq!(err.code(), "consecutive_character");
    }

    /// `.alice@example.com` is refused. The local part must start with a
    /// letter or digit.
    #[test]
    fn email_rejects_leading_dot_in_local() {
        assert!(
            Validator::new("email", ".alice@example.com")
                .email()
                .validate_first()
                .is_err()
        );
    }

    /// `alice.@example.com` is refused. The local part must end with a
    /// letter or digit.
    #[test]
    fn email_rejects_trailing_dot_in_local() {
        assert!(
            Validator::new("email", "alice.@example.com")
                .email()
                .validate_first()
                .is_err()
        );
    }

    /// `alice@localhost` is refused with `invalid_domain`. A domain needs at
    /// least one dot, so a mail to a local host name is not accepted.
    #[test]
    fn email_rejects_domain_without_dot() {
        let err = Validator::new("email", "alice@localhost")
            .email()
            .validate_first()
            .unwrap_err();
        assert_eq!(err.code(), "invalid_domain");
    }

    /// `alice@.example.com` has an empty first label and is refused.
    #[test]
    fn email_rejects_leading_dot_in_domain() {
        assert!(
            Validator::new("email", "alice@.example.com")
                .email()
                .validate_first()
                .is_err()
        );
    }

    /// `alice@example.com.` has an empty last label and is refused, so one
    /// address cannot be stored in two spellings.
    #[test]
    fn email_rejects_trailing_dot_in_domain() {
        assert!(
            Validator::new("email", "alice@example.com.")
                .email()
                .validate_first()
                .is_err()
        );
    }

    /// `alice@-example.com` is refused. A DNS label may not start with a
    /// hyphen.
    #[test]
    fn email_rejects_leading_hyphen_in_domain_label() {
        assert!(
            Validator::new("email", "alice@-example.com")
                .email()
                .validate_first()
                .is_err()
        );
    }

    /// `alice@example-.com` is refused. A DNS label may not end with a
    /// hyphen.
    #[test]
    fn email_rejects_trailing_hyphen_in_domain_label() {
        assert!(
            Validator::new("email", "alice@example-.com")
                .email()
                .validate_first()
                .is_err()
        );
    }

    /// A domain whose first label is 64 characters is refused, one past the
    /// DNS limit.
    #[test]
    fn email_rejects_domain_label_over_63_chars() {
        let long_label = "a".repeat(64);
        let addr = format!("alice@{long_label}.com");
        assert!(
            Validator::new("email", &addr)
                .email()
                .validate_first()
                .is_err()
        );
    }

    /// `álice@example.com` is refused. Addresses are ASCII only.
    #[test]
    fn email_rejects_unicode() {
        assert!(
            Validator::new("email", "álice@example.com")
                .email()
                .validate_first()
                .is_err()
        );
    }

    /// `alice @example.com` is refused for its space.
    #[test]
    fn email_rejects_spaces() {
        assert!(
            Validator::new("email", "alice @example.com")
                .email()
                .validate_first()
                .is_err()
        );
    }

    /// An address whose local part and labels are each within limits, but
    /// which is longer than 254 characters in total, is refused.
    #[test]
    fn email_rejects_over_254_total() {
        let local = "a".repeat(64);
        let domain_label = "b".repeat(63);
        let addr = format!("{local}@{domain_label}.{domain_label}.{domain_label}.com");
        assert!(addr.len() > 254);
        assert!(
            Validator::new("email", &addr)
                .email()
                .validate_first()
                .is_err()
        );
    }

    /// An address with quotes and `=` from a SQL injection is refused by the
    /// local part's charset.
    #[test]
    fn email_rejects_sql_injection() {
        assert!(
            Validator::new("email", "alice'OR'1'='1@example.com")
                .email()
                .validate_first()
                .is_err()
        );
    }

    /// Email validation rejects parentheses, asterisks, equals signs, and pipes used in LDAP filters.
    #[test]
    fn email_rejects_ldap_injection() {
        assert!(
            Validator::new("email", "alice)(cn=*))(|(cn=*@example.com")
                .email()
                .validate_first()
                .is_err()
        );
    }

    /// An email address containing a CRLF header fragment is invalid.
    #[test]
    fn email_rejects_crlf_injection() {
        assert!(
            Validator::new("email", "alice\r\nbcc:attacker@evil.com@example.com")
                .email()
                .validate_first()
                .is_err()
        );
    }

    /// A null byte within an email address is rejected.
    #[test]
    fn email_rejects_null_byte_injection() {
        assert!(
            Validator::new("email", "alice\x00@example.com")
                .email()
                .validate_first()
                .is_err()
        );
    }

    /// A Cyrillic lookalike in an email address fails the ASCII requirement.
    #[test]
    fn email_rejects_unicode_homoglyph_attack() {
        assert!(
            Validator::new("email", "\u{0430}lice@example.com")
                .email()
                .validate_first()
                .is_err()
        );
    }

    /// A bare newline introducing a mail-header fragment is invalid in an email address.
    #[test]
    fn email_rejects_header_injection_via_newline() {
        assert!(
            Validator::new("email", "alice\nbcc:evil@evil.com@example.com")
                .email()
                .validate_first()
                .is_err()
        );
    }

    /// A 65-character local part is refused, one past the limit of 64.
    #[test]
    fn email_rejects_oversized_local_part() {
        let long_local = "a".repeat(65);
        let addr = format!("{long_local}@example.com");
        assert!(
            Validator::new("email", &addr)
                .email()
                .validate_first()
                .is_err()
        );
    }

    /// A local part of only `+.-_` is refused. It must start and end with a
    /// letter or digit.
    #[test]
    fn email_rejects_special_chars_only_local() {
        assert!(
            Validator::new("email", "+.-_@example.com")
                .email()
                .validate_first()
                .is_err()
        );
    }

    /// Percent-encoded characters are refused in the email local part.
    #[test]
    fn email_rejects_percent_encoding() {
        assert!(
            Validator::new("email", "alice%40@example.com")
                .email()
                .validate_first()
                .is_err()
        );
    }

    /// An address with a backslash in the local part is refused.
    #[test]
    fn email_rejects_backslash() {
        assert!(
            Validator::new("email", "alice\\bob@example.com")
                .email()
                .validate_first()
                .is_err()
        );
    }

    /// `"alice bob"@example.com` is valid under RFC 5321 but refused here.
    /// Quoted local parts are outside the subset this rule accepts.
    #[test]
    fn email_rejects_quoted_local_part() {
        assert!(
            Validator::new("email", "\"alice bob\"@example.com")
                .email()
                .validate_first()
                .is_err()
        );
    }

    /// An IP-literal domain is invalid in an email address.
    #[test]
    fn email_rejects_ip_address_domain() {
        assert!(
            Validator::new("email", "alice@[127.0.0.1]")
                .email()
                .validate_first()
                .is_err()
        );
    }

    /// `alice(comment)@example.com` is refused. Some mail software drops a
    /// comment and some keeps it, so one address could be read two ways.
    #[test]
    fn email_rejects_comment_in_email() {
        assert!(
            Validator::new("email", "alice(comment)@example.com")
                .email()
                .validate_first()
                .is_err()
        );
    }

    /// `<alice@example.com>` is refused. Angle brackets belong to a mail
    /// header, not to the address.
    #[test]
    fn email_rejects_angle_brackets() {
        assert!(
            Validator::new("email", "<alice@example.com>")
                .email()
                .validate_first()
                .is_err()
        );
    }

    /// An address with a semicolon is refused, so it cannot end a command
    /// it is written into.
    #[test]
    fn email_rejects_semicolon() {
        assert!(
            Validator::new("email", "alice;drop@example.com")
                .email()
                .validate_first()
                .is_err()
        );
    }

    /// An address with `|` is refused, so it cannot pipe into a command.
    #[test]
    fn email_rejects_pipe() {
        assert!(
            Validator::new("email", "alice|bob@example.com")
                .email()
                .validate_first()
                .is_err()
        );
    }

    /// An address with backticks around `cmd` is refused, so a shell cannot
    /// run it.
    #[test]
    fn email_rejects_backtick() {
        assert!(
            Validator::new("email", "alice`cmd`@example.com")
                .email()
                .validate_first()
                .is_err()
        );
    }

    /// An address with `$var` is refused, so a shell or template cannot
    /// expand it.
    #[test]
    fn email_rejects_dollar_sign() {
        assert!(
            Validator::new("email", "alice$var@example.com")
                .email()
                .validate_first()
                .is_err()
        );
    }
}
