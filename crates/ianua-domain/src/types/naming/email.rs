use crate::shared::validation::{TextValue, Validator, text_value};

text_value! {
    /// A checked email address.
    ///
    /// The checks are practical ones, enough for an identity provider:
    /// - ASCII only, at most 254 characters in all, per RFC 5321.
    /// - Exactly one `@` between the local part and the domain.
    /// - The local part has 1 to 64 letters, digits or `.+-_`. It has no two
    ///   dots in a row, and starts and ends with a letter or digit.
    /// - The domain has 3 to 255 characters of valid DNS labels. Each label
    ///   has 1 to 63 characters and does not start or end with a hyphen.
    /// - It is stored in lower case, since mail systems treat addresses as
    ///   case-insensitive in practice.
    ///
    /// It does not try to meet all of RFC 5321. The real check is the
    /// verification email reaching the user's inbox.
    ///
    /// It is unique within a tenant, not everywhere. `alice@example.com` can
    /// be one user in tenant Acme and a separate user in tenant Globex.
    ///
    /// # Examples
    ///
    /// ```
    /// # use ianua_domain::types::Email;
    /// let email = Email::new("Alice@Example.COM").unwrap();
    /// assert_eq!(email.as_str(), "alice@example.com");
    /// ```
    pub struct Email;
}

impl TextValue for Email {
    const FIELD: &'static str = "email";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.email()
    }

    fn normalized(value: String) -> String {
        value.to_ascii_lowercase()
    }
}

impl Email {
    /// The local part, everything before the `@`.
    #[must_use]
    pub fn local_part(&self) -> &str {
        self.0.split_once('@').map_or("", |(local, _)| local)
    }

    /// The domain, everything after the `@`.
    #[must_use]
    pub fn domain(&self) -> &str {
        self.0.split_once('@').map_or("", |(_, domain)| domain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `alice@example.com` is accepted and kept as written.
    #[test]
    fn accepts_simple_email() {
        let email = Email::new("alice@example.com").unwrap();
        assert_eq!(email.as_str(), "alice@example.com");
    }

    /// `Alice@Example.COM` is kept as `alice@example.com`, so both spellings
    /// find the same user.
    #[test]
    fn lowercases_on_construction() {
        let email = Email::new("Alice@Example.COM").unwrap();
        assert_eq!(email.as_str(), "alice@example.com");
    }

    /// `alice.bob@example.com` with a dot in the local part is accepted.
    #[test]
    fn accepts_dots_in_local_part() {
        assert!(Email::new("alice.bob@example.com").is_ok());
    }

    /// A tagged address, `alice+tag@example.com`, is accepted.
    #[test]
    fn accepts_plus_in_local_part() {
        assert!(Email::new("alice+tag@example.com").is_ok());
    }

    /// A domain with a hyphen, `my-company.com`, is accepted.
    #[test]
    fn accepts_hyphens_in_domain() {
        assert!(Email::new("alice@my-company.com").is_ok());
    }

    /// A domain with several labels, `mail.example.co.uk`, is accepted.
    #[test]
    fn email_addresses_can_use_subdomains() {
        assert!(Email::new("alice@mail.example.co.uk").is_ok());
    }

    /// A local part of only digits, `123@example.com`, is accepted.
    #[test]
    fn accepts_numeric_local() {
        assert!(Email::new("123@example.com").is_ok());
    }

    /// `alice_bob@example.com` with an underscore is accepted.
    #[test]
    fn accepts_underscores_in_local() {
        assert!(Email::new("alice_bob@example.com").is_ok());
    }

    /// The local part of `alice@example.com` is `alice`.
    #[test]
    fn extracts_local_part() {
        let email = Email::new("alice@example.com").unwrap();
        assert_eq!(email.local_part(), "alice");
    }

    /// The domain of `alice@example.com` is `example.com`.
    #[test]
    fn the_domain_follows_the_at_sign() {
        let email = Email::new("alice@example.com").unwrap();
        assert_eq!(email.domain(), "example.com");
    }

    /// An empty address is refused with the `required` code.
    #[test]
    fn empty_email_addresses_report_required() {
        let err = Email::new("").unwrap_err();
        assert_eq!(err.code(), "required");
    }

    /// `aliceexample.com` with no `@` is refused with the `invalid_format`
    /// code.
    #[test]
    fn rejects_no_at_symbol() {
        let err = Email::new("aliceexample.com").unwrap_err();
        assert_eq!(err.code(), "invalid_format");
    }

    /// `alice@@example.com` with two `@` is refused with the
    /// `invalid_format` code.
    #[test]
    fn rejects_multiple_at_symbols() {
        let err = Email::new("alice@@example.com").unwrap_err();
        assert_eq!(err.code(), "invalid_format");
    }

    /// `@example.com` has no local part and is refused.
    #[test]
    fn rejects_at_at_start() {
        assert!(Email::new("@example.com").is_err());
    }

    /// `alice@` has no domain and is refused.
    #[test]
    fn rejects_at_at_end() {
        assert!(Email::new("alice@").is_err());
    }

    /// `alice..bob@example.com` is refused with the `consecutive_character`
    /// code.
    #[test]
    fn rejects_consecutive_dots_in_local() {
        let err = Email::new("alice..bob@example.com").unwrap_err();
        assert_eq!(err.code(), "consecutive_character");
    }

    /// `.alice@example.com` starts with a dot and is refused.
    #[test]
    fn rejects_leading_dot_in_local() {
        assert!(Email::new(".alice@example.com").is_err());
    }

    /// `alice.@example.com` ends its local part with a dot and is refused.
    #[test]
    fn rejects_trailing_dot_in_local() {
        assert!(Email::new("alice.@example.com").is_err());
    }

    /// `alice@localhost` has a domain with no dot and is refused with the
    /// `invalid_domain` code.
    #[test]
    fn rejects_domain_without_dot() {
        let err = Email::new("alice@localhost").unwrap_err();
        assert_eq!(err.code(), "invalid_domain");
    }

    /// A domain starting with a dot, `.example.com`, is refused.
    #[test]
    fn rejects_leading_dot_in_domain() {
        assert!(Email::new("alice@.example.com").is_err());
    }

    /// A domain ending with a dot, `example.com.`, is refused.
    #[test]
    fn rejects_trailing_dot_in_domain() {
        assert!(Email::new("alice@example.com.").is_err());
    }

    /// A domain label starting with a hyphen, `-example`, is refused.
    #[test]
    fn rejects_leading_hyphen_in_domain_label() {
        assert!(Email::new("alice@-example.com").is_err());
    }

    /// A domain label ending with a hyphen, `example-`, is refused.
    #[test]
    fn rejects_trailing_hyphen_in_domain_label() {
        assert!(Email::new("alice@example-.com").is_err());
    }

    /// A domain with a 64-character label is refused, since DNS caps a label
    /// at 63.
    #[test]
    fn rejects_domain_label_over_63_chars() {
        let long_label = "a".repeat(64);
        assert!(Email::new(format!("alice@{long_label}.com")).is_err());
    }

    /// `álice@example.com` with an accented local part is refused.
    #[test]
    fn rejects_unicode_in_local() {
        assert!(Email::new("álice@example.com").is_err());
    }

    /// An accented domain is refused rather than accepted as a lookalike
    /// spelling of an ASCII mailbox domain.
    #[test]
    fn rejects_unicode_in_domain() {
        assert!(Email::new("alice@exämple.com").is_err());
    }

    /// An address with an emoji in the local part is refused.
    #[test]
    fn email_addresses_with_emoji_are_refused() {
        assert!(Email::new("alice👋@example.com").is_err());
    }

    /// `alice @example.com` with a space is refused.
    #[test]
    fn email_addresses_with_spaces_are_refused() {
        assert!(Email::new("alice @example.com").is_err());
    }

    /// A newline in an email address is refused before it can split a mail
    /// header.
    #[test]
    fn email_addresses_with_newlines_are_refused() {
        assert!(Email::new("alice\n@example.com").is_err());
    }

    /// An address with a NUL byte inside it is refused.
    #[test]
    fn rejects_null_bytes() {
        assert!(Email::new("alice\x00@example.com").is_err());
    }

    /// An address with valid parts but over 254 characters in all is
    /// refused.
    #[test]
    fn rejects_over_254_total() {
        let local = "a".repeat(64);
        let domain_label = "b".repeat(63);
        let addr = format!("{local}@{domain_label}.{domain_label}.{domain_label}.com");
        assert!(addr.len() > 254);
        assert!(Email::new(addr).is_err());
    }

    /// `Alice@Example.COM` prints in its lower-case form,
    /// `alice@example.com`.
    #[test]
    fn display_returns_normalized_value() {
        let email = Email::new("Alice@Example.COM").unwrap();
        assert_eq!(email.to_string(), "alice@example.com");
    }
}
