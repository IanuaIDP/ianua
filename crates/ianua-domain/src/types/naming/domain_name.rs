use crate::shared::validation::{Charset, Rule, TextValue, ValidationError, Validator, text_value};

text_value! {
    /// A checked domain name a tenant owns.
    ///
    /// It routes email, such as `alice@acme.com` to Acme's tenant. It also
    /// serves federation domain hints and custom domains.
    ///
    /// It follows the DNS rules:
    /// - ASCII only, in lower case.
    /// - At least one dot, so at least two labels.
    /// - Each label has 1 to 63 characters.
    /// - Labels hold only lowercase letters, digits and hyphens.
    /// - No label starts or ends with a hyphen.
    /// - 3 to 253 characters in all.
    ///
    /// It may start with one `*.` wildcard label.
    ///
    /// # Examples
    ///
    /// ```
    /// # use ianua_domain::types::DomainName;
    /// let domain = DomainName::new("acme.com").unwrap();
    /// assert_eq!(domain.as_str(), "acme.com");
    /// ```
    pub struct DomainName;
}

impl TextValue for DomainName {
    const FIELD: &'static str = "domain";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.rule(&DomainShape)
    }

    fn normalized(value: String) -> String {
        value.to_ascii_lowercase()
    }
}

impl DomainName {
    /// Whether this is a wildcard domain (`*.acme.com`).
    #[must_use]
    pub fn is_wildcard(&self) -> bool {
        self.0.starts_with("*.")
    }

    /// The name a wildcard stands in front of, or `None` if this is not one.
    ///
    /// `*.auth.acme.com` covers names beneath `auth.acme.com`, which is both
    /// the zone a certificate challenge is written into and the domain a
    /// tenant must already hold before a wildcard over it means anything.
    #[must_use]
    pub fn wildcard_parent(&self) -> Option<Self> {
        self.0.strip_prefix("*.").map(|rest| Self(rest.to_owned()))
    }

    /// Whether requests for `hostname` are served by this name.
    ///
    /// It serves an exact match. A wildcard also serves a name exactly one
    /// label beneath its parent. `*.acme.com` serves `api.acme.com`, but not
    /// `a.b.acme.com` or `acme.com` itself.
    ///
    /// This is not the DNS wildcard rule, which matches at any depth. In DNS
    /// `*.acme.com` answers for `a.b.acme.com`, but by RFC 6125 a
    /// certificate for `*.acme.com` does not cover that name. Matching more
    /// here than the certificate covers would route a request that then
    /// fails the TLS handshake.
    #[must_use]
    pub fn serves(&self, hostname: &str) -> bool {
        let hostname = hostname.trim_end_matches('.').to_ascii_lowercase();

        if self.0 == hostname {
            return true;
        }

        let Some(parent) = self.0.strip_prefix("*.") else {
            return false;
        };

        let Some(label) = hostname.strip_suffix(parent) else {
            return false;
        };

        matches!(label.strip_suffix('.'), Some(one) if !one.is_empty() && !one.contains('.'))
    }
}

/// A DNS name, optionally behind one leading `*.` wildcard label.
struct DomainShape;

impl Rule for DomainShape {
    fn check(&self, field: &'static str, value: &str) -> Option<ValidationError> {
        let base = value.strip_prefix("*.").unwrap_or(value);
        Validator::new(field, base)
            .ascii_only()
            .length(3..=253)
            .charset(Charset::LOWERCASE | Charset::DIGIT | Charset::HYPHEN | Charset::DOT)
            .domain_labels()
            .validate_first()
            .err()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::builders::domain_name;

    /// `acme.com` is accepted and kept as written.
    #[test]
    fn accepts_simple_domain() {
        let d = DomainName::new("acme.com").unwrap();
        assert_eq!(d.as_str(), "acme.com");
    }

    /// A subdomain, `mail.acme.com`, is accepted.
    #[test]
    fn subdomains_are_valid_domain_names() {
        assert!(DomainName::new("mail.acme.com").is_ok());
    }

    /// A name six labels deep is accepted.
    #[test]
    fn accepts_deep_subdomain() {
        assert!(DomainName::new("a.b.c.d.example.com").is_ok());
    }

    /// `my-company.co.uk` with a hyphen inside a label is accepted.
    #[test]
    fn accepts_hyphenated_labels() {
        assert!(DomainName::new("my-company.co.uk").is_ok());
    }

    /// `123.456.com` with labels of digits is accepted, since it ends in a
    /// name and not a number.
    #[test]
    fn accepts_numeric_labels() {
        assert!(DomainName::new("123.456.com").is_ok());
    }

    /// `ACME.COM` is kept as `acme.com`.
    #[test]
    fn lowercases_on_construction() {
        let d = DomainName::new("ACME.COM").unwrap();
        assert_eq!(d.as_str(), "acme.com");
    }

    /// `localhost` has no dot and is refused.
    #[test]
    fn rejects_no_dot() {
        assert!(DomainName::new("localhost").is_err());
    }

    /// Empty text is refused before it can identify a domain in ownership checks.
    #[test]
    fn an_empty_domain_name_is_refused() {
        assert!(DomainName::new("").is_err());
    }

    /// `.acme.com` starts with a dot and is refused.
    #[test]
    fn rejects_leading_dot() {
        assert!(DomainName::new(".acme.com").is_err());
    }

    /// `acme.com.` ends with a dot and is refused.
    #[test]
    fn rejects_trailing_dot() {
        assert!(DomainName::new("acme.com.").is_err());
    }

    /// `acme..com` has an empty label and is refused.
    #[test]
    fn rejects_consecutive_dots() {
        assert!(DomainName::new("acme..com").is_err());
    }

    /// `-acme.com` starts a label with a hyphen and is refused.
    #[test]
    fn rejects_leading_hyphen_in_label() {
        assert!(DomainName::new("-acme.com").is_err());
    }

    /// `acme-.com` ends a label with a hyphen and is refused.
    #[test]
    fn rejects_trailing_hyphen_in_label() {
        assert!(DomainName::new("acme-.com").is_err());
    }

    /// A name with a 64-character label is refused.
    #[test]
    fn rejects_label_over_63_chars() {
        let long = "a".repeat(64);
        assert!(DomainName::new(format!("{long}.com")).is_err());
    }

    /// A name with valid labels but over 253 characters in all is refused.
    #[test]
    fn rejects_total_over_253_chars() {
        let label = "a".repeat(63);
        let domain = format!("{label}.{label}.{label}.{label}.com");
        assert!(domain.len() > 253);
        assert!(DomainName::new(domain).is_err());
    }

    /// An accented lookalike of an ASCII domain is rejected during validation.
    #[test]
    fn non_ascii_domain_names_are_refused() {
        assert!(DomainName::new("ácme.com").is_err());
    }

    /// `acme .com` with a space is refused.
    #[test]
    fn domain_names_with_spaces_are_refused() {
        assert!(DomainName::new("acme .com").is_err());
    }

    /// `ac_me.com` with an underscore is refused, since host names do not
    /// allow one.
    #[test]
    fn domain_names_with_underscores_are_refused() {
        assert!(DomainName::new("ac_me.com").is_err());
    }

    /// `*.acme.com` is accepted as written and reports that it is a
    /// wildcard.
    #[test]
    fn accepts_wildcard_domain() {
        let d = DomainName::new("*.acme.com").unwrap();
        assert_eq!(d.as_str(), "*.acme.com");
        assert!(d.is_wildcard());
    }

    /// A wildcard over a subdomain, `*.sub.acme.com`, is accepted and is a
    /// wildcard.
    #[test]
    fn accepts_wildcard_subdomain() {
        let d = DomainName::new("*.sub.acme.com").unwrap();
        assert_eq!(d.as_str(), "*.sub.acme.com");
        assert!(d.is_wildcard());
    }

    /// Plain `acme.com` is not a wildcard.
    #[test]
    fn non_wildcard_is_not_wildcard() {
        let d = DomainName::new("acme.com").unwrap();
        assert!(!d.is_wildcard());
    }

    /// A bare star is refused because a wildcard must name the domain it covers.
    #[test]
    fn rejects_bare_wildcard() {
        assert!(DomainName::new("*").is_err());
    }

    /// `*acme.com` has a star with no dot after it and is refused.
    #[test]
    fn rejects_wildcard_without_dot() {
        assert!(DomainName::new("*acme.com").is_err());
    }

    /// `acme.com` prints as `acme.com`.
    #[test]
    fn display_returns_inner_value() {
        let d = DomainName::new("acme.com").unwrap();
        assert_eq!(d.to_string(), "acme.com");
    }

    /// `api.acme.com` serves itself, but not a sibling, its parent or a name
    /// beneath it.
    #[test]
    fn an_exact_name_serves_itself_and_nothing_else() {
        let exact = domain_name("api.acme.com");

        assert!(exact.serves("api.acme.com"));
        assert!(!exact.serves("other.acme.com"));
        assert!(!exact.serves("acme.com"));
        assert!(!exact.serves("sub.api.acme.com"));
    }

    /// `*.acme.com` serves `api.acme.com` and `www.acme.com`.
    #[test]
    fn a_wildcard_serves_one_label_beneath_its_parent() {
        let wildcard = domain_name("*.acme.com");

        assert!(wildcard.serves("api.acme.com"));
        assert!(wildcard.serves("www.acme.com"));
    }

    /// `*.acme.com` does not serve `a.b.acme.com`. By RFC 6125 its
    /// certificate does not cover that name, so the TLS handshake would
    /// fail.
    #[test]
    fn a_wildcard_does_not_serve_deeper_than_one_label() {
        assert!(!domain_name("*.acme.com").serves("a.b.acme.com"));
    }

    /// `*.acme.com` does not serve `acme.com`. The star stands for a label
    /// that has to be there.
    #[test]
    fn a_wildcard_does_not_serve_its_own_parent() {
        assert!(!domain_name("*.acme.com").serves("acme.com"));
    }

    /// A wildcard excludes lookalike suffixes that do not match its parent on
    /// a whole DNS label boundary.
    #[test]
    fn a_wildcard_does_not_serve_a_name_that_merely_ends_the_same_way() {
        let wildcard = domain_name("*.acme.com");

        assert!(!wildcard.serves("evilacme.com"));
        assert!(!wildcard.serves("api.notacme.com"));
    }

    /// `*.acme.com` serves the text `*.acme.com`, so a route that names the
    /// wildcard as its host is covered by the domain the tenant registered.
    #[test]
    fn a_wildcard_serves_its_own_spelling() {
        assert!(domain_name("*.acme.com").serves("*.acme.com"));
    }

    /// A client asks for `API.Acme.Com` or `api.acme.com.`. Case and a
    /// trailing dot are ignored, so both are served.
    #[test]
    fn serving_ignores_case_and_a_trailing_dot() {
        let wildcard = domain_name("*.acme.com");

        assert!(wildcard.serves("API.Acme.Com"));
        assert!(wildcard.serves("api.acme.com."));
        assert!(domain_name("api.acme.com").serves("API.ACME.COM."));
    }

    /// The parent of `*.auth.acme.com` is `auth.acme.com`. A plain name has
    /// no wildcard parent.
    #[test]
    fn a_wildcards_parent_is_the_name_it_stands_in_front_of() {
        assert_eq!(
            domain_name("*.auth.acme.com")
                .wildcard_parent()
                .unwrap()
                .as_str(),
            "auth.acme.com"
        );
        assert!(domain_name("auth.acme.com").wildcard_parent().is_none());
    }

    /// Abbreviated, hexadecimal, octal and five-part address spellings are
    /// refused so resolver-specific notation cannot pass as an ordinary domain.
    #[test]
    fn rejects_an_ipv4_address_written_in_an_unusual_form() {
        for name in [
            "127.1",
            "0x7f.0.0.1",
            "0177.0.0.1",
            "127.0.0.0x1",
            "1.2.3.4.5",
        ] {
            assert!(DomainName::new(name).is_err(), "{name} was accepted");
        }
    }

    /// An IPv4 address in plain dotted form, `10.0.0.1`, is accepted.
    #[test]
    fn accepts_an_ipv4_address_written_the_ordinary_way() {
        assert!(DomainName::new("10.0.0.1").is_ok());
    }
}
