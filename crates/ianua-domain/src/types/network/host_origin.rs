//! The `https://` origin of one named host.

use crate::message;
use crate::shared::validation::rules::url::{self as web_url, UrlRules, UrlShape};
use crate::shared::validation::{Rule, TextValue, ValidationError, Validator, text_value};
use crate::types::DomainName;

text_value! {
    /// The `https://` origin of one named host: `https://shop.acme.com`.
    ///
    /// Pages on such an origin may be trusted to send a request with a
    /// session cookie, or a browser sent on to one. Unlike an [`Origin`],
    /// it is never `*`, never plain `http://` and never a wildcard host, so
    /// trusting it trusts exactly one site.
    ///
    /// [`Origin`]: crate::types::Origin
    pub struct HostOrigin;
}

impl TextValue for HostOrigin {
    const FIELD: &'static str = "origin";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.rule(&HttpsOrigin).rule(&OneHost)
    }
}

impl HostOrigin {
    /// The `https://` origin of `host`.
    ///
    /// # Errors
    ///
    /// - [`ValidationError`] when `host` is a wildcard, which names no one
    ///   site.
    pub fn of(host: &DomainName) -> Result<Self, ValidationError> {
        Self::new(format!("https://{}", host.as_str()))
    }
}

const RULES: UrlRules = UrlRules {
    schemes: &["https"],
    max_len: 2048,
    shape: UrlShape::OriginOnly,
};

/// An `https://` origin, with nothing after the host and port.
struct HttpsOrigin;

impl Rule for HttpsOrigin {
    fn check(&self, field: &'static str, value: &str) -> Option<ValidationError> {
        web_url::parse(field, value, RULES).err()
    }
}

/// A host named in full, not a wildcard over many.
struct OneHost;

impl Rule for OneHost {
    fn check(&self, field: &'static str, value: &str) -> Option<ValidationError> {
        if !value.contains('*') {
            return None;
        }
        Some(ValidationError::Custom {
            field,
            code: "wildcard_origin".to_owned(),
            message: message!(
                "values-must-name-one-host-not-a",
                format!("{field} must name one host, not a wildcard.")
            ),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `shop.acme.com` has the origin `https://shop.acme.com`.
    #[test]
    fn a_host_has_its_https_origin() {
        let host = DomainName::new("shop.acme.com").unwrap();

        assert_eq!(
            HostOrigin::of(&host).unwrap().as_str(),
            "https://shop.acme.com"
        );
    }

    /// Wildcards, plain HTTP and URLs with paths are refused when an origin
    /// must identify exactly one HTTPS site.
    #[test]
    fn anything_but_one_https_host_is_refused() {
        for refused in [
            "*",
            "http://shop.acme.com",
            "https://*.acme.com",
            "https://shop.acme.com/app",
        ] {
            assert!(HostOrigin::new(refused).is_err(), "{refused} was kept");
        }
    }

    /// A wildcard domain cannot produce an origin that trusts every site
    /// beneath it.
    #[test]
    fn a_wildcard_host_has_no_origin() {
        let wildcard = DomainName::new("*.acme.com").unwrap();

        assert!(HostOrigin::of(&wildcard).is_err());
    }
}
