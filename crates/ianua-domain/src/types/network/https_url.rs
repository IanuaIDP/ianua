use std::fmt;

use crate::shared::security::ssrf;
use crate::shared::validation::ValidationError;
use crate::shared::validation::rules::url::{self as web_url, UrlHost, UrlRules, UrlShape};

/// An HTTPS URL.
///
/// Used for any URL that must be secure, such as logo URLs, SSO, token and
/// authorization endpoints. A webhook target or a signal stream endpoint is
/// a [`PublicHttpsUrl`](crate::types::PublicHttpsUrl) instead, which also
/// refuses `localhost`, single-label names and internal suffixes.
///
/// Rules:
/// - The shared URL rules in
///   [`web_url`](crate::shared::validation::rules::url). A host every parser
///   reads the same way, no credentials, and at most 2048 bytes.
/// - `https://` only.
/// - The host is not an IP address in a private or otherwise blocked range.
///   Infrastructure checks a host name again after it resolves it.
/// - Whether the URL can be reached is not checked here. Infrastructure
///   does that.
///
/// A webhook or stream address often carries its secret in the path or
/// query. So `Debug` shows only the [`origin`](Self::origin). `Display` and
/// [`as_str`](Self::as_str) give the full URL to the code that calls it.
#[derive(Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "String", into = "String"))]
pub struct HttpsUrl {
    text: String,
    parsed: url::Url,
}

const RULES: UrlRules = UrlRules {
    schemes: &["https"],
    max_len: 2048,
    shape: UrlShape::Any,
};

impl TryFrom<String> for HttpsUrl {
    type Error = ValidationError;

    /// Goes through [`HttpsUrl::new`], so a value that arrives as JSON is
    /// held to the same rules as one built in code.
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<HttpsUrl> for String {
    fn from(url: HttpsUrl) -> Self {
        url.text
    }
}

impl HttpsUrl {
    /// Checks and wraps an HTTPS URL.
    ///
    /// # Errors
    ///
    /// - [`ValidationError`] if the text is not an `https://` URL every
    ///   parser reads the same way.
    /// - [`ValidationError`] if it is longer than 2048 bytes.
    /// - [`ValidationError`] if it carries credentials.
    /// - [`ValidationError`] if its host is a blocked IP address.
    pub fn new(value: impl Into<String>) -> Result<Self, ValidationError> {
        let text = value.into();
        let parsed = web_url::parse("url", &text, RULES)?;
        ssrf::reject_internal_host(web_url::host_of(&parsed), "url")?;
        Ok(Self { text, parsed })
    }

    /// The URL as it was written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// Where the URL points, as the HTTP client will read it.
    #[must_use]
    pub fn host(&self) -> UrlHost<'_> {
        web_url::host_of(&self.parsed)
    }

    /// Whether the URL carries a query or a fragment.
    #[must_use]
    pub fn has_query_or_fragment(&self) -> bool {
        self.parsed.query().is_some() || self.parsed.fragment().is_some()
    }

    /// Where the URL points, without anything after the host and port.
    #[must_use]
    pub fn origin(&self) -> UrlOrigin {
        UrlOrigin(self.parsed.origin().ascii_serialization())
    }
}

/// Where an [`HttpsUrl`] points, without the path, query or fragment.
///
/// Records name an endpoint by this. A webhook address often carries its
/// secret in the path or query, as in `/services/T000/B000/XXXX`. Far more
/// people read a record than may hold that secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UrlOrigin(String);

impl UrlOrigin {
    /// The origin, `https://host` with a port when it is not the default.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for UrlOrigin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for HttpsUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.parsed.path() == "/" && !self.has_query_or_fragment() {
            return write!(f, "HttpsUrl({})", self.origin());
        }
        write!(f, "HttpsUrl({}/<redacted>)", self.origin())
    }
}

impl fmt::Display for HttpsUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A webhook URL with a secret path and `?token=abc` has the origin
    /// `https://hooks.example.com:8443`, port kept, path and query gone.
    #[test]
    fn an_origin_drops_the_path_and_query_that_may_hold_a_secret() {
        let url =
            HttpsUrl::new("https://hooks.example.com:8443/services/T0/B0/XXXX?token=abc").unwrap();

        assert_eq!(url.origin().as_str(), "https://hooks.example.com:8443");
    }

    /// A webhook URL with a secret path and token prints in a debug log as
    /// its origin and `<redacted>`, so the secret never reaches the log.
    #[test]
    fn debug_shows_the_origin_but_not_a_secret_path_or_query() {
        let url = HttpsUrl::new("https://hooks.example.com/services/T0/B0/XXXX?token=abc").unwrap();

        let shown = format!("{url:?}");

        assert_eq!(shown, "HttpsUrl(https://hooks.example.com/<redacted>)");
    }

    /// A logo at `https://acme.com/logo.png` is accepted and kept as
    /// written.
    #[test]
    fn https_addresses_are_kept_as_written() {
        let url = HttpsUrl::new("https://acme.com/logo.png").unwrap();
        assert_eq!(url.as_str(), "https://acme.com/logo.png");
    }

    /// The same logo over plain `http://` is refused.
    #[test]
    fn plain_http_addresses_are_refused() {
        assert!(HttpsUrl::new("http://acme.com/logo.png").is_err());
    }

    /// A cloud metadata address is refused during JSON deserialization,
    /// preserving the constructor's address checks.
    #[cfg(feature = "serde")]
    #[test]
    fn deserializing_refuses_an_internal_address_too() {
        let result = serde_json::from_str::<HttpsUrl>(r#""https://169.254.169.254/latest""#);

        assert!(result.is_err());
    }

    /// Both IPv4 and IPv6 loopback destinations are refused as HTTPS URLs.
    #[test]
    fn rejects_loopback_targets() {
        assert!(HttpsUrl::new("https://127.0.0.1/hook").is_err());
        assert!(HttpsUrl::new("https://[::1]:8443/hook").is_err());
    }

    /// Private IPv4 destinations and the cloud metadata address are refused
    /// before they can become outbound HTTPS targets.
    #[test]
    fn rejects_private_and_metadata_targets() {
        assert!(HttpsUrl::new("https://10.0.0.5/hook").is_err());
        assert!(HttpsUrl::new("https://192.168.1.1/hook").is_err());
        assert!(HttpsUrl::new("https://169.254.169.254/latest/meta-data").is_err());
    }

    /// A public IP address and an ordinary host name are both accepted.
    #[test]
    fn allows_a_public_address_and_a_host_name() {
        assert!(HttpsUrl::new("https://93.184.216.34/hook").is_ok());
        assert!(HttpsUrl::new("https://hooks.acme.com/events").is_ok());
    }

    /// An empty destination cannot become a validated HTTPS endpoint.
    #[test]
    fn an_empty_https_address_is_refused() {
        assert!(HttpsUrl::new("").is_err());
    }

    /// `acme.com/logo.png` with no scheme is refused.
    #[test]
    fn rejects_no_scheme() {
        assert!(HttpsUrl::new("acme.com/logo.png").is_err());
    }

    /// `https://app.acme.com/callback` prints in full, as given. Redirects,
    /// email links and JWKS pointers use this printed form.
    #[test]
    fn renders_as_the_url_it_was_built_from() {
        let url = HttpsUrl::new("https://app.acme.com/callback").unwrap();

        assert_eq!(url.to_string(), "https://app.acme.com/callback");
    }

    /// Decimal, hexadecimal, abbreviated and octal loopback spellings are
    /// refused, preventing alternate notation from evading address checks.
    #[test]
    fn rejects_loopback_written_as_a_number() {
        for url in [
            "https://2130706433/hook",
            "https://0x7f000001/hook",
            "https://127.1/hook",
            "https://0x7f.0.0.1/hook",
            "https://0177.0.0.1/hook",
        ] {
            assert!(HttpsUrl::new(url).is_err(), "{url} was accepted");
        }
    }

    /// A backslash before an apparent host suffix is refused because a
    /// browser-style parser would instead target the metadata address.
    #[test]
    fn rejects_a_backslash_that_hides_the_real_host() {
        assert!(HttpsUrl::new("https://169.254.169.254\\@hooks.acme.com/").is_err());
    }

    /// Tabs and spaces in hosts are refused, including a tab that another
    /// parser could discard to recover the metadata address.
    #[test]
    fn rejects_whitespace_inside_the_host() {
        assert!(HttpsUrl::new("https://169.254.169\t.254/latest").is_err());
        assert!(HttpsUrl::new("https://hooks.acme.com /x").is_err());
    }

    /// User information is refused whether it resembles a trusted hostname
    /// or contains a username and password.
    #[test]
    fn rejects_credentials_in_the_url() {
        assert!(HttpsUrl::new("https://hooks.acme.com@evil.example/").is_err());
        assert!(HttpsUrl::new("https://user:pass@hooks.acme.com/").is_err());
    }

    /// `https:///path` and `https://:443/path` name no host. Both are
    /// refused.
    #[test]
    fn rejects_a_url_without_a_host() {
        assert!(HttpsUrl::new("https:///path").is_err());
        assert!(HttpsUrl::new("https://:443/path").is_err());
    }
}
