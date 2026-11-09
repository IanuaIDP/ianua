use std::fmt;

use crate::shared::validation::ValidationError;
use crate::shared::validation::rules::url::{self as web_url, UrlHost};

/// An HTTP or HTTPS URL.
///
/// Used for upstream service URLs where plain HTTP is fine, such as an
/// internal service behind a service mesh or VPN.
///
/// It follows the shared URL rules in
/// [`web_url`](crate::shared::validation::rules::url). It is `http://` or
/// `https://`, at most 2048 bytes, with a host every parser reads the same
/// way and no credentials.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "String", into = "String"))]
pub struct HttpUrl {
    text: String,
    parsed: url::Url,
}

impl TryFrom<String> for HttpUrl {
    type Error = ValidationError;

    /// Goes through [`HttpUrl::new`], so a URL that arrives as JSON is held
    /// to the same rules as one built in code.
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<HttpUrl> for String {
    fn from(url: HttpUrl) -> Self {
        url.text
    }
}

impl HttpUrl {
    /// Checks and wraps an HTTP or HTTPS URL.
    ///
    /// # Errors
    ///
    /// - [`ValidationError`] if the text is not an `http://` or `https://`
    ///   URL every parser reads the same way.
    /// - [`ValidationError`] if it is longer than 2048 bytes.
    /// - [`ValidationError`] if it carries credentials.
    pub fn new(value: impl Into<String>) -> Result<Self, ValidationError> {
        let text = value.into();
        let parsed = web_url::parse("url", &text, web_url::WEB)?;
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

    /// The port the URL names, or 443 for HTTPS and 80 for HTTP when it
    /// names none.
    ///
    /// Most URLs are written without a port. A caller that builds an address
    /// does not have to work out the scheme's default itself.
    #[must_use]
    pub fn port(&self) -> u16 {
        let default = if self.is_https() { 443 } else { 80 };
        self.parsed.port().unwrap_or(default)
    }

    /// Whether this URL uses HTTPS.
    #[must_use]
    pub fn is_https(&self) -> bool {
        self.parsed.scheme() == "https"
    }
}

impl fmt::Display for HttpUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `https://api.internal:8080` is accepted, kept as written and reports
    /// HTTPS.
    #[test]
    fn https_addresses_keep_their_scheme() {
        let url = HttpUrl::new("https://api.internal:8080").unwrap();
        assert_eq!(url.as_str(), "https://api.internal:8080");
        assert!(url.is_https());
    }

    /// Plain `http://localhost:3000` is accepted for an internal upstream
    /// and reports that it is not HTTPS.
    #[test]
    fn http_addresses_report_no_tls() {
        let url = HttpUrl::new("http://localhost:3000").unwrap();
        assert!(!url.is_https());
    }

    /// An empty destination is refused as an HTTP endpoint.
    #[test]
    fn an_empty_web_address_is_refused() {
        assert!(HttpUrl::new("").is_err());
    }

    /// An `ftp://` URL arriving as JSON is refused, as it would be in code.
    /// An `https://` one loads.
    #[cfg(feature = "serde")]
    #[test]
    fn a_url_read_from_json_is_held_to_the_same_rules() {
        assert!(serde_json::from_str::<HttpUrl>("\"ftp://files.example.com\"").is_err());
        assert!(serde_json::from_str::<HttpUrl>("\"https://api.example.com\"").is_ok());
    }

    /// `ftp://files.internal` is refused. Only HTTP and HTTPS are allowed.
    #[test]
    fn ftp_addresses_are_refused() {
        assert!(HttpUrl::new("ftp://files.internal").is_err());
    }

    /// `api.internal:8080` with no scheme is refused.
    #[test]
    fn rejects_no_scheme() {
        assert!(HttpUrl::new("api.internal:8080").is_err());
    }

    /// A host with a NUL byte inside it is refused.
    #[test]
    fn rejects_control_chars() {
        assert!(HttpUrl::new("https://api\x00.internal").is_err());
    }

    /// `http://orders:8080` reports port 8080, and a URL with a path after
    /// `:9443` reports 9443.
    #[test]
    fn a_url_with_a_port_reports_it() {
        assert_eq!(HttpUrl::new("http://orders:8080").unwrap().port(), 8080);
        assert_eq!(
            HttpUrl::new("https://orders.internal:9443/health")
                .unwrap()
                .port(),
            9443
        );
    }

    /// A URL with no port reports 80 for HTTP and 443 for HTTPS, with or
    /// without a path.
    #[test]
    fn a_url_without_a_port_reports_the_schemes_default() {
        assert_eq!(HttpUrl::new("http://orders.internal").unwrap().port(), 80);
        assert_eq!(HttpUrl::new("https://orders.internal").unwrap().port(), 443);
        assert_eq!(
            HttpUrl::new("https://orders.internal/deep/path")
                .unwrap()
                .port(),
            443
        );
    }

    /// `http://[2001:db8::1]:8080` reports port 8080, and the same host with
    /// no port reports 80. The colons inside the brackets are never read as
    /// a port.
    #[test]
    fn an_ipv6_host_does_not_have_its_address_read_as_a_port() {
        assert_eq!(
            HttpUrl::new("http://[2001:db8::1]:8080").unwrap().port(),
            8080
        );
        assert_eq!(HttpUrl::new("http://[2001:db8::1]").unwrap().port(), 80);
    }

    /// `http://api.internal:8080/v1` prints exactly as given, not in a
    /// normalised form. The proxy dials what it prints.
    #[test]
    fn renders_as_the_url_it_was_built_from() {
        let url = HttpUrl::new("http://api.internal:8080/v1").unwrap();

        assert_eq!(url.to_string(), "http://api.internal:8080/v1");
    }

    /// Numeric or abbreviated addresses, backslashes, credentials and missing
    /// or space-containing hosts are refused before an HTTP client reads them.
    #[test]
    fn rejects_a_host_written_as_a_number_or_hidden_behind_a_backslash() {
        for url in [
            "http://2130706433/",
            "http://127.1/",
            "http://10.0.0.1\\@api.internal/",
            "http://user@api.internal/",
            "http://",
            "http://api internal/",
        ] {
            assert!(HttpUrl::new(url).is_err(), "{url} was accepted");
        }
    }

    /// An IPv4 address in dotted form and a bracketed IPv6 address are both
    /// accepted as hosts.
    #[test]
    fn accepts_an_ip_written_the_ordinary_way() {
        assert!(HttpUrl::new("http://10.0.0.1:8080/health").is_ok());
        assert!(HttpUrl::new("http://[fd00::1]:8080/").is_ok());
    }
}
