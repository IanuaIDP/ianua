use std::fmt;

use crate::message;
use crate::shared::security::ssrf::{is_blocked_ip, is_never_public};
use crate::shared::validation::{UrlHost, ValidationError};
use crate::types::{HttpsUrl, UrlOrigin};

/// An HTTPS endpoint on the public internet that the platform calls out to,
/// such as a webhook target or a security signal receiver.
///
/// A tenant names it and the platform sends requests to it from inside the
/// deployment. So on top of the [`HttpsUrl`] rules, its host must be one only
/// the public internet can answer for. Refused are:
/// - `localhost` and any name under `.localhost`
/// - names under `.local`, `.internal`, `.lan`, `.home.arpa`, `.svc` and
///   `.cluster.local`
/// - a single-label name such as `billing` or `db`, which only a local
///   resolver can answer
/// - IP literals in the loopback, private, link-local, unique-local,
///   unspecified and other internal ranges, in IPv4 and IPv6
///
/// This is a check on what the tenant wrote, not on where it leads. A public
/// name can still resolve to an internal address, or change to one after it
/// was saved. So the outbound adapter checks every resolved address again
/// before it connects, and this type does not replace that check.
///
/// `Debug` shows only the origin, as [`HttpsUrl`] does, since the path or
/// query often carries the endpoint's secret.
#[derive(Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "String", into = "String"))]
pub struct PublicHttpsUrl(HttpsUrl);

impl PublicHttpsUrl {
    /// Checks and wraps an HTTPS URL on the public internet.
    ///
    /// # Errors
    ///
    /// - [`ValidationError`] for anything [`HttpsUrl::new`] refuses.
    /// - [`ValidationError`] if the host is `localhost`, a single label, a
    ///   name under a suffix kept for internal networks, or an internal IP
    ///   address.
    pub fn new(value: impl Into<String>) -> Result<Self, ValidationError> {
        let url = HttpsUrl::new(value)?;
        ensure_public(url.host())?;
        Ok(Self(url))
    }

    /// The URL as it was written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    /// The same URL as a plain [`HttpsUrl`].
    #[must_use]
    pub fn as_https(&self) -> &HttpsUrl {
        &self.0
    }

    /// Where the URL points, as the HTTP client will read it.
    #[must_use]
    pub fn host(&self) -> UrlHost<'_> {
        self.0.host()
    }

    /// Where the URL points, without anything after the host and port.
    #[must_use]
    pub fn origin(&self) -> UrlOrigin {
        self.0.origin()
    }
}

/// Refuses a host only an internal network can answer for.
fn ensure_public(host: UrlHost<'_>) -> Result<(), ValidationError> {
    let internal = match host {
        UrlHost::Address(ip) => is_blocked_ip(ip),
        UrlHost::Name(name) => is_never_public(name),
    };
    if !internal {
        return Ok(());
    }
    Err(ValidationError::Custom {
        field: "url",
        code: "not_public".to_owned(),
        message: message!(
            "values-the-endpoint-must-be-on-the",
            "the endpoint must be on the public internet, not a local or internal host."
        ),
    })
}

impl TryFrom<String> for PublicHttpsUrl {
    type Error = ValidationError;

    /// Goes through [`PublicHttpsUrl::new`], so a value that arrives as JSON
    /// is held to the same rules as one built in code.
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<PublicHttpsUrl> for String {
    fn from(url: PublicHttpsUrl) -> Self {
        url.0.into()
    }
}

impl From<PublicHttpsUrl> for HttpsUrl {
    fn from(url: PublicHttpsUrl) -> Self {
        url.0
    }
}

impl fmt::Debug for PublicHttpsUrl {
    /// The origin only, through [`HttpsUrl`]'s own redacting `Debug`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("PublicHttpsUrl").field(&self.0).finish()
    }
}

impl fmt::Display for PublicHttpsUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Localhost destinations are refused with explicit ports, uppercase or
    /// trailing-dot spelling, and names beneath the localhost suffix.
    #[test]
    fn localhost_in_any_spelling_is_refused() {
        for url in [
            "https://localhost/admin",
            "https://localhost:8443/admin",
            "https://LOCALHOST./admin",
            "https://api.localhost/admin",
        ] {
            assert!(PublicHttpsUrl::new(url).is_err(), "{url} was accepted");
        }
    }

    /// Names under internal network suffixes are refused as public endpoints,
    /// including metadata, local devices and cluster services.
    #[test]
    fn names_under_internal_suffixes_are_refused() {
        for url in [
            "https://metadata.google.internal/computeMetadata/v1/",
            "https://printer.local/",
            "https://nas.lan/",
            "https://router.home.arpa/",
            "https://db.svc.cluster.local/",
        ] {
            assert!(PublicHttpsUrl::new(url).is_err(), "{url} was accepted");
        }
    }

    /// Single-label destinations are refused with or without a trailing dot.
    #[test]
    fn a_single_label_host_is_refused() {
        assert!(PublicHttpsUrl::new("https://billing/hook").is_err());
        assert!(PublicHttpsUrl::new("https://billing./hook").is_err());
    }

    /// Internal IPv4 and IPv6 address literals are refused, including mapped
    /// IPv4 loopback, link-local and unspecified destinations.
    #[test]
    fn internal_ip_literals_are_refused() {
        for url in [
            "https://127.0.0.1/hook",
            "https://10.0.0.5/hook",
            "https://172.16.0.1/hook",
            "https://192.168.1.1/hook",
            "https://169.254.169.254/latest",
            "https://0.0.0.0/hook",
            "https://[::1]/hook",
            "https://[fd00::1]/hook",
            "https://[fe80::1]/hook",
            "https://[::]/hook",
            "https://[::ffff:127.0.0.1]/hook",
        ] {
            assert!(PublicHttpsUrl::new(url).is_err(), "{url} was accepted");
        }
    }

    /// A public host name and a public address are accepted and kept as
    /// written.
    #[test]
    fn a_public_endpoint_is_accepted() {
        let url = PublicHttpsUrl::new("https://hooks.acme.com/events?token=abc").unwrap();

        assert_eq!(url.as_str(), "https://hooks.acme.com/events?token=abc");
        assert!(PublicHttpsUrl::new("https://93.184.216.34/hook").is_ok());
    }

    /// JSON deserialization refuses a localhost endpoint just as construction
    /// from text does.
    #[cfg(feature = "serde")]
    #[test]
    fn deserializing_refuses_an_internal_host_too() {
        let result = serde_json::from_str::<PublicHttpsUrl>(r#""https://localhost/hook""#);

        assert!(result.is_err());
    }

    /// A webhook URL with a secret path prints in a debug log as its origin
    /// and `<redacted>`, so the secret never reaches the log.
    #[test]
    fn debug_shows_the_origin_but_not_a_secret_path() {
        let url = PublicHttpsUrl::new("https://hooks.acme.com/services/T0/B0/XXXX").unwrap();

        let shown = format!("{url:?}");

        assert!(!shown.contains("XXXX"));
        assert!(shown.contains("https://hooks.acme.com"));
    }
}
