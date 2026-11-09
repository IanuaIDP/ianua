use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

use url::{Host, Url};

use crate::shared::validation::ValidationError;
use crate::types::HttpsUrl;

/// The longest redirect URI taken, as for any URL.
const MAX_LEN: usize = 2048;

/// Schemes an app may not claim as its own: they belong to the web, or run
/// what follows them.
const RESERVED_SCHEMES: [&str; 6] = ["http", "https", "javascript", "data", "file", "vbscript"];

/// Where an authorization server may send a client's answer.
///
/// Three kinds, as OAuth for native apps (RFC 8252) sets out:
/// - A web address, `https://`, held to [`HttpsUrl`]'s rules.
/// - A loopback address, `http://127.0.0.1` or `http://[::1]`, for a desktop
///   app or a CLI that listens on a port of its own choosing. The port is
///   not compared (RFC 8252 7.3). `localhost` is refused: a name can be
///   pointed elsewhere, an address cannot (RFC 8252 8.3).
/// - An app's own scheme in reverse-domain form, such as
///   `com.acme.app:/callback` (RFC 8252 7.1). The dot keeps an app from
///   claiming a short scheme another app might also register.
///
/// None carries a fragment: the answer is added to the query, and a
/// fragment would be dropped or leak it (RFC 6749 3.1.2).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "String", into = "String"))]
pub struct RedirectUri {
    text: String,
    kind: RedirectKind,
}

/// Which kind of redirect a [`RedirectUri`] is.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum RedirectKind {
    /// A web address.
    Web,
    /// A loopback address, kept also without its port for matching.
    Loopback {
        /// The address with its port taken out.
        portless: String,
    },
    /// An app's own scheme.
    App,
}

impl TryFrom<String> for RedirectUri {
    type Error = ValidationError;

    /// Goes through [`RedirectUri::new`].
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<RedirectUri> for String {
    fn from(uri: RedirectUri) -> Self {
        uri.text
    }
}

impl From<HttpsUrl> for RedirectUri {
    fn from(url: HttpsUrl) -> Self {
        Self {
            text: url.as_str().to_owned(),
            kind: RedirectKind::Web,
        }
    }
}

impl RedirectUri {
    /// Checks and wraps a redirect URI.
    ///
    /// # Errors
    ///
    /// - [`ValidationError`] if it is not a URL, is longer than 2048 bytes,
    ///   or carries a fragment.
    /// - [`ValidationError`] if an `https://` address breaks [`HttpsUrl`]'s
    ///   rules.
    /// - [`ValidationError`] if an `http://` address is not `127.0.0.1` or
    ///   `[::1]`.
    /// - [`ValidationError`] if any other scheme is reserved, or not in
    ///   reverse-domain form.
    pub fn new(value: impl Into<String>) -> Result<Self, ValidationError> {
        let text = value.into();
        if text.len() > MAX_LEN {
            return Err(invalid("a redirect URI is at most 2048 bytes"));
        }
        let parsed = Url::parse(&text).map_err(|_| invalid("a redirect URI must be a URL"))?;
        if parsed.fragment().is_some() {
            return Err(invalid("a redirect URI carries no fragment"));
        }
        let kind = kind_of(&text, &parsed)?;
        Ok(Self { text, kind })
    }

    /// The URI as it was written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// Whether `presented`, from a request, is this registered redirect.
    ///
    /// It must be the same, character for character, except that a
    /// loopback address may name any port: the app picks a free one each
    /// time it runs.
    #[must_use]
    pub fn accepts(&self, presented: &Self) -> bool {
        match (&self.kind, &presented.kind) {
            (
                RedirectKind::Loopback {
                    portless: registered,
                },
                RedirectKind::Loopback { portless: asked },
            ) => registered == asked,
            _ => self.text == presented.text,
        }
    }
}

/// What kind of redirect `parsed` is, or why it is refused.
fn kind_of(text: &str, parsed: &Url) -> Result<RedirectKind, ValidationError> {
    match parsed.scheme() {
        "https" => HttpsUrl::new(text).map(|_| RedirectKind::Web),
        "http" => loopback(parsed),
        scheme => app_scheme(scheme).map(|()| RedirectKind::App),
    }
}

/// A loopback address, or why an `http://` redirect is refused.
fn loopback(parsed: &Url) -> Result<RedirectKind, ValidationError> {
    let is_loopback = match parsed.host() {
        Some(Host::Ipv4(ip)) => ip == Ipv4Addr::LOCALHOST,
        Some(Host::Ipv6(ip)) => ip == Ipv6Addr::LOCALHOST,
        Some(Host::Domain(_)) | None => false,
    };
    if !is_loopback {
        return Err(invalid(
            "an http redirect URI must be the loopback address 127.0.0.1 or [::1]",
        ));
    }
    let mut portless = parsed.clone();
    portless
        .set_port(None)
        .map_err(|()| invalid("a redirect URI must be a URL"))?;
    Ok(RedirectKind::Loopback {
        portless: portless.into(),
    })
}

/// Refuses an app scheme that is reserved, or not in reverse-domain form.
fn app_scheme(scheme: &str) -> Result<(), ValidationError> {
    if RESERVED_SCHEMES.contains(&scheme) {
        return Err(invalid("this scheme cannot be a redirect URI"));
    }
    if !scheme.contains('.') {
        return Err(invalid(
            "an app's redirect URI scheme is a reversed domain, such as com.acme.app",
        ));
    }
    Ok(())
}

/// A refused redirect URI.
fn invalid(message: &str) -> ValidationError {
    ValidationError::Custom {
        field: "redirect_uri",
        code: "invalid_redirect_uri".to_owned(),
        message: message.into(),
    }
}

impl fmt::Display for RedirectUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    /// The redirect `text` stands for.
    fn uri(text: &str) -> RedirectUri {
        RedirectUri::new(text).unwrap()
    }

    /// A web app's address, a CLI's loopback address and a mobile app's own
    /// scheme are all redirects.
    #[test]
    fn each_kind_of_redirect_is_taken() {
        for text in [
            "https://app.acme.com/callback",
            "http://127.0.0.1/callback",
            "http://[::1]:8080/cb",
            "com.acme.app:/callback",
        ] {
            assert!(RedirectUri::new(text).is_ok(), "{text}");
        }
    }

    /// Redirects using remote plain HTTP, localhost names, short or executable
    /// schemes, fragments or malformed URL text are refused at registration.
    #[test]
    fn unsafe_redirects_are_refused() {
        for text in [
            "http://evil.test/cb",
            "http://localhost:8080/cb",
            "myapp:/cb",
            "javascript:alert(1)",
            "https://app.acme.com/cb#frag",
            "not a url",
        ] {
            assert!(RedirectUri::new(text).is_err(), "{text}");
        }
    }

    /// A CLI registered `http://127.0.0.1/callback` and listens on whatever
    /// port is free. Any port is accepted.
    #[test]
    fn a_loopback_redirect_accepts_any_port() {
        let registered = uri("http://127.0.0.1/callback");

        assert!(registered.accepts(&uri("http://127.0.0.1:53124/callback")));
        assert!(!registered.accepts(&uri("http://127.0.0.1:53124/other")));
    }

    /// A web redirect must match exactly, port and path included.
    #[test]
    fn a_web_redirect_must_match_exactly() {
        let registered = uri("https://app.acme.com/callback");

        assert!(registered.accepts(&uri("https://app.acme.com/callback")));
        assert!(!registered.accepts(&uri("https://app.acme.com:8443/callback")));
        assert!(!registered.accepts(&uri("https://app.acme.com/callback?x=1")));
    }

    proptest! {
        /// Whatever the text, a redirect that is taken never carries a
        /// fragment, and always reads back as written.
        #[test]
        fn a_taken_redirect_reads_back_and_has_no_fragment(text in "\\PC{0,80}") {
            if let Ok(redirect) = RedirectUri::new(text.clone()) {
                prop_assert_eq!(redirect.as_str(), text.as_str());
                prop_assert!(!text.contains('#'));
            }
        }
    }
}
