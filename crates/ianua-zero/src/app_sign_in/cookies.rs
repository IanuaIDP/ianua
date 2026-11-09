//! The cookies the gateway sets on an app's host when someone signs in there.
//!
//! A device the person asks to remember on the second-factor page gets a
//! cookie of its own, holding a fresh secret the gateway makes; the API
//! keeps only its digest, bound to this host.
//!
//! Every one is `__Host-`: the browser takes it only over HTTPS, only with
//! `Path=/`, and never with a `Domain`, so a sibling subdomain cannot set one
//! for this host and a cookie this host sets reaches no other. Their names
//! are the request layer's, which strips every one of them from what it
//! forwards, so none ever reaches the app.

use http::HeaderMap;
use http::header::HeaderValue;
use ianua_domain::shared::clock;

use crate::request::{
    APP_CHALLENGE_COOKIE, APP_CSRF_COOKIE, APP_DEVICE_COOKIE, APP_HOP_COOKIE, APP_SESSION_COOKIE,
    APP_SINGLE_SIGN_ON_COOKIE, CookieRead, read_cookie,
};

/// How long the browser keeps a remembered device's cookie, in seconds: a
/// year, the longest a device may be trusted. Whether it still counts is
/// the API's to decide on each sign-in, by the tenant's trust window.
const DEVICE_LIFETIME_SECS: i64 = 365 * 86_400;

/// How long a single sign-on may stay at the outside identity provider, in
/// seconds, before the browser must start again.
const SINGLE_SIGN_ON_LIFETIME_SECS: i64 = 600;

/// How long a hop's browser value is kept, in seconds: one round trip to the
/// owner's host and back, with room to spare.
const HOP_LIFETIME_SECS: i64 = 300;

/// A named cookie's value, when the request carries exactly one under that
/// name. Two of a name, or a `Cookie` field that cannot be read, is none:
/// a cookie a sibling host planted must never decide which is read.
#[must_use]
pub(super) fn read(headers: &HeaderMap, name: &str) -> Option<String> {
    match read_cookie(headers, name) {
        CookieRead::One(value) if !value.is_empty() => Some(value.to_owned()),
        CookieRead::One(_) | CookieRead::Absent | CookieRead::Ambiguous => None,
    }
}

/// The session cookie's token.
#[must_use]
pub(super) fn session_of(headers: &HeaderMap) -> Option<String> {
    read(headers, APP_SESSION_COOKIE)
}

/// The challenge cookie's token.
#[must_use]
pub(super) fn challenge_of(headers: &HeaderMap) -> Option<String> {
    read(headers, APP_CHALLENGE_COOKIE)
}

/// The value the browser keeps for a hop on this host.
#[must_use]
pub(super) fn hop_value_of(headers: &HeaderMap) -> Option<String> {
    read(headers, APP_HOP_COOKIE)
}

/// The secret of the device the browser remembered on this host.
#[must_use]
pub(super) fn device_of(headers: &HeaderMap) -> Option<String> {
    read(headers, APP_DEVICE_COOKIE)
}

/// Sets the cookie holding the secret of the device just remembered on
/// this host. `HttpOnly`, so page scripts never see it, and `SameSite=Lax`,
/// so another site's form never sends it.
#[must_use]
pub(super) fn device(secret: &str) -> Option<HeaderValue> {
    set(
        APP_DEVICE_COOKIE,
        secret,
        DEVICE_LIFETIME_SECS,
        Reach::SameSiteServer,
    )
}

/// A fresh secret for a device to remember: 32 random bytes as the 64 hex
/// digits the API takes.
#[must_use]
pub(super) fn fresh_device_secret() -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let bytes: [u8; 32] = rand::random();
    let mut secret = String::with_capacity(64);
    for byte in bytes {
        secret.push(char::from(DIGITS[usize::from(byte >> 4)]));
        secret.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    secret
}

/// Sets the session cookie, lapsing with the token at `expires_at`, in Unix
/// seconds. `HttpOnly`, so page scripts never see it.
#[must_use]
pub(super) fn session(token: &str, expires_at: i64) -> Option<HeaderValue> {
    set(
        APP_SESSION_COOKIE,
        token,
        lasting_until(expires_at),
        Reach::SameSiteServer,
    )
}

/// Sets the double-submit CSRF cookie, lapsing with the session it guards.
/// Readable by the page on purpose: its scripts echo it in a header on
/// requests that change something.
#[must_use]
pub(super) fn csrf(value: &str, expires_at: i64) -> Option<HeaderValue> {
    set(
        APP_CSRF_COOKIE,
        value,
        lasting_until(expires_at),
        Reach::SameSiteScripts,
    )
}

/// Sets the challenge cookie, lapsing with the challenge. `HttpOnly`.
#[must_use]
pub(super) fn challenge(token: &str, expires_at: i64) -> Option<HeaderValue> {
    set(
        APP_CHALLENGE_COOKIE,
        token,
        lasting_until(expires_at),
        Reach::SameSiteServer,
    )
}

/// Sets the value a browser keeps for a hop on this host. `HttpOnly`, and
/// sent on the top-level navigation that brings the browser back from the
/// owner's host, which `SameSite=Lax` allows.
#[must_use]
pub(super) fn hop(value: &str) -> Option<HeaderValue> {
    set(
        APP_HOP_COOKIE,
        value,
        HOP_LIFETIME_SECS,
        Reach::SameSiteServer,
    )
}

/// Sets the single sign-on cookie.
///
/// It is sent from any site, unlike the others: a SAML provider sends the
/// browser back with a cross-site `POST`, which carries no `SameSite=Lax`
/// cookie, and the way back is refused without it. It holds only the
/// secrets of this one sign-on, which the provider's answer is checked
/// against, never a session.
#[must_use]
pub(super) fn single_sign_on(kept: &KeptSignOn) -> Option<HeaderValue> {
    set(
        APP_SINGLE_SIGN_ON_COOKIE,
        &kept.encoded(),
        SINGLE_SIGN_ON_LIFETIME_SECS,
        Reach::CrossSiteServer,
    )
}

/// Clears `name`.
#[must_use]
pub(super) fn cleared(name: &str) -> Option<HeaderValue> {
    HeaderValue::from_str(&format!(
        "{name}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0"
    ))
    .ok()
}

/// The single sign-on kept while the browser is away, read from its cookie.
#[must_use]
pub(super) fn kept_sign_on(headers: &HeaderMap) -> Option<KeptSignOn> {
    KeptSignOn::decoded(&read(headers, APP_SINGLE_SIGN_ON_COOKIE)?)
}

/// What a single sign-on keeps on the browser until it comes back. Holds two
/// secrets, so it has no `Debug`.
pub(super) struct KeptSignOn {
    /// The secret the provider's answer is accepted only with.
    pub(super) binding: String,
    /// The secret the session is handed back against.
    pub(super) hand_back: String,
    /// Where to send the person once they are in.
    pub(super) return_to: Option<String>,
}

impl KeptSignOn {
    fn encoded(&self) -> String {
        let mut encoded = url::form_urlencoded::Serializer::new(String::new());
        encoded.append_pair("b", &self.binding);
        encoded.append_pair("h", &self.hand_back);
        if let Some(return_to) = &self.return_to {
            encoded.append_pair("r", return_to);
        }
        encoded.finish()
    }

    fn decoded(value: &str) -> Option<Self> {
        let mut binding = None;
        let mut hand_back = None;
        let mut return_to = None;
        for (key, value) in url::form_urlencoded::parse(value.as_bytes()) {
            let slot = match key.as_ref() {
                "b" => &mut binding,
                "h" => &mut hand_back,
                "r" => &mut return_to,
                _ => continue,
            };
            *slot = Some(value.into_owned());
        }
        Some(Self {
            binding: binding.filter(|value| !value.is_empty())?,
            hand_back: hand_back.filter(|value| !value.is_empty())?,
            return_to,
        })
    }
}

/// Who can read a cookie and which site's requests may carry it.
#[derive(Clone, Copy)]
enum Reach {
    SameSiteServer,
    SameSiteScripts,
    CrossSiteServer,
}

fn lasting_until(expires_at: i64) -> i64 {
    expires_at.saturating_sub(clock::now().unix_timestamp())
}

/// The `Set-Cookie` value, or `None` for a value that is not made of cookie
/// characters alone: one holding `;` would add attributes of its own.
fn set(name: &str, value: &str, max_age: i64, reach: Reach) -> Option<HeaderValue> {
    if value.is_empty() || !value.bytes().all(is_cookie_octet) {
        return None;
    }
    let (http_only, same_site) = match reach {
        Reach::SameSiteServer => ("; HttpOnly", "Lax"),
        Reach::SameSiteScripts => ("", "Lax"),
        Reach::CrossSiteServer => ("; HttpOnly", "None"),
    };
    let max_age = max_age.max(0);
    HeaderValue::from_str(&format!(
        "{name}={value}; Path=/; Secure{http_only}; SameSite={same_site}; Max-Age={max_age}"
    ))
    .ok()
}

/// A byte a cookie value may hold, as RFC 6265 lists them.
fn is_cookie_octet(byte: u8) -> bool {
    matches!(byte, 0x21 | 0x23..=0x2B | 0x2D..=0x3A | 0x3C..=0x5B | 0x5D..=0x7E)
}

#[cfg(test)]
mod tests {
    use http::header::COOKIE;

    use super::*;

    fn later() -> i64 {
        clock::now().unix_timestamp() + 3600
    }

    fn text(value: Option<HeaderValue>) -> String {
        value.unwrap().to_str().unwrap().to_owned()
    }

    fn sent(fields: &[&str]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for field in fields {
            headers.append(COOKIE, HeaderValue::from_str(field).unwrap());
        }
        headers
    }

    #[test]
    fn the_session_cookie_is_host_bound_secure_lax_and_hidden_from_scripts() {
        let value = text(session("tok", later()));

        assert!(value.starts_with("__Host-ianua_app=tok;"));
        for part in ["Path=/", "Secure", "HttpOnly", "SameSite=Lax"] {
            assert!(value.contains(part), "{part} missing from {value}");
        }
        assert!(!value.contains("Domain"));
    }

    #[test]
    fn the_challenge_cookie_is_hidden_from_scripts() {
        let value = text(challenge("chal", later()));

        assert!(value.starts_with("__Host-ianua_mfa=chal;"));
        assert!(value.contains("HttpOnly"));
        assert!(value.contains("SameSite=Lax"));
    }

    /// The hop's value is the browser's own proof that it asked for the
    /// code: hidden from scripts, bound to this host, and short-lived.
    #[test]
    fn the_hop_cookie_is_host_bound_hidden_from_scripts_and_short_lived() {
        let value = text(hop("v4lue"));

        assert!(value.starts_with("__Host-ianua_hop=v4lue;"));
        for part in [
            "Path=/",
            "Secure",
            "HttpOnly",
            "SameSite=Lax",
            "Max-Age=300",
        ] {
            assert!(value.contains(part), "{part} missing from {value}");
        }
        assert!(!value.contains("Domain"));
    }

    /// A remembered device's cookie is bound to this host, hidden from
    /// scripts, never sent by another site's form, and kept for a year.
    #[test]
    fn the_device_cookie_is_host_bound_hidden_from_scripts_and_lax() {
        let value = text(device(&fresh_device_secret()));

        assert!(value.starts_with("__Host-ianua_device="));
        for part in [
            "Path=/",
            "Secure",
            "HttpOnly",
            "SameSite=Lax",
            "Max-Age=31536000",
        ] {
            assert!(value.contains(part), "{part} missing from {value}");
        }
        assert!(!value.contains("Domain"));
    }

    /// A fresh device secret is 64 hex digits, and never the same twice.
    #[test]
    fn a_fresh_device_secret_is_64_hex_digits_and_new_each_time() {
        let first = fresh_device_secret();

        assert_eq!(first.len(), 64);
        assert!(first.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_ne!(first, fresh_device_secret());
    }

    /// Two device cookies with different values yield no device secret.
    #[test]
    fn a_device_cookie_sent_twice_is_not_read() {
        let headers = sent(&["__Host-ianua_device=aa", "__Host-ianua_device=bb"]);

        assert_eq!(device_of(&headers), None);
    }

    /// Page scripts echo the CSRF value back, so they must be able to read it.
    #[test]
    fn the_csrf_cookie_is_readable_by_the_page() {
        assert!(!text(csrf("abc", later())).contains("HttpOnly"));
    }

    /// A SAML provider posts the browser back from its own site; a `Lax`
    /// cookie would stay behind and the way back would always be refused.
    #[test]
    fn the_single_sign_on_cookie_is_sent_from_any_site_and_hidden_from_scripts() {
        let value = text(single_sign_on(&KeptSignOn {
            binding: "bind".to_owned(),
            hand_back: "back".to_owned(),
            return_to: Some("/orders?id=1".to_owned()),
        }));

        assert!(value.starts_with("__Host-ianua_sso="));
        for part in ["Path=/", "Secure", "HttpOnly", "SameSite=None"] {
            assert!(value.contains(part), "{part} missing from {value}");
        }
    }

    #[test]
    fn a_kept_sign_on_reads_back_as_it_was_written() {
        let kept = KeptSignOn {
            binding: "b&=1".to_owned(),
            hand_back: "h;2".to_owned(),
            return_to: Some("/orders?id=1&x=y".to_owned()),
        };
        let headers = sent(&[&format!("{APP_SINGLE_SIGN_ON_COOKIE}={}", kept.encoded())]);

        let read = kept_sign_on(&headers).unwrap();

        assert_eq!(read.binding, "b&=1");
        assert_eq!(read.hand_back, "h;2");
        assert_eq!(read.return_to.as_deref(), Some("/orders?id=1&x=y"));
    }

    #[test]
    fn a_kept_sign_on_without_both_secrets_is_none() {
        assert!(KeptSignOn::decoded("b=only").is_none());
        assert!(KeptSignOn::decoded("b=&h=x").is_none());
    }

    /// A value holding `;` would set attributes of its own, such as a
    /// `Domain` reaching every sibling host.
    #[test]
    fn a_value_that_is_not_cookie_characters_sets_no_cookie() {
        for value in [
            "bad\nvalue",
            "tok; Domain=example.com",
            "a b",
            "",
            "a,b",
            "a\"b",
        ] {
            assert!(session(value, later()).is_none(), "{value:?}");
        }
    }

    #[test]
    fn a_lapsed_token_sets_a_cookie_that_lapses_at_once() {
        assert!(text(session("tok", 0)).ends_with("Max-Age=0"));
    }

    #[test]
    fn a_cookie_is_read_from_any_cookie_header() {
        let headers = sent(&["a=1", "__Host-ianua_app=tok; b=2"]);

        assert_eq!(session_of(&headers).as_deref(), Some("tok"));
        assert_eq!(challenge_of(&headers), None);
    }

    /// Two session cookies with different values yield no session token.
    #[test]
    fn a_cookie_sent_twice_is_not_read() {
        let headers = sent(&["__Host-ianua_app=ann", "__Host-ianua_app=eve"]);

        assert_eq!(session_of(&headers), None);
    }
}
