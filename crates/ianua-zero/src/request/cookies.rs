//! The platform's cookies and the CSRF header: their names, and reading
//! one from a request.
//!
//! These names are the gateway's one list. The app sign-in sets the
//! `__Host-` cookies, the identity step reads them, and forwarding strips
//! every one of them, so all three use the names here.

use http::HeaderMap;
use http::header::COOKIE;

/// The session cookie on a host without app sign-in, carrying a token the
/// tenant signed.
pub(crate) const SESSION_COOKIE: &str = "ianua_session";

/// The double-submit CSRF cookie beside [`SESSION_COOKIE`].
pub(crate) const CSRF_COOKIE: &str = "ianua_csrf";

/// The app session cookie on a host with app sign-in. `__Host-`, so only
/// this host sets it, over HTTPS, and no sibling subdomain can plant one.
pub(crate) const APP_SESSION_COOKIE: &str = "__Host-ianua_app";

/// The double-submit CSRF cookie beside [`APP_SESSION_COOKIE`].
pub(crate) const APP_CSRF_COOKIE: &str = "__Host-ianua_csrf";

/// The challenge cookie of a sign-in not finished yet on a host with app
/// sign-in: a second factor, a confirmation from the mailbox, or a password
/// that must change.
pub(crate) const APP_CHALLENGE_COOKIE: &str = "__Host-ianua_mfa";

/// What a single sign-on keeps on a host with app sign-in while the browser
/// is at the outside identity provider.
pub(crate) const APP_SINGLE_SIGN_ON_COOKIE: &str = "__Host-ianua_sso";

/// The value a browser keeps on a host of a service's own cookie while a
/// hop sets the session there: the hop's code works only beside it.
pub(crate) const APP_HOP_COOKIE: &str = "__Host-ianua_hop";

/// The secret of a device the browser remembered on a host with app
/// sign-in. `__Host-`, so it is good on this host alone: a device
/// remembered here counts nowhere else, and the API binds its digest to
/// this host too.
pub(crate) const APP_DEVICE_COOKIE: &str = "__Host-ianua_device";

/// The header a page echoes the CSRF cookie's value in.
///
/// Not under `x-ianua-`: that family is the proxy's own and is stripped
/// before anything reads the request, so an echo sent under it would never
/// be seen.
pub(crate) const CSRF_HEADER: &str = "ianua-csrf-token";

/// Whether a cookie is the platform's rather than the app's.
///
/// None of them is ever forwarded. Every name the platform might use is
/// covered, not only the ones above, so a cookie added later is never
/// passed on by default.
#[must_use]
pub(crate) fn is_platform_cookie(name: &str) -> bool {
    name.starts_with("ianua_")
        || name.starts_with("__Host-ianua_")
        || name.starts_with("__Secure-ianua_")
}

/// What a request carries under one cookie name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CookieRead<'a> {
    /// No such cookie.
    Absent,
    /// Exactly one, with this value.
    One(&'a str),
    /// More than one, or a `Cookie` field the gateway cannot read and so
    /// cannot rule out holding one.
    Ambiguous,
}

/// The cookie `name` in `headers`, across every `Cookie` field.
///
/// A name sent twice is ambiguous, not "the first one": a cookie planted by
/// a sibling host would otherwise decide which session is read.
pub(crate) fn read<'a>(headers: &'a HeaderMap, name: &str) -> CookieRead<'a> {
    let mut found = CookieRead::Absent;
    for field in headers.get_all(COOKIE) {
        let Ok(text) = std::str::from_utf8(field.as_bytes()) else {
            return CookieRead::Ambiguous;
        };
        for value in values_named(text, name) {
            if found != CookieRead::Absent {
                return CookieRead::Ambiguous;
            }
            found = CookieRead::One(value);
        }
    }
    found
}

/// Every cookie named `name` in one `Cookie` field, in order.
fn values_named<'f>(field: &'f str, name: &str) -> impl Iterator<Item = &'f str> {
    field
        .split(';')
        .filter_map(|pair| pair.split_once('='))
        .filter(move |(sent, _)| sent.trim() == name)
        .map(|(_, value)| value.trim())
}

#[cfg(test)]
mod tests {
    use http::HeaderValue;
    use proptest::prelude::*;

    use super::*;

    fn cookies(fields: &[&str]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for field in fields {
            map.append(COOKIE, HeaderValue::from_str(field).unwrap());
        }
        map
    }

    #[test]
    fn a_cookie_sent_once_is_read() {
        let map = cookies(&["theme=dark; ianua_session=aaa.bbb.ccc"]);

        assert_eq!(read(&map, SESSION_COOKIE), CookieRead::One("aaa.bbb.ccc"));
        assert_eq!(read(&map, CSRF_COOKIE), CookieRead::Absent);
    }

    /// Duplicate session cookies are ambiguous whether they share a Cookie
    /// field or arrive in separate fields.
    #[test]
    fn a_cookie_sent_twice_is_ambiguous() {
        let same_field = cookies(&["ianua_session=a; ianua_session=b"]);
        let two_fields = cookies(&["ianua_session=a", "ianua_session=b"]);

        assert_eq!(read(&same_field, SESSION_COOKIE), CookieRead::Ambiguous);
        assert_eq!(read(&two_fields, SESSION_COOKIE), CookieRead::Ambiguous);
    }

    #[test]
    fn an_unreadable_cookie_field_is_ambiguous() {
        let mut map = HeaderMap::new();
        map.append(COOKIE, HeaderValue::from_bytes(b"a=\xff").unwrap());

        assert_eq!(read(&map, SESSION_COOKIE), CookieRead::Ambiguous);
    }

    /// A name that only starts like the platform's is matched whole, not
    /// by prefix.
    #[test]
    fn a_longer_name_is_another_cookie() {
        let map = cookies(&["ianua_session_old=x"]);

        assert_eq!(read(&map, SESSION_COOKIE), CookieRead::Absent);
    }

    #[test]
    fn every_platform_cookie_is_the_platforms() {
        for name in [
            SESSION_COOKIE,
            CSRF_COOKIE,
            APP_SESSION_COOKIE,
            APP_CSRF_COOKIE,
            APP_CHALLENGE_COOKIE,
            APP_SINGLE_SIGN_ON_COOKIE,
            APP_HOP_COOKIE,
            APP_DEVICE_COOKIE,
            "ianua_later",
            "__Secure-ianua_x",
        ] {
            assert!(is_platform_cookie(name), "{name}");
        }
        assert!(!is_platform_cookie("session"));
        assert!(!is_platform_cookie("my_ianua_thing"));
    }

    proptest! {
        /// Whatever a `Cookie` field holds, reading never panics, and a
        /// value read is one the field carries under that exact name.
        #[test]
        fn reading_finds_only_what_was_sent(field in "[ -~]{0,80}") {
            let Ok(value) = HeaderValue::from_str(&field) else {
                return Ok(());
            };
            let mut map = HeaderMap::new();
            map.append(COOKIE, value);

            if let CookieRead::One(found) = read(&map, SESSION_COOKIE) {
                let sent = field.split(';').any(|pair| {
                    pair.split_once('=')
                        .is_some_and(|(name, value)| name.trim() == SESSION_COOKIE && value.trim() == found)
                });
                prop_assert!(sent);
            }
        }
    }
}
