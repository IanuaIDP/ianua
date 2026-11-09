//! The headers the gateway takes off a request: the ones it owns and the
//! ones a client names in its `Connection` header, on the way in, and the
//! caller's credentials, on the way out.

use http::HeaderMap;
use http::header::{
    CONNECTION, COOKIE, HeaderName, HeaderValue, PROXY_AUTHENTICATE, PROXY_AUTHORIZATION, TE,
    TRANSFER_ENCODING, UPGRADE,
};
use ianua_domain::shared::web::proxy_headers::is_proxy_owned;

use crate::request::cookies::{CSRF_HEADER, is_platform_cookie};
use crate::request::credentials::{API_KEY_HEADERS, DPOP_HEADER};

/// The headers that carry a credential to the gateway, which no upstream
/// receives.
const CREDENTIAL_HEADERS: [&str; 3] = ["authorization", "proxy-authorization", DPOP_HEADER];

/// Removes every header [`is_proxy_owned`] says is the proxy's.
///
/// Runs on every inbound request, on every route, before anything reads
/// it. The domain's rule reads `_` as `-`, so `X_Forwarded_User` goes too.
pub(crate) fn strip_proxy_owned(headers: &mut HeaderMap) {
    remove_where(headers, |name| is_proxy_owned(name.as_str()));
}

/// Removes the headers a client names in its `Connection` header.
///
/// They describe the client's hop, not the message, and a proxy drops them
/// (RFC 9110, section 7.6.1). It happens on the way in, before the gateway
/// sets anything of its own: a client naming a header the gateway sets for
/// the upstream must never be able to strip it on the way out. The
/// connection headers themselves stay, `Upgrade` and `TE` among them: the
/// forwarder reads them to tell a protocol switch and trailers apart, and
/// drops them when it sends the request on. A `Connection` value that is
/// not text names nothing anyone could set.
pub(crate) fn strip_connection_named(headers: &mut HeaderMap) {
    let named: Vec<HeaderName> = headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|option| HeaderName::from_bytes(option.trim().as_bytes()).ok())
        .filter(|name| !is_connection_header(name))
        .collect();
    for name in named {
        headers.remove(name);
    }
}

/// Whether `name` is one of the headers that describe a connection, which
/// the forwarder reads and drops itself.
fn is_connection_header(name: &HeaderName) -> bool {
    [
        CONNECTION,
        PROXY_AUTHENTICATE,
        PROXY_AUTHORIZATION,
        TE,
        TRANSFER_ENCODING,
        UPGRADE,
    ]
    .contains(name)
        || matches!(name.as_str(), "keep-alive" | "proxy-connection")
}

/// Removes the caller's credential from what is forwarded: `Authorization`,
/// `Proxy-Authorization`, `DPoP`, every API key header, the CSRF echo, and
/// the platform's cookies, leaving the app's own cookies in place.
///
/// No route or service setting passes a credential on, so this runs on
/// every forwarded request. An upstream holding the caller's token could
/// replay it against any other route of the tenant; it learns who the
/// caller is from the signed assertion instead. Names are compared the way
/// CGI-style servers read them, `_` as `-`, so `X_Api_Key` goes too.
pub(crate) fn strip_credentials(headers: &mut HeaderMap) {
    remove_where(headers, |name| is_credential_header(name.as_str()));
    keep_app_cookies(headers);
}

/// Whether `name` carries a credential to the gateway.
fn is_credential_header(name: &str) -> bool {
    let spelled = name.to_ascii_lowercase().replace('_', "-");
    CREDENTIAL_HEADERS.contains(&spelled.as_str())
        || API_KEY_HEADERS.contains(&spelled.as_str())
        || spelled == CSRF_HEADER
}

/// Removes every header whose name `owned` picks.
fn remove_where(headers: &mut HeaderMap, owned: impl Fn(&HeaderName) -> bool) {
    let picked: Vec<HeaderName> = headers.keys().filter(|name| owned(name)).cloned().collect();
    for name in picked {
        headers.remove(name);
    }
}

/// Rewrites the `Cookie` headers with the platform's cookies taken out.
fn keep_app_cookies(headers: &mut HeaderMap) {
    let kept: Vec<HeaderValue> = headers
        .get_all(COOKIE)
        .iter()
        .filter_map(app_cookies_of)
        .collect();
    headers.remove(COOKIE);
    for value in kept {
        headers.append(COOKIE, value);
    }
}

/// One `Cookie` field with the platform's cookies removed, or `None` when
/// nothing is left.
///
/// A field that is not UTF-8 is dropped whole: the gateway cannot read it,
/// so it cannot say no session cookie is in there.
fn app_cookies_of(field: &HeaderValue) -> Option<HeaderValue> {
    let text = std::str::from_utf8(field.as_bytes()).ok()?;
    let kept: Vec<&str> = text
        .split(';')
        .map(str::trim)
        .filter(|pair| !pair.is_empty())
        .filter(|pair| !is_platform_cookie(cookie_name(pair)))
        .collect();
    if kept.is_empty() {
        return None;
    }
    HeaderValue::from_str(&kept.join("; ")).ok()
}

/// The name of one `name=value` pair, trimmed as browsers send it.
fn cookie_name(pair: &str) -> &str {
    pair.split_once('=').map_or(pair, |(name, _)| name).trim()
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.append(
                HeaderName::from_bytes(name.as_bytes()).unwrap(),
                HeaderValue::from_str(value).unwrap(),
            );
        }
        map
    }

    /// Stripping credentials removes authorization, DPoP, API keys and the
    /// CSRF echo while preserving the Accept header.
    #[test]
    fn credentials_are_not_forwarded_on_a_public_route() {
        let mut forwarded = headers(&[
            ("authorization", "Bearer aaa.bbb.ccc"),
            ("proxy-authorization", "Basic YTpi"),
            ("dpop", "proof"),
            ("x-api-key", "sk_1"),
            ("apikey", "sk_2"),
            ("X_Api_Key", "sk_3"),
            (CSRF_HEADER, "t0k3n"),
            ("accept", "text/html"),
        ]);

        strip_credentials(&mut forwarded);

        let left: Vec<&str> = forwarded.keys().map(HeaderName::as_str).collect();
        assert_eq!(left, ["accept"]);
    }

    /// The app's own cookies reach it; the platform's sessions do not.
    #[test]
    fn platform_cookies_are_taken_out_and_the_apps_kept() {
        let mut forwarded = headers(&[
            ("cookie", "theme=dark; ianua_session=aaa.bbb; cart=42"),
            ("cookie", "__Host-ianua_app=ccc; __Host-ianua_csrf=x"),
            ("cookie", "lang=en"),
        ]);

        strip_credentials(&mut forwarded);

        let left: Vec<&str> = forwarded
            .get_all(COOKIE)
            .iter()
            .map(|value| value.to_str().unwrap())
            .collect();
        assert_eq!(left, ["theme=dark; cart=42", "lang=en"]);
    }

    /// A cookie field the gateway cannot read could hold a session, so it
    /// is not forwarded.
    #[test]
    fn an_unreadable_cookie_field_is_dropped() {
        let mut forwarded = HeaderMap::new();
        forwarded.append(COOKIE, HeaderValue::from_bytes(b"s=\xff\xfe").unwrap());

        strip_credentials(&mut forwarded);

        assert!(forwarded.get(COOKIE).is_none());
    }

    /// Headers named in Connection are removed, while Connection, Upgrade,
    /// TE and the unrelated Accept header remain for forwarding.
    #[test]
    fn headers_named_in_connection_go_and_connection_headers_stay() {
        let mut inbound = headers(&[
            ("connection", "Upgrade, X-Debug , te"),
            ("connection", "x-request-id"),
            ("upgrade", "websocket"),
            ("te", "trailers"),
            ("x-debug", "1"),
            ("x-request-id", "abc"),
            ("accept", "text/html"),
        ]);

        strip_connection_named(&mut inbound);

        let mut left: Vec<&str> = inbound.keys().map(HeaderName::as_str).collect();
        left.sort_unstable();
        assert_eq!(left, ["accept", "connection", "te", "upgrade"]);
    }

    /// A `Connection` header naming nothing a header could be called
    /// removes nothing.
    #[test]
    fn a_connection_header_naming_nothing_removes_nothing() {
        let mut inbound = headers(&[("connection", " , ,keep-alive"), ("accept", "*/*")]);

        strip_connection_named(&mut inbound);

        assert_eq!(inbound.len(), 2);
    }

    #[test]
    fn every_owned_header_goes_and_the_rest_stay() {
        let mut inbound = headers(&[
            ("forwarded", "for=10.0.0.5"),
            ("x-real-ip", "10.0.0.5"),
            ("x-http-method-override", "DELETE"),
            ("x-ianua-anything", "x"),
            ("x-request-id", "abc"),
            ("authorization", "Bearer t"),
        ]);

        strip_proxy_owned(&mut inbound);

        let mut left: Vec<&str> = inbound.keys().map(HeaderName::as_str).collect();
        left.sort_unstable();
        assert_eq!(left, ["authorization", "x-request-id"]);
    }

    proptest! {
        /// Whatever a client sends, no header the domain calls the proxy's
        /// is left after stripping, and every other one is.
        #[test]
        fn stripping_leaves_exactly_the_headers_the_proxy_does_not_own(
            names in proptest::collection::vec("(x-forwarded-|x-ianua-|x_forwarded_|x-|)[a-z_-]{1,12}", 0..12),
        ) {
            let mut inbound = HeaderMap::new();
            for name in &names {
                inbound.append(HeaderName::from_bytes(name.as_bytes()).unwrap(), HeaderValue::from_static("v"));
            }

            strip_proxy_owned(&mut inbound);

            for name in &names {
                let present = inbound.contains_key(name.as_str());
                prop_assert_eq!(present, !is_proxy_owned(name));
            }
        }
    }
}
