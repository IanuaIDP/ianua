//! The credential a request presents, extracted into the app's
//! [`Presented`] as it arrived, never read.
//!
//! One credential is picked, in the app's order: a bearer token, an API key
//! header, the app session cookie on a host with app sign-in, the session
//! cookie elsewhere. What is picked is handed to the authentication use
//! case untouched. Anything the gateway could read two ways (a header sent
//! twice, a cookie planted beside another, an `Authorization` it does not
//! understand) is refused rather than resolved by a guess.

use http::HeaderMap;
use http::header::AUTHORIZATION;
use ianua_app::use_cases::oauth::sender::DpopHeader;
use ianua_app::use_cases::proxy::credentials::{AppSessionCookie, Presented, RequestTarget};
use ianua_domain::domains::proxy::request::cross_site::CsrfEcho;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{CanonicalPath, HttpMethod, HttpUrl};

use crate::request::cookies::{
    APP_CSRF_COOKIE, APP_SESSION_COOKIE, CSRF_COOKIE, CSRF_HEADER, CookieRead, SESSION_COOKIE, read,
};
use crate::request::host::RequestHost;
use crate::request::origin::page_origin;
use crate::resolve::AppSessionRules;

/// The headers an API key is read from, in the spelling clients send.
pub(crate) const API_KEY_HEADERS: [&str; 2] = ["apikey", "x-api-key"];

/// The header a `DPoP` proof is sent in.
pub(crate) const DPOP_HEADER: &str = "dpop";

/// Which session cookie a request's host and route let the gateway read.
///
/// The tenant's [`AppSignInIndex`](crate::resolve::sign_in::AppSignInIndex) answers
/// it for a matched route and host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SessionCookies {
    /// The host has no app sign-in: the platform's session cookie is read.
    Platform,
    /// The host has app sign-in. Only its app session cookie is read, and
    /// only when the matched route takes that sign-in, held to these rules.
    /// The platform's session cookie is never read here, since a sibling
    /// subdomain could have planted it.
    AppSignIn(Option<AppSessionRules>),
}

/// Where a credential was looked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CredentialPlace {
    /// The `Authorization` header.
    Authorization,
    /// An API key header.
    ApiKey,
    /// The browser's bearer session credential carried in its named cookie.
    SessionCookie,
    /// The CSRF cookie or header.
    CsrfEcho,
    /// The `DPoP` header.
    Dpop,
}

impl std::fmt::Display for CredentialPlace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Authorization => "authorization header",
            Self::ApiKey => "API key header",
            Self::SessionCookie => "session cookie",
            Self::CsrfEcho => "CSRF cookie or header",
            Self::Dpop => "DPoP header",
        })
    }
}

/// Why a request's credential could not be extracted. Neither carries the
/// credential's value, so either may be logged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum CredentialRefusal {
    /// It is sent more than once, or in two places that each count.
    #[error("the request sends its {0} more than once")]
    Repeated(CredentialPlace),
    /// It is not text, empty, or of a scheme the gateway does not take.
    #[error("the request's {0} cannot be read")]
    Unreadable(CredentialPlace),
}

/// The one credential `headers` present on `host`, as the app takes it.
///
/// # Errors
///
/// - [`CredentialRefusal::Repeated`] when the credential picked, or the CSRF
///   pair beside a cookie, is sent more than once.
/// - [`CredentialRefusal::Unreadable`] when `Authorization` is not a
///   bearer token, or a credential is empty or not text.
pub(crate) fn presented(
    headers: &HeaderMap,
    host: &RequestHost,
    cookies: &SessionCookies,
) -> Result<Presented, CredentialRefusal> {
    if let Some(token) = bearer(headers)? {
        return Ok(Presented::Bearer(token));
    }
    if let Some(key) = api_key(headers)? {
        return Ok(Presented::ApiKey(key));
    }
    match cookies {
        SessionCookies::Platform => platform_session(headers),
        SessionCookies::AppSignIn(Some(rules)) => app_session(headers, host, rules),
        SessionCookies::AppSignIn(None) => Ok(Presented::Nothing),
    }
}

/// The `DPoP` header `headers` carry.
///
/// # Errors
///
/// - [`CredentialRefusal::Repeated`] when it is sent twice.
/// - [`CredentialRefusal::Unreadable`] when it is empty or not text.
pub(crate) fn dpop(headers: &HeaderMap) -> Result<DpopHeader, CredentialRefusal> {
    let Some(proof) = single(headers, DPOP_HEADER, CredentialPlace::Dpop)? else {
        return Ok(DpopHeader::NotSent);
    };
    Ok(DpopHeader::Sent(proof))
}

/// The run pass `headers` carry as a bearer token, the only credential the
/// workflow listener reads; nothing when they carry none.
///
/// # Errors
///
/// The refusals of a bearer token [`presented`] makes.
pub(crate) fn run_pass(headers: &HeaderMap) -> Result<Presented, CredentialRefusal> {
    Ok(bearer(headers)?.map_or(Presented::Nothing, Presented::RunPass))
}

/// Which listener a request came on, which decides how its app is found
/// and what it may present.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ListenerRole {
    /// The public and runner listeners: the app is found by the request's
    /// host, and every credential is read.
    ByHost,
    /// The workflow listener: the app is the route the run pass names, and
    /// a pass is the only credential read.
    ByRunPass,
}

/// How a request reached the gateway, for the address a `DPoP` proof
/// names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Scheme {
    /// Over TLS the gateway ended, or one ended in front of it.
    Https,
    /// In the clear.
    Http,
}

/// Where a request was sent, as a `DPoP` proof must name it: the scheme,
/// the host and the canonical path spelled for the wire, without query.
///
/// `None` when that address is not a URL the domain takes, such as one
/// longer than it holds; a request whose target cannot be named cannot
/// prove a proof was made for it.
#[must_use]
pub(crate) fn target(
    method: HttpMethod,
    scheme: Scheme,
    host: &RequestHost,
    path: &CanonicalPath,
) -> Option<RequestTarget> {
    let scheme = match scheme {
        Scheme::Https => "https",
        Scheme::Http => "http",
    };
    let url = HttpUrl::new(format!("{scheme}://{}{}", host.as_str(), path.to_wire())).ok()?;
    Some(RequestTarget { method, url })
}

/// The schemes an access token is sent under: `Bearer`, and `DPoP` for a
/// token bound to a key, as RFC 9449 has clients send it. Either is checked
/// the same way; a bound token needs its key's proof whatever it was sent
/// under.
const TOKEN_SCHEMES: [&str; 2] = ["bearer", "dpop"];

/// The bearer token in `Authorization`, if it is sent.
fn bearer(headers: &HeaderMap) -> Result<Option<Secret>, CredentialRefusal> {
    let place = CredentialPlace::Authorization;
    let Some(value) = single(headers, AUTHORIZATION.as_str(), place)? else {
        return Ok(None);
    };
    let (scheme, token) = value
        .expose()
        .split_once(' ')
        .ok_or(CredentialRefusal::Unreadable(place))?;
    let token = token.trim();
    let known = TOKEN_SCHEMES
        .iter()
        .any(|taken| scheme.eq_ignore_ascii_case(taken));
    if !known || token.is_empty() {
        return Err(CredentialRefusal::Unreadable(place));
    }
    Ok(Some(Secret::new(token)))
}

/// The API key sent in one of [`API_KEY_HEADERS`], if any is.
fn api_key(headers: &HeaderMap) -> Result<Option<Secret>, CredentialRefusal> {
    let place = CredentialPlace::ApiKey;
    let mut sent = Vec::with_capacity(1);
    for name in API_KEY_HEADERS {
        if let Some(key) = single(headers, name, place)? {
            sent.push(key);
        }
    }
    let Some(key) = sent.pop() else {
        return Ok(None);
    };
    if !sent.is_empty() {
        return Err(CredentialRefusal::Repeated(place));
    }
    Ok(Some(key))
}

/// The platform's session cookie, with its CSRF pair.
fn platform_session(headers: &HeaderMap) -> Result<Presented, CredentialRefusal> {
    let Some(token) = cookie(headers, SESSION_COOKIE, CredentialPlace::SessionCookie)? else {
        return Ok(Presented::Nothing);
    };
    let csrf = csrf_echo(headers, CSRF_COOKIE)?;
    Ok(Presented::SessionCookie { token, csrf })
}

/// The app session cookie of a host with app sign-in, held to `rules`.
fn app_session(
    headers: &HeaderMap,
    host: &RequestHost,
    rules: &AppSessionRules,
) -> Result<Presented, CredentialRefusal> {
    let Some(token) = cookie(headers, APP_SESSION_COOKIE, CredentialPlace::SessionCookie)? else {
        return Ok(Presented::Nothing);
    };
    Ok(Presented::AppSession(AppSessionCookie {
        token,
        host: host.name().clone(),
        owner: *rules.owner(),
        audience: rules.audience().clone(),
        origin: page_origin(headers, host, rules.trusted_origins()),
        csrf: csrf_echo(headers, APP_CSRF_COOKIE)?,
    }))
}

/// The CSRF cookie `name` and the CSRF header, either possibly missing.
fn csrf_echo(headers: &HeaderMap, name: &str) -> Result<CsrfEcho, CredentialRefusal> {
    let place = CredentialPlace::CsrfEcho;
    Ok(CsrfEcho::new(
        cookie(headers, name, place)?,
        single(headers, CSRF_HEADER, place)?,
    ))
}

/// The value of cookie `name`, if it is sent with one.
fn cookie(
    headers: &HeaderMap,
    name: &str,
    place: CredentialPlace,
) -> Result<Option<Secret>, CredentialRefusal> {
    match read(headers, name) {
        CookieRead::Absent | CookieRead::One("") => Ok(None),
        CookieRead::One(value) => Ok(Some(Secret::new(value))),
        CookieRead::Ambiguous => Err(CredentialRefusal::Repeated(place)),
    }
}

/// The value of header `name`, if it is sent once with one.
fn single(
    headers: &HeaderMap,
    name: &str,
    place: CredentialPlace,
) -> Result<Option<Secret>, CredentialRefusal> {
    let mut sent = headers.get_all(name).iter();
    let Some(value) = sent.next() else {
        return Ok(None);
    };
    if sent.next().is_some() {
        return Err(CredentialRefusal::Repeated(place));
    }
    let text = value
        .to_str()
        .map_err(|_| CredentialRefusal::Unreadable(place))?;
    if text.trim().is_empty() {
        return Err(CredentialRefusal::Unreadable(place));
    }
    Ok(Some(Secret::new(text)))
}

#[cfg(test)]
mod tests {
    use http::HeaderValue;
    use ianua_domain::domains::proxy::request::cross_site::PageOrigin;
    use ianua_domain::types::{Audience, DomainName, HostOrigin, ServiceId};

    use super::*;

    fn headers(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.append(*name, HeaderValue::from_static(value));
        }
        map
    }

    fn host(name: &str) -> RequestHost {
        RequestHost::new(DomainName::new(name).unwrap()).unwrap()
    }

    fn shop_rules() -> AppSessionRules {
        AppSessionRules::new(
            ServiceId::new(),
            Audience::new("shop").unwrap(),
            vec![HostOrigin::new("https://shop.example.com").unwrap()],
        )
    }

    fn platform(pairs: &[(&'static str, &'static str)]) -> Result<Presented, CredentialRefusal> {
        presented(
            &headers(pairs),
            &host("app.example.com"),
            &SessionCookies::Platform,
        )
    }

    #[test]
    fn a_bearer_token_is_presented_as_sent() {
        let picked = platform(&[("authorization", "Bearer aaa.bbb.ccc")]);

        let Ok(Presented::Bearer(token)) = picked else {
            panic!("a bearer token is presented");
        };

        assert_eq!(token.expose(), "aaa.bbb.ccc");
    }

    /// The scheme is case-insensitive, as HTTP says it is.
    #[test]
    fn the_bearer_scheme_is_read_in_any_case() {
        assert!(matches!(
            platform(&[("authorization", "bearer t")]),
            Ok(Presented::Bearer(_))
        ));
    }

    /// A token bound to a key comes under the `DPoP` scheme, as RFC 9449
    /// has an agent send it, and is presented like a bearer token.
    #[test]
    fn a_token_sent_under_the_dpop_scheme_is_presented() {
        let picked = platform(&[("authorization", "DPoP aaa.bbb.ccc")]);

        let Ok(Presented::Bearer(token)) = picked else {
            panic!("a DPoP token is presented");
        };

        assert_eq!(token.expose(), "aaa.bbb.ccc");
    }

    /// Unsupported or incomplete authorization is rejected even when a session
    /// cookie is present; the cookie does not replace the unreadable header.
    #[test]
    fn an_authorization_the_gateway_cannot_read_is_refused() {
        for value in ["Basic YTpi", "Bearer", "Bearer   ", "DPoP ", "token"] {
            let sent = headers(&[("authorization", value), ("cookie", "ianua_session=s")]);

            assert_eq!(
                presented(&sent, &host("app.example.com"), &SessionCookies::Platform).err(),
                Some(CredentialRefusal::Unreadable(
                    CredentialPlace::Authorization
                )),
                "{value}"
            );
        }
    }

    #[test]
    fn a_credential_sent_twice_is_refused() {
        assert_eq!(
            platform(&[("authorization", "Bearer a"), ("authorization", "Bearer b")]).err(),
            Some(CredentialRefusal::Repeated(CredentialPlace::Authorization))
        );
        assert_eq!(
            platform(&[("apikey", "k1"), ("x-api-key", "k2")]).err(),
            Some(CredentialRefusal::Repeated(CredentialPlace::ApiKey))
        );
        assert_eq!(
            platform(&[("cookie", "ianua_session=a; ianua_session=b")]).err(),
            Some(CredentialRefusal::Repeated(CredentialPlace::SessionCookie))
        );
    }

    /// The app's order: a bearer token wins over an API key and a cookie.
    #[test]
    fn a_bearer_token_is_picked_before_a_key_or_a_cookie() {
        let picked = platform(&[
            ("authorization", "Bearer t"),
            ("x-api-key", "k"),
            ("cookie", "ianua_session=s"),
        ]);

        assert!(matches!(picked, Ok(Presented::Bearer(_))));
    }

    #[test]
    fn an_api_key_is_picked_before_a_cookie() {
        let picked = platform(&[("apikey", "k"), ("cookie", "ianua_session=s")]);

        assert!(matches!(picked, Ok(Presented::ApiKey(key)) if key.expose() == "k"));
    }

    #[test]
    fn the_platform_session_cookie_is_read_with_its_csrf_pair() {
        let picked = platform(&[
            ("cookie", "ianua_session=s; ianua_csrf=c"),
            (CSRF_HEADER, "c"),
        ]);

        let Ok(Presented::SessionCookie { token, csrf }) = picked else {
            panic!("the session cookie is presented");
        };
        assert_eq!(token.expose(), "s");
        assert!(csrf.matches());
    }

    #[test]
    fn nothing_sent_presents_nothing() {
        assert!(matches!(platform(&[]), Ok(Presented::Nothing)));
        assert!(matches!(
            platform(&[("cookie", "ianua_session=")]),
            Ok(Presented::Nothing)
        ));
    }

    /// A platform session cookie presents no credential on a host configured
    /// for application sign-in.
    #[test]
    fn the_platform_cookie_is_ignored_on_a_host_with_app_sign_in() {
        let cookies = SessionCookies::AppSignIn(Some(shop_rules()));
        let sent = headers(&[("cookie", "ianua_session=planted")]);

        let picked = presented(&sent, &host("shop.example.com"), &cookies);

        assert!(matches!(picked, Ok(Presented::Nothing)));
    }

    #[test]
    fn the_app_session_cookie_is_held_to_its_hosts_rules() {
        let rules = shop_rules();
        let sent = headers(&[
            ("cookie", "__Host-ianua_app=s; __Host-ianua_csrf=c"),
            ("sec-fetch-site", "same-origin"),
        ]);

        let cookies = SessionCookies::AppSignIn(Some(rules.clone()));

        let picked = presented(&sent, &host("shop.example.com"), &cookies);

        let Ok(Presented::AppSession(cookie)) = picked else {
            panic!("the app session is presented");
        };
        assert_eq!(cookie.token.expose(), "s");
        assert_eq!(cookie.host.as_str(), "shop.example.com");
        assert_eq!(cookie.owner, *rules.owner());
        assert_eq!(cookie.audience.as_str(), "shop");
        assert_eq!(cookie.origin, PageOrigin::Trusted);
    }

    /// A route that does not take the host's sign-in reads no cookie at
    /// all, so the session of one app never signs a caller in to another.
    #[test]
    fn a_route_not_taking_the_sign_in_reads_no_cookie() {
        let sent = headers(&[("cookie", "__Host-ianua_app=s")]);

        let picked = presented(
            &sent,
            &host("shop.example.com"),
            &SessionCookies::AppSignIn(None),
        );

        assert!(matches!(picked, Ok(Presented::Nothing)));
    }

    #[test]
    fn a_dpop_proof_is_read_once() {
        assert!(matches!(dpop(&headers(&[])), Ok(DpopHeader::NotSent)));
        assert!(matches!(
            dpop(&headers(&[("dpop", "p")])),
            Ok(DpopHeader::Sent(proof)) if proof.expose() == "p"
        ));
        assert_eq!(
            dpop(&headers(&[("dpop", "a"), ("dpop", "b")])).err(),
            Some(CredentialRefusal::Repeated(CredentialPlace::Dpop))
        );
    }

    #[test]
    fn the_target_names_the_scheme_host_and_wire_path() {
        let path = CanonicalPath::new("/files%20private").unwrap();

        let named = target(
            HttpMethod::Post,
            Scheme::Https,
            &host("api.example.com"),
            &path,
        )
        .unwrap();

        assert_eq!(named.method, HttpMethod::Post);
        assert_eq!(
            named.url.as_str(),
            "https://api.example.com/files%20private"
        );
    }

    /// A refusal names where the credential was looked for, never what it
    /// held.
    #[test]
    fn a_refusal_never_shows_the_credential() {
        let refusal = platform(&[("authorization", "Basic c2VjcmV0")]).err();

        assert!(refusal.is_some_and(|refusal| !refusal.to_string().contains("c2VjcmV0")));
    }
}
