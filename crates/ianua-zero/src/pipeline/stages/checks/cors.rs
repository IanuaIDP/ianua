//! Reads a request's CORS headers into the domain's [`CorsRequest`]; the
//! route's configuration decides what they come to.
//!
//! An `Origin` sent twice or not as text is unreadable, and neither copy is
//! taken. A preflight's method or header line not sent as text is unknown,
//! which the configuration refuses.

use http::HeaderMap;
use ianua_domain::domains::proxy::stages::checks::cors::{CorsRequest, PreflightAsk, SentOrigin};
use ianua_domain::types::{Fact, HttpMethod};

/// The request `method` carrying `headers`, as CORS reads it.
pub(super) fn read(method: HttpMethod, headers: &HeaderMap) -> CorsRequest<'_> {
    CorsRequest {
        method,
        origin: origin(headers),
        preflight: preflight(headers),
    }
}

/// The request's `Origin`.
fn origin(headers: &HeaderMap) -> SentOrigin<'_> {
    let mut sent = headers.get_all(http::header::ORIGIN).iter();
    let Some(first) = sent.next() else {
        return SentOrigin::Absent;
    };
    if sent.next().is_some() {
        return SentOrigin::Unreadable;
    }
    first
        .to_str()
        .map_or(SentOrigin::Unreadable, SentOrigin::One)
}

/// What the request's `Access-Control-Request-*` headers ask.
fn preflight(headers: &HeaderMap) -> PreflightAsk<'_> {
    let Some(method) = headers.get(http::header::ACCESS_CONTROL_REQUEST_METHOD) else {
        return PreflightAsk::NotAsked;
    };
    PreflightAsk::Asks {
        method: text(method),
        headers: headers
            .get_all(http::header::ACCESS_CONTROL_REQUEST_HEADERS)
            .iter()
            .map(text)
            .collect(),
    }
}

/// A header's value, unknown when not sent as text.
fn text(value: &http::HeaderValue) -> Fact<&str> {
    value.to_str().map_or(Fact::Unknown, Fact::Known)
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::proxy::stages::checks::cors::{CorsAnswer, CorsRefusal};
    use ianua_domain::domains::proxy::stages::stage::{CorsConfig, CorsCredentials};
    use ianua_domain::types::{HeaderName, Origin, Seconds};

    use super::*;

    fn config() -> CorsConfig {
        CorsConfig {
            allowed_origins: vec![Origin::new("https://app.acme.com").unwrap()],
            allowed_methods: vec![HttpMethod::Get, HttpMethod::Post],
            allowed_headers: vec![
                HeaderName::new("Authorization").unwrap(),
                HeaderName::new("Content-Type").unwrap(),
            ],
            exposed_headers: vec![HeaderName::new("X-Request-Id").unwrap()],
            max_age_secs: Seconds::new(3600),
            allow_credentials: CorsCredentials::Allowed,
        }
    }

    fn headers(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.append(*name, http::HeaderValue::from_static(value));
        }
        map
    }

    #[test]
    fn a_request_without_an_origin_is_not_cross_origin() {
        let sent = HeaderMap::new();

        let answer = config().answer(&read(HttpMethod::Get, &sent));

        assert_eq!(answer, Ok(CorsAnswer::NotCrossOrigin));
    }

    #[test]
    fn an_origin_sent_twice_is_refused() {
        let sent = headers(&[
            ("origin", "https://app.acme.com"),
            ("origin", "https://evil.example"),
        ]);

        let answer = config().answer(&read(HttpMethod::Get, &sent));

        assert_eq!(answer, Err(CorsRefusal::UnreadableOrigin));
    }

    #[test]
    fn an_origin_not_sent_as_text_is_refused() {
        let mut sent = HeaderMap::new();
        sent.insert(
            http::header::ORIGIN,
            http::HeaderValue::from_bytes(b"https://\xffapp").unwrap(),
        );

        let answer = config().answer(&read(HttpMethod::Get, &sent));

        assert_eq!(answer, Err(CorsRefusal::UnreadableOrigin));
    }

    #[test]
    fn a_preflight_is_read_with_every_header_line() {
        let sent = headers(&[
            ("origin", "https://app.acme.com"),
            ("access-control-request-method", "POST"),
            ("access-control-request-headers", "content-type"),
            ("access-control-request-headers", "x-debug"),
        ]);

        let answer = config().answer(&read(HttpMethod::Options, &sent));

        assert_eq!(answer, Err(CorsRefusal::Header));
    }

    #[test]
    fn a_preflight_method_not_sent_as_text_is_refused() {
        let mut sent = headers(&[("origin", "https://app.acme.com")]);
        sent.insert(
            http::header::ACCESS_CONTROL_REQUEST_METHOD,
            http::HeaderValue::from_bytes(b"P\xffST").unwrap(),
        );

        let answer = config().answer(&read(HttpMethod::Options, &sent));

        assert_eq!(answer, Err(CorsRefusal::Method));
    }

    #[test]
    fn an_allowed_preflight_is_answered() {
        let sent = headers(&[
            ("origin", "https://app.acme.com"),
            ("access-control-request-method", "POST"),
            (
                "access-control-request-headers",
                "content-type, Authorization",
            ),
        ]);

        let answer = config().answer(&read(HttpMethod::Options, &sent));

        assert!(matches!(answer, Ok(CorsAnswer::Preflight(_))));
    }
}
