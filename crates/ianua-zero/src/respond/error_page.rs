//! The answer to a request the gateway refused or could not carry, in the
//! form its client reads.
//!
//! A browser, whose `Accept` header prefers HTML, gets a page a person can
//! read: what kind of trouble it was, what to do, and the request's
//! reference, in the tenant's look when it is known. Anything else, a
//! script or a client that names no preference, gets a small JSON body
//! with the same code and reference. Both carry the same status, are never
//! cached, and are never sniffed as another type. The page runs no script:
//! it is served under a policy that allows none.
//!
//! The page is drawn through the [`PageRenderer`] port. When it cannot be
//! drawn, the browser gets the JSON body instead: the refusal stands either
//! way.

use http::header::{
    ACCEPT, ACCEPT_LANGUAGE, CACHE_CONTROL, CONTENT_SECURITY_POLICY, CONTENT_TYPE, HeaderMap,
    HeaderName, HeaderValue, REFERRER_POLICY, VARY, X_CONTENT_TYPE_OPTIONS, X_FRAME_OPTIONS,
};
use http::{StatusCode, response};
use http_body_util::Full;
use hyper::body::Bytes;
use ianua_app::ports::pages::{ErrorPage, PageRenderer};
use ianua_app::ports::shared::PreferredLanguages;
use ianua_domain::domains::proxy::stages::decision::HeaderEntry;

use crate::respond::grpc::{GrpcWire, grpc_refusal};

/// What an error page may do: draw itself with its own styles and the
/// tenant's logo. No script, no form, no frame around it.
const PAGE_POLICY: &str = "default-src 'none'; style-src 'unsafe-inline'; img-src https: data:; \
                           form-action 'none'; frame-ancestors 'none'; base-uri 'none'";

/// The media types a browser asks for a page by.
const PAGE_TYPES: [&str; 2] = ["text/html", "application/xhtml+xml"];

/// An answer with its whole body.
pub type Response = http::Response<Full<Bytes>>;

/// The form a client reads an error in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Wanted {
    /// A page, for a person in a browser.
    Page,
    /// A JSON body, for a script.
    Json,
    /// A gRPC status, for a gRPC or gRPC-web call, whatever it accepts.
    Grpc(GrpcWire),
}

impl Wanted {
    /// The form the client sending `headers` reads: gRPC's own for a gRPC
    /// call, else what its `Accept` header prefers.
    #[must_use]
    pub(crate) fn of(headers: &HeaderMap) -> Self {
        if let Some(wire) = GrpcWire::of(headers) {
            return Self::Grpc(wire);
        }
        let accept = headers.get(ACCEPT).and_then(|value| value.to_str().ok());
        Self::from_accept(accept)
    }

    /// The form an `Accept` header of `accept` prefers: a page when the
    /// type it values most, first among equals, is HTML. A header that is
    /// missing, or names only wildcards, prefers JSON.
    fn from_accept(accept: Option<&str>) -> Self {
        let preferred = accept
            .into_iter()
            .flat_map(|accept| accept.split(','))
            .filter_map(MediaRange::parse)
            .filter(|range| range.quality > 0.0 && !range.kind.contains('*'))
            .reduce(|best, next| {
                if next.quality > best.quality {
                    next
                } else {
                    best
                }
            });
        match preferred {
            Some(range) if range.is_page() => Self::Page,
            Some(_) | None => Self::Json,
        }
    }
}

/// One entry of an `Accept` header: a media type and how much it is
/// wanted.
struct MediaRange<'a> {
    kind: &'a str,
    quality: f32,
}

impl<'a> MediaRange<'a> {
    /// The entry `item`, or `None` when it names no type. An entry without
    /// a weight, or with one that does not parse, is wanted fully.
    fn parse(item: &'a str) -> Option<Self> {
        let mut parts = item.split(';');
        let kind = parts.next()?.trim();
        if kind.is_empty() {
            return None;
        }
        let quality = parts.find_map(|part| weight(part.trim())).unwrap_or(1.0);
        Some(Self { kind, quality })
    }

    /// Whether the entry asks for a page.
    fn is_page(&self) -> bool {
        PAGE_TYPES
            .iter()
            .any(|page| self.kind.eq_ignore_ascii_case(page))
    }
}

/// The weight a `q=` parameter gives, or `None` for another parameter.
fn weight(parameter: &str) -> Option<f32> {
    let value = parameter
        .strip_prefix("q=")
        .or_else(|| parameter.strip_prefix("Q="))?;
    value.trim().parse().ok()
}

/// The answer to the request sending `headers`, refused as `page` says: the
/// page drawn through `pages` for a browser, a gRPC status for a gRPC
/// call, JSON for anything else.
#[must_use]
pub(crate) fn error_response(
    headers: &HeaderMap,
    page: &ErrorPage,
    pages: &dyn PageRenderer,
) -> Response {
    match Wanted::of(headers) {
        Wanted::Page => page_or_json(&in_readers_languages(headers, page), pages),
        Wanted::Json => json(page),
        Wanted::Grpc(wire) => grpc_refusal(wire, page),
    }
}

/// `answer` with the headers the pipeline set for its client, such as
/// `Retry-After` and `RateLimit-*` on a 429 or a route's CORS headers.
///
/// A header the answer already sets is kept as the answer set it: no stage
/// loosens the refusal's own content type, policy or caching, nor turns a
/// gRPC refusal into another status.
#[must_use]
pub(crate) fn with_pipeline_headers(mut answer: Response, headers: &[HeaderEntry]) -> Response {
    for entry in headers {
        let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(entry.name().as_str().as_bytes()),
            HeaderValue::from_str(entry.value().as_str()),
        ) else {
            continue;
        };
        answer.headers_mut().entry(name).or_insert(value);
    }
    answer
}

/// `page` to be drawn in the languages the browser's `Accept-Language` asks for.
fn in_readers_languages(headers: &HeaderMap, page: &ErrorPage) -> ErrorPage {
    let asked = headers
        .get(ACCEPT_LANGUAGE)
        .and_then(|value| value.to_str().ok());
    ErrorPage {
        languages: PreferredLanguages::from_accept_language(asked),
        ..page.clone()
    }
}

/// `page` drawn for a browser, or its JSON body when it cannot be drawn.
fn page_or_json(page: &ErrorPage, pages: &dyn PageRenderer) -> Response {
    match pages.error_page(page) {
        Ok(drawn) => html(page, drawn.into_html()),
        Err(error) => {
            tracing::warn!(reference = %page.reference, %error, "the error page could not be drawn");
            json(page)
        }
    }
}

/// The page `body`, under a policy that runs no script.
fn html(page: &ErrorPage, body: String) -> Response {
    let builder = head(page)
        .header(CONTENT_TYPE, "text/html; charset=utf-8")
        .header(CONTENT_SECURITY_POLICY, PAGE_POLICY)
        .header(X_FRAME_OPTIONS, "DENY")
        .header(REFERRER_POLICY, "no-referrer");
    finish(builder, status_of(page), Bytes::from(body))
}

/// `page` as JSON: its code and its reference, nothing more.
fn json(page: &ErrorPage) -> Response {
    let body = serde_json::json!({
        "error": page.kind.code(),
        "reference": page.reference.to_string(),
    });
    let builder = head(page).header(CONTENT_TYPE, "application/json");
    finish(builder, status_of(page), Bytes::from(body.to_string()))
}

/// The start every error answer shares: its status, never cached, never
/// sniffed, and marked as varying by what the client accepts and the
/// languages it reads.
fn head(page: &ErrorPage) -> response::Builder {
    http::Response::builder()
        .status(status_of(page))
        .header(CACHE_CONTROL, "no-store")
        .header(X_CONTENT_TYPE_OPTIONS, "nosniff")
        .header(VARY, "Accept, Accept-Language")
}

/// The answer `builder` makes with `body`, or a bare `status` when it
/// cannot be built.
fn finish(builder: response::Builder, status: StatusCode, body: Bytes) -> Response {
    builder.body(Full::new(body)).unwrap_or_else(|_| {
        let mut bare = http::Response::new(Full::new(Bytes::new()));
        *bare.status_mut() = status;
        bare
    })
}

/// The status `page` is answered with. A denial status is always a valid
/// one; a `500` stands in should that ever not hold.
fn status_of(page: &ErrorPage) -> StatusCode {
    StatusCode::from_u16(page.status.code()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR)
}

#[cfg(test)]
mod tests {
    use http::HeaderValue;
    use http_body_util::BodyExt;
    use ianua_app::ports::pages::{DrawnPage, ErrorPageKind, SignInPage};
    use ianua_app::test_support::pages::FakePageRenderer;
    use ianua_domain::shared::errors::DomainError;
    use ianua_domain::types::CorrelationId;

    use super::*;

    /// What Firefox and Chrome send for a page they navigate to.
    const BROWSER: &str = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";

    /// A renderer whose templates are broken: it draws nothing.
    struct BrokenPageRenderer;

    impl PageRenderer for BrokenPageRenderer {
        fn sign_in_page(&self, _: &SignInPage) -> Result<DrawnPage, DomainError> {
            Err(DomainError::infra_msg("the template does not parse"))
        }

        fn error_page(&self, _: &ErrorPage) -> Result<DrawnPage, DomainError> {
            Err(DomainError::infra_msg("the template does not parse"))
        }
    }

    fn accepting(accept: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(ACCEPT, HeaderValue::from_str(accept).unwrap());
        headers
    }

    fn forbidden() -> ErrorPage {
        ErrorPage::new(ErrorPageKind::Forbidden, CorrelationId::new())
    }

    async fn body_of(response: Response) -> String {
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    /// A browser navigating to a page prefers HTML, and gets the page.
    #[test]
    fn a_browser_wants_the_page() {
        assert_eq!(Wanted::from_accept(Some(BROWSER)), Wanted::Page);
        assert_eq!(
            Wanted::from_accept(Some("application/xhtml+xml")),
            Wanted::Page
        );
        assert_eq!(Wanted::from_accept(Some("TEXT/HTML")), Wanted::Page);
    }

    /// A script asking for JSON, or for anything, gets JSON; so does a
    /// client that sends no `Accept` at all.
    #[test]
    fn a_script_wants_json() {
        for accept in ["application/json", "*/*", "", "text/plain"] {
            assert_eq!(Wanted::from_accept(Some(accept)), Wanted::Json, "{accept}");
        }
        assert_eq!(Wanted::from_accept(None), Wanted::Json);
    }

    /// The weights decide: HTML valued below JSON loses, HTML refused with
    /// `q=0` is never chosen, and between equals the first named wins.
    #[test]
    fn the_weights_choose_between_html_and_json() {
        assert_eq!(
            Wanted::from_accept(Some("application/json, text/html;q=0.5")),
            Wanted::Json
        );
        assert_eq!(
            Wanted::from_accept(Some("text/html;q=0.4, application/json;q=0.3")),
            Wanted::Page
        );
        assert_eq!(Wanted::from_accept(Some("text/html;q=0")), Wanted::Json);
        assert_eq!(
            Wanted::from_accept(Some("text/html, application/json")),
            Wanted::Page
        );
        assert_eq!(
            Wanted::from_accept(Some("application/json, text/html")),
            Wanted::Json
        );
    }

    /// HTML with an unparseable quality value is preferred over JSON with
    /// quality 0.9 because the malformed value defaults to full preference.
    #[test]
    fn a_weight_that_does_not_parse_counts_as_full() {
        assert_eq!(
            Wanted::from_accept(Some("text/html;q=lots, application/json;q=0.9")),
            Wanted::Page
        );
    }

    /// Ann's browser is refused: she gets the page, as HTML, under a policy
    /// that runs no script, never cached or sniffed, with the refusal's
    /// status.
    #[tokio::test]
    async fn a_browser_gets_the_page_under_a_policy_without_script() {
        let page = forbidden();

        let response = error_response(&accepting(BROWSER), &page, &FakePageRenderer);

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let headers = response.headers();
        assert_eq!(headers[CONTENT_TYPE], "text/html; charset=utf-8");
        assert_eq!(headers[CACHE_CONTROL], "no-store");
        assert_eq!(headers[X_CONTENT_TYPE_OPTIONS], "nosniff");
        let policy = headers[CONTENT_SECURITY_POLICY].to_str().unwrap();
        assert!(policy.starts_with("default-src 'none'"));
        assert!(!policy.contains("script-src"));
        assert_eq!(
            body_of(response).await,
            format!("<p>forbidden ({})</p>", page.reference)
        );
    }

    /// A script is refused: it gets the code and the reference as JSON,
    /// with the same status, never cached or sniffed.
    #[tokio::test]
    async fn a_script_gets_json_with_the_same_status() {
        let page = forbidden();

        let response = error_response(&accepting("application/json"), &page, &FakePageRenderer);

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(response.headers()[CONTENT_TYPE], "application/json");
        assert_eq!(response.headers()[CACHE_CONTROL], "no-store");
        assert_eq!(response.headers()[X_CONTENT_TYPE_OPTIONS], "nosniff");
        let body: serde_json::Value = serde_json::from_str(&body_of(response).await).unwrap();
        assert_eq!(
            body,
            serde_json::json!({ "error": "forbidden", "reference": page.reference.to_string() })
        );
    }

    /// Every kind is answered with its own status, to a browser and to a
    /// script alike.
    #[test]
    fn every_kind_keeps_its_status_either_way() {
        for kind in ErrorPageKind::ALL {
            let page = ErrorPage::new(kind, CorrelationId::new());

            let to_browser = error_response(&accepting(BROWSER), &page, &FakePageRenderer);
            let to_script = error_response(&HeaderMap::new(), &page, &FakePageRenderer);

            assert_eq!(to_browser.status().as_u16(), page.status.code(), "{kind:?}");
            assert_eq!(to_script.status().as_u16(), page.status.code(), "{kind:?}");
        }
    }

    /// A gRPC client asking with a browser's `Accept` is still a gRPC
    /// caller: its refusal is a gRPC status, not a page.
    #[test]
    fn a_grpc_call_is_refused_in_grpc_terms() {
        let mut headers = accepting(BROWSER);
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/grpc-web+proto"),
        );

        let response = error_response(&headers, &forbidden(), &FakePageRenderer);

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["grpc-status"], "7");
        assert_eq!(response.headers()[CONTENT_TYPE], "application/grpc-web");
    }

    fn entry(name: &str, value: &str) -> HeaderEntry {
        use ianua_domain::types::{HeaderName as Name, HeaderValue as Value};
        HeaderEntry::new(Name::new(name).unwrap(), Value::new(value).unwrap())
    }

    /// Ann is over her limit. The 429 carries `Retry-After` and the
    /// `RateLimit-*` headers the counting stage set, so her client knows
    /// when to come back.
    #[test]
    fn a_429_carries_when_to_come_back() {
        let page = ErrorPage::new(ErrorPageKind::TooManyRequests, CorrelationId::new());
        let refused = error_response(&accepting("application/json"), &page, &FakePageRenderer);

        let answered = with_pipeline_headers(
            refused,
            &[
                entry("retry-after", "30"),
                entry("ratelimit-limit", "100"),
                entry("ratelimit-remaining", "0"),
                entry("ratelimit-reset", "30"),
            ],
        );

        assert_eq!(answered.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(answered.headers()["retry-after"], "30");
        assert_eq!(answered.headers()["ratelimit-limit"], "100");
        assert_eq!(answered.headers()["ratelimit-remaining"], "0");
        assert_eq!(answered.headers()["ratelimit-reset"], "30");
    }

    /// Pipeline headers cannot replace a JSON refusal's content type or
    /// no-store directive, and no duplicate cache-control header is added.
    #[test]
    fn a_pipeline_header_never_replaces_the_refusals_own() {
        let refused = error_response(
            &accepting("application/json"),
            &forbidden(),
            &FakePageRenderer,
        );

        let answered = with_pipeline_headers(
            refused,
            &[
                entry("cache-control", "public, max-age=3600"),
                entry("content-type", "text/html"),
            ],
        );

        assert_eq!(answered.headers()[CACHE_CONTROL], "no-store");
        assert_eq!(answered.headers()[CONTENT_TYPE], "application/json");
        assert_eq!(answered.headers().get_all(CACHE_CONTROL).iter().count(), 1);
    }

    /// When page rendering fails, a browser receives JSON naming the
    /// forbidden error and retains the 403 status.
    #[tokio::test]
    async fn a_page_that_cannot_be_drawn_falls_back_to_json() {
        let page = forbidden();

        let response = error_response(&accepting(BROWSER), &page, &BrokenPageRenderer);

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(response.headers()[CONTENT_TYPE], "application/json");
        assert!(body_of(response).await.contains("\"error\":\"forbidden\""));
    }
}
