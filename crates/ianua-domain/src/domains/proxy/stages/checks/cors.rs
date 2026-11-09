//! Cross-origin resource sharing: which pages may call a route, and the
//! answer to a browser's preflight.
//!
//! A request without `Origin` is not cross-origin and passes. One from an
//! origin the route does not allow is refused. A preflight is answered from
//! the configuration, never forwarded: an upstream has nothing to add to
//! it, and a method or header the route does not allow is refused. The
//! `Access-Control-*` headers go on whatever answers the request.
//!
//! An adapter reads the headers ([`CorsRequest`]); what they come to is
//! decided here.

use crate::domains::proxy::request::context::{PipelineContext, ReadyResponse, ResponseSource};
use crate::domains::proxy::stages::decision::{HeaderEntry, StageDecision};
use crate::domains::proxy::stages::stage::{CorsConfig, CorsCredentials};
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::validation::numeric::{validate_count, validate_range};
use crate::types::{DenialStatus, Fact, HeaderName, HeaderValue, HttpMethod, Origin};

/// The longest a browser may cache a preflight answer: one day.
const MAX_PREFLIGHT_CACHE_SECS: u32 = 86_400;

/// The status a preflight is answered with.
pub const PREFLIGHT_STATUS: u16 = 204;

/// The `Origin` a request sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SentOrigin<'a> {
    /// None: not a cross-origin request.
    Absent,
    /// This one origin.
    One(&'a str),
    /// Sent twice, or not as text. Which a browser meant cannot be told,
    /// so neither is taken.
    Unreadable,
}

/// What an `OPTIONS` request's `Access-Control-Request-*` headers ask.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreflightAsk<'a> {
    /// No `Access-Control-Request-Method`: not a preflight.
    NotAsked,
    /// A preflight.
    Asks {
        /// The method it asks about; unknown when not sent as text.
        method: Fact<&'a str>,
        /// Each `Access-Control-Request-Headers` line as sent; unknown for
        /// one not sent as text.
        headers: Vec<Fact<&'a str>>,
    },
}

/// A request as CORS reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorsRequest<'a> {
    /// The HTTP verb checked against allowed CORS methods.
    pub method: HttpMethod,
    /// The origin it sent.
    pub origin: SentOrigin<'a>,
    /// What its preflight headers ask, if it sent them.
    pub preflight: PreflightAsk<'a>,
}

impl CorsRequest<'_> {
    /// Whether the request is a preflight: an `OPTIONS` naming the method
    /// it asks about. A preflight carries no credential and grants
    /// nothing.
    #[must_use]
    pub fn is_preflight(&self) -> bool {
        self.method == HttpMethod::Options && self.preflight != PreflightAsk::NotAsked
    }
}

/// What CORS makes of a request it lets through.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CorsAnswer {
    /// No `Origin`: not a cross-origin request.
    NotCrossOrigin,
    /// An allowed origin's request, with the headers its answer carries.
    Allowed(Vec<HeaderEntry>),
    /// An allowed origin's preflight, answered with these headers.
    Preflight(Vec<HeaderEntry>),
}

impl CorsAnswer {
    /// Writes the answer onto `ctx`: its headers for whatever answers the
    /// request, and for a preflight the empty answer served instead of the
    /// upstream's.
    #[must_use]
    pub fn applied_to(self, ctx: &mut PipelineContext) -> StageDecision {
        match self {
            Self::NotCrossOrigin => pass("cors: not a cross-origin request"),
            Self::Allowed(headers) => {
                ctx.response_headers.extend(headers);
                pass("cors: origin allowed")
            }
            Self::Preflight(headers) => {
                ctx.response_headers.extend(headers);
                ctx.response = ResponseSource::Ready(preflight_response());
                pass("cors: preflight answered")
            }
        }
    }
}

/// The empty answer a preflight is served; its `Access-Control-*` headers
/// travel on the context's response headers.
#[must_use]
pub(crate) fn preflight_response() -> ReadyResponse {
    ReadyResponse {
        status: PREFLIGHT_STATUS,
        headers: Vec::new(),
        body: Vec::new(),
    }
}

/// Why a cross-origin request is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CorsRefusal {
    /// `Origin` sent twice, or not as text.
    UnreadableOrigin,
    /// An origin the route does not allow.
    Origin,
    /// A preflight for a method the route does not allow.
    Method,
    /// A preflight for a header the route does not allow.
    Header,
    /// An answer header could not be written.
    Unwritable,
}

impl CorsRefusal {
    /// The reason the request record keeps.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UnreadableOrigin => "cors: the origin cannot be read",
            Self::Origin => "cors: the origin is not allowed",
            Self::Method => "cors: the preflight asks for a method not allowed",
            Self::Header => "cors: the preflight asks for a header not allowed",
            Self::Unwritable => "cors: the answer's headers cannot be written",
        }
    }

    /// The 403 the refusal is answered with.
    #[must_use]
    pub fn decision(self) -> StageDecision {
        StageDecision::Deny {
            status: DenialStatus::FORBIDDEN,
            reason: self.as_str().to_owned(),
        }
    }
}

impl CorsConfig {
    /// Refuses credentials with a wildcard origin.
    ///
    /// Browsers ignore such a response. If one ever honoured it, any site
    /// could read an answer meant for a signed-in user.
    pub(crate) fn validate(&self) -> Result<(), DomainError> {
        validate_count(
            "allowed_origins",
            self.allowed_origins.len(),
            1..=usize::MAX,
        )?;
        if self.allow_credentials == CorsCredentials::Allowed
            && self.allowed_origins.iter().any(Origin::is_wildcard)
        {
            return Err(DomainError::invalid(message!(
                "proxy-credentials-cannot-be-allowed-for-a",
                "credentials cannot be allowed for a wildcard origin; name the origins"
            )));
        }
        validate_range(
            "max_age_secs",
            self.max_age_secs.get(),
            0..=MAX_PREFLIGHT_CACHE_SECS,
        )?;
        Ok(())
    }

    /// What this configuration makes of `request`.
    ///
    /// # Errors
    ///
    /// - The [`CorsRefusal`] of an origin that cannot be read or is not
    ///   allowed, or of a preflight for a method or header not allowed.
    pub fn answer(&self, request: &CorsRequest<'_>) -> Result<CorsAnswer, CorsRefusal> {
        let origin = match request.origin {
            SentOrigin::Absent => return Ok(CorsAnswer::NotCrossOrigin),
            SentOrigin::Unreadable => return Err(CorsRefusal::UnreadableOrigin),
            SentOrigin::One(origin) => origin,
        };
        if !self
            .allowed_origins
            .iter()
            .any(|allowed| allowed.matches(origin))
        {
            return Err(CorsRefusal::Origin);
        }
        let shared = self.shared_headers(origin)?;
        let PreflightAsk::Asks { method, headers } = &request.preflight else {
            return self.allowed(shared);
        };
        if request.method != HttpMethod::Options {
            return self.allowed(shared);
        }
        self.preflight(*method, headers, shared)
    }

    /// The headers every answer to an allowed origin carries.
    fn shared_headers(&self, origin: &str) -> Result<Vec<HeaderEntry>, CorsRefusal> {
        let mut headers = vec![
            entry("access-control-allow-origin", origin)?,
            entry("vary", "Origin")?,
        ];
        if self.allow_credentials == CorsCredentials::Allowed {
            headers.push(entry("access-control-allow-credentials", "true")?);
        }
        Ok(headers)
    }

    /// The answer to an allowed origin's ordinary request.
    fn allowed(&self, mut headers: Vec<HeaderEntry>) -> Result<CorsAnswer, CorsRefusal> {
        if !self.exposed_headers.is_empty() {
            headers.push(entry(
                "access-control-expose-headers",
                &joined(&self.exposed_headers),
            )?);
        }
        Ok(CorsAnswer::Allowed(headers))
    }

    /// The answer to an allowed origin's preflight for `method` and
    /// `requested` headers.
    fn preflight(
        &self,
        method: Fact<&str>,
        requested: &[Fact<&str>],
        mut headers: Vec<HeaderEntry>,
    ) -> Result<CorsAnswer, CorsRefusal> {
        if !self.allows_method(method) {
            return Err(CorsRefusal::Method);
        }
        if !requested.iter().all(|line| self.allows_line(*line)) {
            return Err(CorsRefusal::Header);
        }
        let methods: Vec<&str> = self
            .allowed_methods
            .iter()
            .map(HttpMethod::as_str)
            .collect();
        headers.push(entry("access-control-allow-methods", &methods.join(", "))?);
        if !self.allowed_headers.is_empty() {
            headers.push(entry(
                "access-control-allow-headers",
                &joined(&self.allowed_headers),
            )?);
        }
        headers.push(entry(
            "access-control-max-age",
            &self.max_age_secs.get().to_string(),
        )?);
        Ok(CorsAnswer::Preflight(headers))
    }

    /// Whether the route allows the method a preflight names. A method the
    /// platform does not know, one not sent as text, and the `*` of route
    /// matching are not allowed.
    fn allows_method(&self, method: Fact<&str>) -> bool {
        let Fact::Known(method) = method else {
            return false;
        };
        let Some(method) = HttpMethod::parse(method).filter(|m| *m != HttpMethod::Any) else {
            return false;
        };
        self.allowed_methods
            .iter()
            .any(|allowed| *allowed == method || *allowed == HttpMethod::Any)
    }

    /// Whether every name on one `Access-Control-Request-Headers` line is
    /// allowed. A line not sent as text is not.
    fn allows_line(&self, line: Fact<&str>) -> bool {
        let Fact::Known(line) = line else {
            return false;
        };
        line.split(',')
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .all(|name| {
                self.allowed_headers
                    .iter()
                    .any(|allowed| allowed.as_str().eq_ignore_ascii_case(name))
            })
    }
}

fn joined(names: &[HeaderName]) -> String {
    names
        .iter()
        .map(HeaderName::as_str)
        .collect::<Vec<_>>()
        .join(", ")
}

fn entry(name: &str, value: &str) -> Result<HeaderEntry, CorsRefusal> {
    let name = HeaderName::new(name).map_err(|_| CorsRefusal::Unwritable)?;
    let value = HeaderValue::new(value).map_err(|_| CorsRefusal::Unwritable)?;
    Ok(HeaderEntry::new(name, value))
}

fn pass(reason: &str) -> StageDecision {
    StageDecision::Pass {
        reason: reason.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{CorrelationId, Origin, PipelineId, Seconds, TenantId};

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

    fn context() -> PipelineContext {
        PipelineContext::new(TenantId::new(), PipelineId::new(), CorrelationId::new())
    }

    fn from(origin: &str) -> CorsRequest<'_> {
        CorsRequest {
            method: HttpMethod::Get,
            origin: SentOrigin::One(origin),
            preflight: PreflightAsk::NotAsked,
        }
    }

    fn preflight<'a>(method: &'a str, headers: &[&'a str]) -> CorsRequest<'a> {
        CorsRequest {
            method: HttpMethod::Options,
            origin: SentOrigin::One("https://app.acme.com"),
            preflight: PreflightAsk::Asks {
                method: Fact::Known(method),
                headers: headers.iter().map(|line| Fact::Known(*line)).collect(),
            },
        }
    }

    fn names(ctx: &PipelineContext) -> Vec<&str> {
        ctx.response_headers
            .iter()
            .map(|header| header.name().as_str())
            .collect()
    }

    #[test]
    fn a_request_without_an_origin_passes_untouched() {
        let mut ctx = context();
        let request = CorsRequest {
            method: HttpMethod::Get,
            origin: SentOrigin::Absent,
            preflight: PreflightAsk::NotAsked,
        };

        let decision = config().answer(&request).unwrap().applied_to(&mut ctx);

        assert!(!decision.is_terminal());
        assert!(ctx.response_headers.is_empty());
    }

    #[test]
    fn an_allowed_origin_passes_with_its_answer_headers() {
        let mut ctx = context();

        let decision = config()
            .answer(&from("https://app.acme.com"))
            .unwrap()
            .applied_to(&mut ctx);

        assert!(!decision.is_terminal());
        let written = names(&ctx);
        assert!(written.contains(&"access-control-allow-origin"));
        assert!(written.contains(&"access-control-allow-credentials"));
        assert!(written.contains(&"access-control-expose-headers"));
        assert!(!written.contains(&"access-control-allow-methods"));
        assert!(ctx.response.ready().is_none());
    }

    #[test]
    fn an_origin_not_allowed_is_refused() {
        assert_eq!(
            config().answer(&from("https://evil.example")),
            Err(CorsRefusal::Origin)
        );
    }

    /// A request whose origin is marked unreadable returns
    /// `UnreadableOrigin`.
    #[test]
    fn an_unreadable_origin_is_refused() {
        let request = CorsRequest {
            method: HttpMethod::Get,
            origin: SentOrigin::Unreadable,
            preflight: PreflightAsk::NotAsked,
        };

        assert_eq!(
            config().answer(&request),
            Err(CorsRefusal::UnreadableOrigin)
        );
    }

    #[test]
    fn a_preflight_is_answered_from_the_configuration() {
        let mut ctx = context();

        let decision = config()
            .answer(&preflight("POST", &["content-type, Authorization"]))
            .unwrap()
            .applied_to(&mut ctx);

        assert!(!decision.is_terminal());
        assert_eq!(ctx.response.ready().unwrap().status, PREFLIGHT_STATUS);
        let written = names(&ctx);
        assert!(written.contains(&"access-control-allow-methods"));
        assert!(written.contains(&"access-control-allow-headers"));
        assert!(written.contains(&"access-control-max-age"));
    }

    #[test]
    fn a_preflight_for_a_method_not_allowed_is_refused() {
        assert_eq!(
            config().answer(&preflight("DELETE", &[])),
            Err(CorsRefusal::Method)
        );
    }

    #[test]
    fn a_preflight_for_a_header_not_allowed_is_refused() {
        assert_eq!(
            config().answer(&preflight("GET", &["content-type, x-debug"])),
            Err(CorsRefusal::Header)
        );
    }

    /// An `OPTIONS` without `Access-Control-Request-Method` is an ordinary
    /// request, not a preflight.
    #[test]
    fn options_without_the_preflight_headers_is_no_preflight() {
        let request = CorsRequest {
            method: HttpMethod::Options,
            origin: SentOrigin::One("https://app.acme.com"),
            preflight: PreflightAsk::NotAsked,
        };

        assert!(!request.is_preflight());
        assert!(matches!(
            config().answer(&request),
            Ok(CorsAnswer::Allowed(_))
        ));
    }

    #[test]
    fn credentials_are_not_offered_when_withheld() {
        let withheld = CorsConfig {
            allow_credentials: CorsCredentials::Withheld,
            ..config()
        };

        let Ok(CorsAnswer::Allowed(written)) = withheld.answer(&from("https://app.acme.com"))
        else {
            panic!("the origin is allowed");
        };

        assert!(
            written
                .iter()
                .all(|header| header.name().as_str() != "access-control-allow-credentials")
        );
    }
}
