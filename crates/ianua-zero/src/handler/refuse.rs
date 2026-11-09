//! A refused request: what its client is told and what its record keeps.
//!
//! The client is told the kind of trouble and the request's reference, in
//! the form it reads, with the headers the pipeline set for it. The record
//! keeps the reason and the check that refused. A refusal a browser could
//! cure by signing in on an app's own sign-in is sent there instead.

use std::borrow::Cow;

use http::header::LOCATION;
use http::{HeaderMap, HeaderValue, Response, StatusCode};
use ianua_app::ports::pages::{ErrorBranding, ErrorPage, ErrorPageKind, PageRenderer};
use ianua_app::ports::shared::PreferredLanguages;
use ianua_domain::domains::proxy::observation::{DecidingRule, DecidingStage, GatewayCheck};
use ianua_domain::domains::proxy::stages::decision::HeaderEntry;
use ianua_domain::domains::proxy::stages::stage::StageConfig;
use ianua_domain::types::{CorrelationId, DenialStatus};

use super::{GatewayBody, whole};
use crate::observability::Refusal;
use crate::respond::error_page::{error_response, with_pipeline_headers};

/// A refused request.
#[derive(Debug, Clone)]
pub(crate) struct Refused {
    status: DenialStatus,
    kind: ErrorPageKind,
    reason: Cow<'static, str>,
    decided_by: DecidingStage,
    rule: DecidingRule,
    answering: Box<Answering>,
}

/// How a refusal is answered, apart from what is recorded of it: the look
/// of its page, the headers the pipeline set for the client, and the
/// sign-in a browser is sent to instead. Boxed, since a refusal travels in
/// the error of every step and the branding alone is a few hundred bytes.
#[derive(Debug, Clone, Default)]
struct Answering {
    branding: Option<ErrorBranding>,
    headers: Vec<HeaderEntry>,
    sign_in_at: Option<String>,
}

impl Refused {
    /// Refused before any stage ran, by the gateway's own `check`, as
    /// `kind` says, recorded with `reason`.
    pub(crate) fn at_gateway(
        kind: ErrorPageKind,
        check: GatewayCheck,
        reason: &'static str,
    ) -> Self {
        Self {
            status: kind.status(),
            kind,
            reason: Cow::Borrowed(reason),
            decided_by: DecidingStage::Gateway(check),
            rule: DecidingRule::Unnamed,
            answering: Box::default(),
        }
    }

    /// Why it was refused, as its record names it.
    pub(crate) fn reason(&self) -> &str {
        &self.reason
    }

    /// Refused by `stage` with `status`, recorded with the stage's own
    /// `reason`.
    pub(crate) fn by_stage(status: DenialStatus, reason: &str, stage: &StageConfig) -> Self {
        Self {
            status,
            kind: kind_of(status),
            reason: Cow::Owned(reason.to_owned()),
            decided_by: DecidingStage::stage(stage),
            rule: DecidingRule::Unnamed,
            answering: Box::default(),
        }
    }

    /// The same refusal answered with `status`, its kind the closest one.
    #[must_use]
    pub(crate) fn answered_with(self, status: DenialStatus) -> Self {
        Self {
            status,
            kind: kind_of(status),
            ..self
        }
    }

    /// The same refusal, made under the tenant policy rule `rule`.
    #[must_use]
    pub(crate) fn under(self, rule: DecidingRule) -> Self {
        Self { rule, ..self }
    }

    /// The same refusal, its page wearing `branding`.
    #[must_use]
    pub(crate) fn wearing(mut self, branding: &ErrorBranding) -> Self {
        self.answering.branding = Some(branding.clone());
        self
    }

    /// The same refusal, carrying the headers the pipeline set for its
    /// client, such as `Retry-After` on a 429.
    #[must_use]
    pub(crate) fn carrying(mut self, headers: Vec<HeaderEntry>) -> Self {
        self.answering.headers = headers;
        self
    }

    /// The same refusal, a browser loading a page sent to sign in at
    /// `address` instead.
    #[must_use]
    pub(crate) fn signing_in_at(mut self, address: Option<String>) -> Self {
        self.answering.sign_in_at = address;
        self
    }

    /// The status the client is answered with.
    pub(crate) fn status(&self) -> DenialStatus {
        self.status
    }

    /// The answer to the request that sent `headers`, under `reference`.
    pub(crate) fn answer(
        &self,
        headers: &HeaderMap,
        reference: CorrelationId,
        pages: &dyn PageRenderer,
    ) -> Response<GatewayBody> {
        let answering = &self.answering;
        if let Some(redirect) = answering.sign_in_at.as_deref().and_then(see_other) {
            return redirect;
        }
        let page = ErrorPage {
            status: self.status,
            kind: self.kind,
            reference,
            branding: answering.branding.clone(),
            languages: PreferredLanguages::default(),
        };
        let answer = error_response(headers, &page, pages);
        whole(with_pipeline_headers(answer, &answering.headers))
    }

    /// What the request's record keeps of the refusal.
    pub(crate) fn into_record(self) -> Refusal {
        let refusal = match self.reason {
            Cow::Borrowed(reason) => Refusal::new(self.status, reason, self.decided_by),
            Cow::Owned(reason) => Refusal::by_stage(self.status, &reason, self.decided_by),
        };
        refusal.under(self.rule)
    }
}

/// A `303 See Other` to `location`, never cached, or `None` when it is no
/// header value.
fn see_other(location: &str) -> Option<Response<GatewayBody>> {
    let location = HeaderValue::from_str(location).ok()?;
    let response = Response::builder()
        .status(StatusCode::SEE_OTHER)
        .header(LOCATION, location)
        .header(http::header::CACHE_CONTROL, "no-store")
        .body(http_body_util::Full::new(hyper::body::Bytes::new()))
        .ok()?;
    Some(whole(response))
}

/// The page kind closest to what a refusal with `status` means.
pub(crate) fn kind_of(status: DenialStatus) -> ErrorPageKind {
    match status.code() {
        401 => ErrorPageKind::NotSignedIn,
        403 => ErrorPageKind::Forbidden,
        404 => ErrorPageKind::NotFound,
        413 => ErrorPageKind::TooLarge,
        421 => ErrorPageKind::Misdirected,
        429 => ErrorPageKind::TooManyRequests,
        502 => ErrorPageKind::UpstreamDown,
        504 => ErrorPageKind::UpstreamTimedOut,
        500..=599 => ErrorPageKind::Unavailable,
        _ => ErrorPageKind::BadRequest,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every status a stage or the upstream refuses with reads as a page
    /// kind, a server error never as a client's fault.
    #[test]
    fn every_status_reads_as_a_kind() {
        let kinds: Vec<_> = [401, 403, 429, 502, 503, 504, 501, 418]
            .into_iter()
            .map(|code| kind_of(DenialStatus::new(code).unwrap()))
            .collect();

        assert_eq!(
            kinds,
            vec![
                ErrorPageKind::NotSignedIn,
                ErrorPageKind::Forbidden,
                ErrorPageKind::TooManyRequests,
                ErrorPageKind::UpstreamDown,
                ErrorPageKind::Unavailable,
                ErrorPageKind::UpstreamTimedOut,
                ErrorPageKind::Unavailable,
                ErrorPageKind::BadRequest,
            ]
        );
    }

    /// A refusal keeps its reason and the check that made it for the
    /// record, whatever its client is told.
    #[test]
    fn a_refusal_keeps_its_reason_for_the_record() {
        let refused = Refused::at_gateway(ErrorPageKind::NotFound, GatewayCheck::Route, "no_route")
            .answered_with(DenialStatus::NOT_FOUND);

        let record = refused.into_record();

        assert_eq!(record.status(), DenialStatus::NOT_FOUND);
    }
}
