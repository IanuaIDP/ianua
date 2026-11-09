//! HTTP error responses: maps `AppError` to JSON + status code.
//!
//! All errors are logged with their full chain via `tracing`.
//! In development mode, internal error details are included in
//! the response body. In production, they are masked.

pub(crate) mod app_sign_in;
pub mod oauth;
pub mod scim;

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use ianua_app::error::AppError;
use ianua_domain::domains::authentication::risk_engine::challenge::ChallengeKind;
use ianua_domain::shared::errors::Refusal;
use serde::Serialize;

/// Global flag: set once at startup. `true` = development mode.
static DEV_MODE: AtomicBool = AtomicBool::new(false);

/// Enables development mode error responses (full details in body).
///
/// Call once at startup before serving requests.
pub fn enable_dev_mode() {
    DEV_MODE.store(true, Ordering::Relaxed);
}

/// Structured JSON error body returned to API consumers.
#[derive(Clone, Serialize, utoipa::ToSchema)]
pub(crate) struct ErrorBody {
    /// Machine-readable error code.
    pub error: ErrorCode,
    /// Human-readable message, in the first language of `Accept-Language`
    /// the platform words it in, else in English.
    pub message: String,
    /// The message key of `message`, when it has one, such as
    /// `routing-cannot-move-a-route-from-to`: a client may show the
    /// message in its own words from the key and `params`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    /// The values `message` was filled with, by name.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub params: BTreeMap<String, String>,
    /// Internal error details (only present in development mode).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
    /// The challenge to solve before signing in again, on
    /// `challenge_required` when one can be set. Absent when none can: only
    /// a trusted device or single sign-on gets in until the pressure eases.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub challenge: Option<ChallengeCode>,
}

/// An error answer with the refusal it words, kept on the response so the
/// wording middleware can put the message into the reader's language.
#[derive(Clone)]
pub(crate) struct WordableRefusal {
    /// The body as answered, in English.
    pub(crate) body: ErrorBody,
    /// The refusal its message came from, with its key and values.
    pub(crate) refusal: Refusal,
}

/// A kind of challenge a sign-in may be asked to solve.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, utoipa::ToSchema)]
pub(crate) enum ChallengeCode {
    /// A puzzle the browser works through itself, served by ianua.
    #[serde(rename = "proof_of_work")]
    ProofOfWork,
    /// Cloudflare Turnstile.
    #[serde(rename = "turnstile")]
    Turnstile,
}

impl From<ChallengeKind> for ChallengeCode {
    fn from(kind: ChallengeKind) -> Self {
        match kind {
            ChallengeKind::ProofOfWork => Self::ProofOfWork,
            ChallengeKind::Turnstile => Self::Turnstile,
        }
    }
}

/// How long a caller told the server is busy waits before trying again,
/// in seconds: a permit usually frees up within one.
const BUSY_RETRY_AFTER_SECONDS: u32 = 1;

/// Fixed set of machine-readable error codes.
#[derive(Clone, Serialize, utoipa::ToSchema)]
pub enum ErrorCode {
    /// Domain validation or business rule violation (422).
    #[serde(rename = "domain_error")]
    DomainError,
    /// Resource not found (404).
    #[serde(rename = "not_found")]
    NotFound,
    /// Access denied (403).
    #[serde(rename = "forbidden")]
    Forbidden,
    /// Resource state conflict (409).
    #[serde(rename = "conflict")]
    Conflict,
    /// Authentication required (401).
    #[serde(rename = "unauthenticated")]
    Unauthenticated,
    /// MFA or step-up authentication required (403).
    #[serde(rename = "step_up_required")]
    StepUpRequired,
    /// Too many failed attempts (429).
    #[serde(rename = "account_locked")]
    AccountLocked,
    /// Email verification required before authenticating (403).
    #[serde(rename = "email_not_verified")]
    EmailNotVerified,
    /// API rate limit exceeded (429).
    #[serde(rename = "rate_limit_exceeded")]
    RateLimitExceeded,
    /// An emailed link ran out of time; ask for another (410).
    #[serde(rename = "link_expired")]
    LinkExpired,
    /// The tenant is suspended, archived or deleted, so no one may sign in to
    /// it or act in its name (403).
    #[serde(rename = "tenant_unavailable")]
    TenantUnavailable,
    /// Server error: details masked in production (500).
    #[serde(rename = "internal_error")]
    InternalError,
    /// A service outside ianua the caller configured failed (502).
    #[serde(rename = "upstream_failed")]
    UpstreamFailed,
    /// Sign-in is under pressure from a flood of failures, and this device
    /// must pass the challenge named in `challenge` before signing in
    /// (401). The same for every address.
    #[serde(rename = "challenge_required")]
    ChallengeRequired,
    /// The request body could not be read as JSON (400).
    #[serde(rename = "malformed_body")]
    MalformedBody,
    /// The request body is JSON, but not the shape the endpoint takes
    /// (422).
    #[serde(rename = "invalid_body")]
    InvalidBody,
    /// The request body was not sent as JSON (415).
    #[serde(rename = "unsupported_media_type")]
    UnsupportedMediaType,
    /// The request body is larger than the server takes (413).
    #[serde(rename = "body_too_large")]
    BodyTooLarge,
    /// The query string is not the shape the endpoint takes (422).
    #[serde(rename = "invalid_query")]
    InvalidQuery,
}

/// Wraps `AppError` so it can be returned from Axum handlers.
pub struct ApiError(pub AppError);

impl From<AppError> for ApiError {
    fn from(e: AppError) -> Self {
        Self(e)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code) = status_and_code(&self.0);

        log_error(&self.0, status);

        let refusal = refusal_of(&self.0);
        let body = ErrorBody {
            error: code,
            message: public_message(&self.0),
            key: refusal.as_ref().and_then(Refusal::key).map(str::to_owned),
            params: refusal.as_ref().map(params_of).unwrap_or_default(),
            details: dev_details(&self.0),
            challenge: challenge_of(&self.0),
        };

        let mut response = (status, axum::Json(body.clone())).into_response();
        if matches!(self.0, AppError::Busy) {
            response.headers_mut().insert(
                axum::http::header::RETRY_AFTER,
                BUSY_RETRY_AFTER_SECONDS.into(),
            );
        }
        if let Some(refusal) = refusal.filter(|refusal| refusal.key().is_some()) {
            response
                .extensions_mut()
                .insert(WordableRefusal { body, refusal });
        }
        response
    }
}

/// The answer refusing a request before any use case ran, such as a body
/// that is not JSON or a caller past their allowance: `refusal`'s words
/// under its key, put into the reader's language by the wording middleware.
pub(crate) fn answered(status: StatusCode, error: ErrorCode, refusal: Refusal) -> Response {
    let body = ErrorBody {
        error,
        message: refusal.as_str().to_owned(),
        key: refusal.key().map(str::to_owned),
        params: params_of(&refusal),
        details: None,
        challenge: None,
    };
    let mut response = (status, axum::Json(body.clone())).into_response();
    response
        .extensions_mut()
        .insert(WordableRefusal { body, refusal });
    response
}

/// The refusal whose words an error answer shows, when it shows one.
fn refusal_of(err: &AppError) -> Option<Refusal> {
    match err {
        AppError::NotFound(refusal)
        | AppError::Forbidden(refusal)
        | AppError::Conflict(refusal)
        | AppError::TenantUnavailable(refusal)
        | AppError::LinkExpired(refusal)
        | AppError::TooManyRequests(refusal) => Some(refusal.clone()),
        AppError::Domain(domain) => domain.refusal(),
        _ => None,
    }
}

/// A refusal's values, by name.
fn params_of(refusal: &Refusal) -> BTreeMap<String, String> {
    refusal
        .values()
        .iter()
        .map(|value| (value.name().to_owned(), value.value().to_owned()))
        .collect()
}

/// The challenge `err` asks the caller to solve, when it asks for one that
/// can be set.
fn challenge_of(err: &AppError) -> Option<ChallengeCode> {
    let AppError::ChallengeRequired(required) = err else {
        return None;
    };
    required.kind().map(ChallengeCode::from)
}

impl ApiError {
    /// Wraps a value object validation failure, or a refusal of the
    /// request's input, as a domain error, keeping its message key.
    pub fn validation(e: impl Into<ianua_domain::shared::errors::DomainError>) -> Self {
        Self(AppError::Domain(e.into()))
    }

    /// Wraps input an outside library refused, such as a malformed UUID or
    /// form, in that library's own English words: it carries no message key.
    pub fn rejected(e: impl std::fmt::Display) -> Self {
        Self::validation(ianua_domain::shared::errors::DomainError::invalid(
            e.to_string(),
        ))
    }
}

/// Maps an `AppError` to its HTTP status code and error code.
pub(crate) fn status_and_code(err: &AppError) -> (StatusCode, ErrorCode) {
    match err {
        AppError::Domain(_) => (StatusCode::UNPROCESSABLE_ENTITY, ErrorCode::DomainError),
        AppError::NotFound(_) => (StatusCode::NOT_FOUND, ErrorCode::NotFound),
        AppError::Forbidden(_) => (StatusCode::FORBIDDEN, ErrorCode::Forbidden),
        AppError::Conflict(_) => (StatusCode::CONFLICT, ErrorCode::Conflict),
        AppError::Unauthenticated => (StatusCode::UNAUTHORIZED, ErrorCode::Unauthenticated),
        AppError::StepUpRequired => (StatusCode::FORBIDDEN, ErrorCode::StepUpRequired),
        AppError::AccountLocked(_) => (StatusCode::TOO_MANY_REQUESTS, ErrorCode::AccountLocked),
        AppError::EmailNotVerified => (StatusCode::FORBIDDEN, ErrorCode::EmailNotVerified),
        AppError::LinkExpired(_) => (StatusCode::GONE, ErrorCode::LinkExpired),
        AppError::TenantUnavailable(_) => (StatusCode::FORBIDDEN, ErrorCode::TenantUnavailable),
        AppError::TooManyRequests(_) | AppError::Busy => {
            (StatusCode::TOO_MANY_REQUESTS, ErrorCode::RateLimitExceeded)
        }
        AppError::ChallengeRequired(_) => (StatusCode::UNAUTHORIZED, ErrorCode::ChallengeRequired),
        AppError::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, ErrorCode::InternalError),
        AppError::Upstream(_) => (StatusCode::BAD_GATEWAY, ErrorCode::UpstreamFailed),
    }
}

/// Logs the error with its full chain. Always runs regardless of env.
pub(crate) fn log_error(err: &AppError, status: StatusCode) {
    match err {
        AppError::Internal(source) => {
            tracing::error!(
                status = status.as_u16(),
                error = %err,
                source = format_error_chain(source.as_ref()),
                "internal server error"
            );
        }
        _ if err.is_server_error() => {
            tracing::error!(status = status.as_u16(), error = %err, "server error");
        }
        _ => {
            tracing::debug!(status = status.as_u16(), error = %err, "client error");
        }
    }
}

/// Returns the message safe for external consumers, as a sentence a person
/// can read.
///
/// The kind of failure is already in the `error` code, so the message is
/// only what went wrong: "Upstreams may not target an internal address", not
/// "domain error: validation failed: upstreams may not …", the error type's
/// own wording for logs.
pub(crate) fn public_message(err: &AppError) -> String {
    let message = match err {
        AppError::Internal(_) => "an internal error occurred".to_owned(),
        AppError::Upstream(_) => "an outside service did not answer; try again later".to_owned(),
        AppError::Busy => "the server is busy checking passwords; try again in a moment".to_owned(),
        AppError::ChallengeRequired(_) => {
            "sign-in is busy right now; pass the challenge to go on".to_owned()
        }
        AppError::NotFound(m)
        | AppError::Forbidden(m)
        | AppError::Conflict(m)
        | AppError::TenantUnavailable(m)
        | AppError::LinkExpired(m)
        | AppError::TooManyRequests(m) => m.to_string(),
        AppError::Domain(domain) => domain_message(domain),
        other => other.to_string(),
    };
    sentence(&message)
}

/// What a domain error says went wrong, without the kind of error in front.
fn domain_message(err: &ianua_domain::shared::errors::DomainError) -> String {
    use ianua_domain::shared::errors::DomainError;
    match err {
        DomainError::Validation(invalid) => invalid.to_string(),
        DomainError::Conflict(refusal)
        | DomainError::Unauthorized(refusal)
        | DomainError::Forbidden(refusal)
        | DomainError::InvalidTransition(refusal) => refusal.to_string(),
        other => other.to_string(),
    }
}

/// `message` starting with a capital letter.
pub(crate) fn sentence(message: &str) -> String {
    let mut chars = message.chars();
    chars
        .next()
        .map(|first| first.to_uppercase().chain(chars).collect())
        .unwrap_or_default()
}

/// Returns internal error details in dev mode, `None` in production.
fn dev_details(err: &AppError) -> Option<String> {
    if !DEV_MODE.load(Ordering::Relaxed) {
        return None;
    }

    let AppError::Internal(source) = err else {
        return None;
    };

    Some(format_error_chain(source.as_ref()))
}

/// Formats an error and its full source chain into a single string.
fn format_error_chain(err: &dyn std::error::Error) -> String {
    let mut chain = String::new();
    chain.push_str(&err.to_string());

    let mut current = err.source();
    while let Some(cause) = current {
        chain.push_str(" → ");
        chain.push_str(&cause.to_string());
        current = cause.source();
    }

    chain
}

#[cfg(test)]
mod tests {
    use ianua_domain::shared::errors::DomainError;

    use super::*;

    /// Ann saves an upstream on an internal address and is told why in a
    /// plain sentence, with no error type in front.
    #[test]
    fn a_validation_failure_reads_as_a_plain_sentence() {
        let err = AppError::Domain(DomainError::invalid(
            "upstreams may not target an internal address",
        ));

        assert_eq!(
            public_message(&err),
            "Upstreams may not target an internal address"
        );
    }

    /// An upstream mail error becomes a general outside-service message
    /// without exposing the server's host or banner.
    #[test]
    fn an_outside_failure_says_nothing_of_the_service() {
        let err = AppError::upstream(std::io::Error::other("smtp.internal.example: 554 banner"));

        assert_eq!(
            public_message(&err),
            "An outside service did not answer; try again later"
        );
    }

    /// A consumer that spent its quota for the period is told `429`, the
    /// status a client backs off on, not a plain refusal.
    #[test]
    fn a_spent_quota_answers_too_many_requests() {
        let (status, _) = status_and_code(&AppError::TooManyRequests(
            "the consumer's quota for this period is spent"
                .to_owned()
                .into(),
        ));

        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    }

    /// A refusal says only what was refused, starting with a capital.
    #[test]
    fn a_refusal_drops_the_error_kind_from_its_message() {
        let err = AppError::Forbidden("invalid TOTP code".to_owned().into());

        assert_eq!(public_message(&err), "Invalid TOTP code");
    }

    /// An internal database failure returns a general message without its cause.
    #[test]
    fn an_internal_failure_still_says_nothing_of_its_cause() {
        let err = AppError::internal_msg("database password rejected");

        assert_eq!(public_message(&err), "An internal error occurred");
    }
}
