//! Application-layer errors.
//!
//! Wraps domain errors and adds app-specific failure modes
//! (authorization failures, not found, conflict, etc.).

use ianua_domain::domains::authentication::risk_engine::challenge::RequiredChallenge;
use ianua_domain::message;
use ianua_domain::shared::errors::{DomainError, Refusal};

/// Simple error wrapper for string messages without a source error.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
struct InternalMessage(String);

/// Application-layer error.
///
/// The API layer maps these to HTTP status codes.
/// The app layer maps domain errors into these.
#[derive(Debug, thiserror::Error)]
pub enum AppError {
    /// A domain rule was violated (validation, state machine, etc.).
    #[error("domain error: {0}")]
    Domain(#[from] DomainError),

    /// The requested resource was not found.
    #[error("not found: {0}")]
    NotFound(Refusal),

    /// The caller doesn't have permission for this operation.
    #[error("forbidden: {0}")]
    Forbidden(Refusal),

    /// The operation conflicts with the current state
    /// (duplicate slug, already exists, etc.).
    #[error("conflict: {0}")]
    Conflict(Refusal),

    /// The caller must authenticate before accessing this resource.
    #[error("authentication required")]
    Unauthenticated,

    /// Step-up authentication is required (MFA, hardware key).
    #[error("step-up authentication required")]
    StepUpRequired,

    /// The account is locked due to too many failed attempts.
    #[error("account locked until {0}")]
    AccountLocked(String),

    /// The user's email address has not been verified yet, which is
    /// required before they can authenticate.
    #[error("email verification required")]
    EmailNotVerified,

    /// The tenant is suspended, archived, or deleted, so nobody signs into it.
    /// Not a credential problem and deliberately not disguised as one: it
    /// applies to every user of the tenant alike, so saying so reveals nothing
    /// about any account, and the person locked out needs to know it is not
    /// their password.
    #[error("tenant unavailable: {0}")]
    TenantUnavailable(Refusal),

    /// An emailed link ran out of time before it was followed. Distinct from
    /// `NotFound`, which is a link that never existed: this one can be
    /// replaced, and the caller should be offered another rather than an
    /// error.
    #[error("link expired: {0}")]
    LinkExpired(Refusal),

    /// A resource the caller may legitimately use is exhausted for now,
    /// concurrent connection slots, in-flight work, and the request should be
    /// retried later rather than treated as denied.
    #[error("too many requests: {0}")]
    TooManyRequests(Refusal),

    /// Every password hash this node may run at once is running, and none
    /// freed up within the wait. Nothing was hashed. Unlike
    /// `TooManyRequests`, which says an allowance is spent for a while, this
    /// passes in a moment, so the caller may retry almost at once.
    #[error("busy: too many password checks are running")]
    Busy,

    /// Password sign-in is under high pressure, and this sign-in came from a
    /// device nobody trusted without a passed challenge. Carries the
    /// challenge it needs. It is the same answer for every address, with an
    /// account or without, so it says nothing about any account.
    #[error("challenge required")]
    ChallengeRequired(RequiredChallenge),

    /// An infrastructure dependency failed (database, cache, external API).
    /// Preserves the full error chain for logging/tracing.
    #[error("internal error: {0}")]
    Internal(#[source] Box<dyn std::error::Error + Send + Sync>),

    /// A service outside ianua that the caller configured, such as a model
    /// provider, failed or could not be reached. Ianua itself did its part:
    /// what it recorded about the attempt stands.
    #[error("upstream service failed: {0}")]
    Upstream(#[source] Box<dyn std::error::Error + Send + Sync>),
}

impl AppError {
    /// Maps a `DomainError` to the correct `AppError` variant.
    ///
    /// Unlike the blanket `From<DomainError>` which maps everything to
    /// `Domain(...)`, this preserves the semantic meaning:
    /// - `DomainError::Forbidden` → `AppError::Forbidden`
    /// - `DomainError::Unauthorized` → `AppError::Forbidden`: a credential
    ///   the domain refused to trust, such as a passkey whose counter went
    ///   backwards, is a refusal of the attempt, not bad input
    /// - `DomainError::NotFound` → `AppError::NotFound`
    /// - `DomainError::Conflict` → `AppError::Conflict`
    /// - `DomainError::Infrastructure` → `AppError::Internal`
    /// - Everything else → `AppError::Domain`
    pub fn from_domain(err: DomainError) -> Self {
        match err {
            DomainError::Forbidden(refusal) | DomainError::Unauthorized(refusal) => {
                Self::Forbidden(refusal)
            }
            DomainError::NotFound => {
                Self::NotFound(message!("app-entity-not-found", "entity not found"))
            }
            DomainError::Conflict(refusal) => Self::Conflict(refusal),
            DomainError::Infrastructure(source) => Self::Internal(source),
            other => Self::Domain(other),
        }
    }

    /// Wraps any error as an internal infrastructure failure.
    ///
    /// Preserves the original error as the source, the API layer
    /// masks it from callers but tracing captures the full chain.
    pub fn internal(err: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self::Internal(Box::new(err))
    }

    /// Wraps the failure of a service outside ianua that the caller
    /// configured.
    pub fn upstream(err: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self::Upstream(Box::new(err))
    }

    /// Creates an internal error from a descriptive message.
    ///
    /// Use when there's no source error to wrap, e.g. invariant
    /// violations that indicate a bug rather than an infra failure.
    pub fn internal_msg(msg: impl Into<String>) -> Self {
        Self::Internal(Box::new(InternalMessage(msg.into())))
    }

    /// Whether this error indicates a client mistake (4xx).
    #[must_use]
    pub fn is_client_error(&self) -> bool {
        matches!(
            self,
            Self::Domain(_)
                | Self::NotFound(_)
                | Self::Forbidden(_)
                | Self::Conflict(_)
                | Self::Unauthenticated
                | Self::StepUpRequired
                | Self::AccountLocked(_)
                | Self::EmailNotVerified
                | Self::TenantUnavailable(_)
                | Self::LinkExpired(_)
                | Self::TooManyRequests(_)
                | Self::Busy
                | Self::ChallengeRequired(_)
        )
    }

    /// Whether this error indicates a server problem (5xx): ours, or an
    /// outside service's that we called.
    #[must_use]
    pub fn is_server_error(&self) -> bool {
        matches!(self, Self::Internal(_) | Self::Upstream(_))
    }
}

/// Turns a failure reaching storage or another port into
/// [`AppError::Internal`], keeping the original error as its source.
pub(crate) trait OrInternal<T> {
    /// The value, or the failure as an internal error.
    ///
    /// # Errors
    ///
    /// Returns `AppError::Internal` wrapping the original error.
    fn or_internal(self) -> Result<T, AppError>;
}

impl<T, E> OrInternal<T> for Result<T, E>
where
    E: std::error::Error + Send + Sync + 'static,
{
    fn or_internal(self) -> Result<T, AppError> {
        self.map_err(AppError::internal)
    }
}

/// Turns a lookup that found nothing into [`AppError::NotFound`].
pub(crate) trait OrNotFound<T> {
    /// The value, or `AppError::NotFound` carrying `message`.
    ///
    /// # Errors
    ///
    /// Returns `AppError::NotFound` when there is no value.
    fn or_not_found(self, message: impl Into<Refusal>) -> Result<T, AppError>;
}

impl<T> OrNotFound<T> for Option<T> {
    fn or_not_found(self, message: impl Into<Refusal>) -> Result<T, AppError> {
        self.ok_or_else(|| AppError::NotFound(message.into()))
    }
}

/// Turns a write storage refused because the record changed since it was
/// read into [`AppError::Conflict`], and any other failure into
/// [`AppError::Internal`].
pub(crate) trait OrConflict<T> {
    /// The value, `AppError::Conflict` carrying `message` when storage
    /// refused the write as a conflict, or the failure as an internal
    /// error.
    ///
    /// # Errors
    ///
    /// - `AppError::Conflict` when storage answered `DomainError::Conflict`.
    /// - `AppError::Internal` wrapping any other error.
    fn or_conflict(self, message: impl Into<Refusal>) -> Result<T, AppError>;
}

impl<T> OrConflict<T> for Result<T, DomainError> {
    fn or_conflict(self, message: impl Into<Refusal>) -> Result<T, AppError> {
        self.map_err(|error| match error {
            DomainError::Conflict(_) => AppError::Conflict(message.into()),
            other => AppError::internal(other),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A stale-write refusal becomes a conflict with the supplied message,
    /// while an infrastructure failure remains internal.
    #[test]
    fn a_refused_stale_write_is_a_conflict() {
        let stale: Result<(), DomainError> = Err(DomainError::conflict("changed meanwhile"));
        let broken: Result<(), DomainError> = Err(DomainError::infra_msg("disk gone"));

        let refused = stale.or_conflict("the request was answered meanwhile");
        let failed = broken.or_conflict("the request was answered meanwhile");

        assert!(matches!(
            refused,
            Err(AppError::Conflict(message)) if message == "the request was answered meanwhile"
        ));
        assert!(matches!(failed, Err(AppError::Internal(_))));
    }

    fn every_client_error() -> Vec<AppError> {
        vec![
            AppError::Domain(DomainError::invalid("bad")),
            AppError::NotFound("x".into()),
            AppError::Forbidden("x".into()),
            AppError::Conflict("x".into()),
            AppError::Unauthenticated,
            AppError::StepUpRequired,
            AppError::AccountLocked("x".to_owned()),
            AppError::EmailNotVerified,
            AppError::TenantUnavailable("x".into()),
            AppError::LinkExpired("x".into()),
            AppError::TooManyRequests("x".into()),
            AppError::Busy,
            AppError::ChallengeRequired(RequiredChallenge::Unavailable),
        ]
    }

    /// Every failure the caller caused, from bad input to too many requests,
    /// a busy node or a missing challenge, counts as the caller's mistake
    /// and never as a server problem.
    #[test]
    fn every_caller_side_failure_is_a_client_error_and_not_a_server_error() {
        for err in every_client_error() {
            assert!(err.is_client_error(), "{err:?}");
            assert!(!err.is_server_error(), "{err:?}");
        }
    }

    /// The database cannot be reached. That is a server problem, not the
    /// caller's mistake.
    #[test]
    fn an_internal_failure_is_a_server_error_and_not_a_client_error() {
        let err = AppError::internal_msg("database unreachable");

        assert!(err.is_server_error());
        assert!(!err.is_client_error());
    }

    /// A configured outside service failing is answered with a 502, so it is
    /// logged as the server problem it is, not as the caller's mistake.
    #[test]
    fn an_upstream_failure_is_a_server_error_and_not_a_client_error() {
        let err = AppError::upstream(std::io::Error::other("connection refused"));

        assert!(err.is_server_error());
        assert!(!err.is_client_error());
    }

    /// A domain authentication refusal becomes a forbidden error carrying
    /// the original reason rather than an input-validation error.
    #[test]
    fn a_credential_the_domain_does_not_trust_is_forbidden() {
        let err = AppError::from_domain(DomainError::unauthorized("the key may be a copy"));

        assert!(matches!(err, AppError::Forbidden(message) if message == "the key may be a copy"));
    }

    /// An internal error keeps its message, so the logs say what went wrong.
    #[test]
    fn an_internal_message_keeps_its_text_for_tracing() {
        let err = AppError::internal_msg("database unreachable");

        assert_eq!(err.to_string(), "internal error: database unreachable");
    }

    /// A store that cannot be reached becomes an internal error, and the
    /// original failure stays attached to it.
    #[test]
    fn a_port_failure_becomes_an_internal_error_keeping_its_source() {
        let failed: Result<(), DomainError> = Err(DomainError::infra_msg("store unreachable"));

        let Err(AppError::Internal(source)) = failed.or_internal() else {
            panic!("a port failure must become an internal error");
        };

        assert!(source.downcast_ref::<DomainError>().is_some());
    }

    /// A lookup that finds nothing becomes a not found error with the message
    /// the caller chose.
    #[test]
    fn nothing_found_becomes_not_found_with_the_given_message() {
        let missing: Option<u8> = None;

        let result = missing.or_not_found("user not found");

        assert!(matches!(result, Err(AppError::NotFound(message)) if message == "user not found"));
    }

    /// A lookup that finds something hands the value back unchanged.
    #[test]
    fn a_found_value_passes_through() {
        assert_eq!(Some(7).or_not_found("user not found").unwrap(), 7);
    }
}
