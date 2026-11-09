//! What a use case's refusal answers over LDAP: a result code and a message
//! safe to send. A fault inside the platform is only logged; the client is
//! told the operation failed, never why.

use ianua_app::error::AppError;
use ianua_domain::shared::errors::DomainError;
use ldap3_proto::proto::LdapResultCode;

use crate::session::Session;

/// The answer to `error`. A bind the use case no longer counts signs the
/// connection out, so its next request is nobody's until it binds again.
pub(super) fn refusal(session: &mut Session, error: AppError) -> (LdapResultCode, String) {
    match error {
        AppError::Unauthenticated => {
            session.sign_out();
            (
                LdapResultCode::InvalidCredentials,
                "the bind no longer counts; bind again".to_owned(),
            )
        }
        AppError::Forbidden(refusal) => {
            (LdapResultCode::InsufficentAccessRights, refusal.to_string())
        }
        AppError::NotFound(refusal) => (LdapResultCode::NoSuchObject, refusal.to_string()),
        AppError::Conflict(refusal) => (LdapResultCode::ConstraintViolation, refusal.to_string()),
        AppError::TooManyRequests(refusal) => (LdapResultCode::Busy, refusal.to_string()),
        AppError::Busy => (LdapResultCode::Busy, "busy, try again shortly".to_owned()),
        AppError::TenantUnavailable(refusal) => (LdapResultCode::Unavailable, refusal.to_string()),
        AppError::Domain(error) => domain_refusal(error),
        AppError::StepUpRequired
        | AppError::ChallengeRequired(_)
        | AppError::AccountLocked(_)
        | AppError::EmailNotVerified
        | AppError::LinkExpired(_) => (
            LdapResultCode::InsufficentAccessRights,
            "not allowed over the directory".to_owned(),
        ),
        error @ (AppError::Internal(_) | AppError::Upstream(_)) => failed(&error),
    }
}

/// The answer to a domain rule the operation broke.
fn domain_refusal(error: DomainError) -> (LdapResultCode, String) {
    match error {
        DomainError::TenantSuspended => (
            LdapResultCode::Unavailable,
            "this directory is unavailable".to_owned(),
        ),
        fault @ DomainError::Infrastructure(_) => failed(&fault),
        other => (LdapResultCode::ConstraintViolation, other.to_string()),
    }
}

/// The answer to a fault inside the platform, logged with its causes.
fn failed(error: &dyn std::error::Error) -> (LdapResultCode, String) {
    tracing::warn!(%error, "ldap: an operation failed");
    (
        LdapResultCode::OperationsError,
        "operation failed".to_owned(),
    )
}
