//! The answers every sign-in and every reset give alike, so none of them
//! says which part of the attempt was wrong.

use ianua_domain::message;

use crate::error::AppError;

/// The one answer every refused sign-in gets: a tenant's, an
/// organization's, an operator's and a directory bind's alike.
pub(crate) fn invalid_credentials() -> AppError {
    AppError::NotFound(message!(
        "authentication-invalid-credentials",
        "invalid credentials"
    ))
}

/// The answer to setting up an authenticator app for someone who already
/// has one in use, a member or a tenant's person alike.
pub(crate) fn already_enrolled() -> AppError {
    AppError::Conflict(message!(
        "authentication-mfa-is-already-enrolled",
        "MFA is already enrolled"
    ))
}

/// The answer to a link that can no longer set a password: unknown,
/// expired, superseded, used, or spent by another request a moment before,
/// all alike.
pub(crate) fn unusable_reset_link() -> AppError {
    AppError::NotFound(message!(
        "authentication-invalid-or-expired-reset-link",
        "invalid or expired reset link"
    ))
}
