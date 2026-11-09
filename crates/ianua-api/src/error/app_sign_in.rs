//! How a refused app sign-in is told to the gateway.

use ianua_app::error::AppError;
use ianua_domain::types::DenialStatus;

use crate::error::{log_error, status_and_code};

/// The status and machine-readable code a refused app sign-in answers the
/// gateway with, which answers the browser with them.
///
/// The gateway gets values, not an error body: the message can name what
/// went wrong in a way meant for an administrator, and the gateway decides
/// for itself what a person at the app's door is told.
pub(crate) fn rejection(err: &AppError) -> (DenialStatus, String) {
    let (status, code) = status_and_code(err);
    log_error(err, status);
    let code = serde_json::to_value(&code)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_default();
    let status = DenialStatus::new(status.as_u16()).unwrap_or(DenialStatus::SERVICE_UNAVAILABLE);
    (status, code)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Ann's account is locked after too many tries; the app is told `429`
    /// with the `account_locked` code.
    #[test]
    fn a_locked_account_is_told_as_too_many_requests_with_its_code() {
        let (status, code) = rejection(&AppError::AccountLocked("in five minutes".to_owned()));

        assert_eq!(status, DenialStatus::TOO_MANY_REQUESTS);
        assert_eq!(code, "account_locked");
    }

    /// A refused sign-up is told as `403` with the `forbidden` code, and the
    /// app never sees the message behind it.
    #[test]
    fn a_refusal_carries_its_code_and_never_its_message() {
        let (status, code) = rejection(&AppError::Forbidden("sign-up is off".to_owned().into()));

        assert_eq!(status, DenialStatus::FORBIDDEN);
        assert_eq!(code, "forbidden");
    }
}
