//! The notes a sign-in page shows above its form.
//!
//! A note arrives as a code in the page's address, so anyone can write one.
//! Only codes from a fixed set become notes; anything else is shown as a
//! plain failure, never as itself. The notes themselves belong to the
//! [`PageRenderer`](crate::ports::pages::PageRenderer) port that draws them.

pub use crate::ports::pages::{Refusal, SignInNote};

impl SignInNote {
    /// The note a code from the page's address stands for. A code this does
    /// not know is shown as a plain failure, never as itself.
    #[must_use]
    pub fn from_code(code: &str) -> Self {
        match code {
            "check_email" => Self::CheckEmail,
            "verified" => Self::Verified,
            "password_reset" => Self::PasswordReset,
            "password_change_required" => Self::PasswordChangeRequired,
            refused => Self::Refused(Refusal::from_code(refused)),
        }
    }
}

impl Refusal {
    /// The refusal an error code from the API stands for.
    fn from_code(code: &str) -> Self {
        match code {
            "not_found" | "unauthenticated" => Self::NotAccepted,
            "account_locked" => Self::Locked,
            "email_not_verified" => Self::NotVerified,
            "too_many_requests" | "rate_limit_exceeded" => Self::TooMany,
            "forbidden" => Self::NotAllowed,
            "domain_error" | "malformed" => Self::Invalid,
            "link_expired" => Self::LinkExpired,
            "step_up_required" => Self::CodeNeeded,
            "tenant_unavailable" | "unavailable" => Self::Unavailable,
            missing if missing.starts_with("missing_") => Self::Invalid,
            _ => Self::Failed,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A page is asked for with a note code it knows. Each becomes its note.
    #[test]
    fn known_codes_become_their_notes() {
        assert_eq!(SignInNote::from_code("check_email"), SignInNote::CheckEmail);
        assert_eq!(SignInNote::from_code("verified"), SignInNote::Verified);
        assert_eq!(
            SignInNote::from_code("password_reset"),
            SignInNote::PasswordReset
        );
        assert_eq!(
            SignInNote::from_code("password_change_required"),
            SignInNote::PasswordChangeRequired
        );
        assert_eq!(
            SignInNote::from_code("step_up_required"),
            SignInNote::Refused(Refusal::CodeNeeded)
        );
        assert_eq!(
            SignInNote::from_code("not_found"),
            SignInNote::Refused(Refusal::NotAccepted)
        );
        assert_eq!(
            SignInNote::from_code("missing_password"),
            SignInNote::Refused(Refusal::Invalid)
        );
    }

    /// Script markup supplied as a note code maps to the generic failure
    /// note instead of becoming display text.
    #[test]
    fn an_unknown_code_is_a_plain_failure() {
        assert_eq!(
            SignInNote::from_code("<script>alert(1)</script>"),
            SignInNote::Refused(Refusal::Failed)
        );
    }
}
