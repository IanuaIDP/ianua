//! A tenant user signing in to their tenant: a password or a passkey, the
//! session it opens and what it still owes, confirming it from the
//! mailbox, refreshing and ending it, and changing or resetting the
//! password.

use serde::{Deserialize, Serialize};

use super::sign_in::Owed;

/// `POST …/tenants/{tenant}/login`: an address and a password. Holds the
/// password, so it has no `Debug`.
#[derive(Clone, Serialize)]
pub struct TenantPasswordSignIn {
    /// The address.
    pub email: String,
    /// Account secret checked before opening a tenant session.
    pub password: String,
    /// The secret a browser keeps for a device the person trusted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint_hash: Option<String>,
}

/// What a tenant password sign-in answered. Holds a token, so it has no
/// `Debug`.
#[derive(Clone, Deserialize)]
#[serde(untagged)]
pub enum TenantSignedIn {
    /// A session opened, owing what its flags say.
    Session(TenantSession),
    /// The password was right but must change before a session opens.
    PasswordChangeRequired(PasswordChangeOwed),
}

/// A session a tenant sign-in opened, by password or passkey. Holds its
/// token, so it has no `Debug`.
#[derive(Clone, Deserialize)]
pub struct TenantSession {
    /// The session's id.
    pub session_id: String,
    /// The token the session is used with, as `Authorization: Bearer`.
    pub refresh_token: String,
    /// Whether it owes more before it is let in.
    pub mfa_required: bool,
    /// Whether a second factor must be set up first.
    pub mfa_enrollment_required: bool,
    /// Whether it waits for the link mailed to the person.
    pub email_confirmation_required: bool,
    /// The person's name.
    #[serde(default)]
    pub display_name: Option<String>,
}

impl TenantSession {
    /// What this session still owes, read from its flags.
    #[must_use]
    pub fn owed(&self) -> Owed {
        owed_by(
            self.mfa_required,
            self.email_confirmation_required,
            self.mfa_enrollment_required,
        )
    }
}

/// A sign-in whose password must change first. Holds the change's token,
/// so it has no `Debug`.
#[derive(Clone, Deserialize)]
pub struct PasswordChangeOwed {
    /// Always `true`.
    pub password_change_required: bool,
    /// `set_by_admin` or `expired`.
    pub reason: String,
    /// `none`, `own_factor` or `mailed_link`.
    pub proof: String,
    /// The single-use token the new password is set with, unless mailed.
    #[serde(default)]
    pub change_token: Option<String>,
}

/// `POST …/auth/sign-in/confirm`: the mailed link's token and the waiting
/// session's. Holds both, so it has no `Debug`.
#[derive(Clone, Serialize)]
pub struct ConfirmTenantSignIn {
    /// The token from the mailed link.
    pub link: String,
    /// The waiting session's token, as this browser holds it.
    pub session_token: String,
}

/// The sign-in a mailed link confirmed, and what it still owes.
#[derive(Debug, Clone, Deserialize)]
pub struct ConfirmedTenantSignIn {
    /// The session confirmed.
    pub session_id: String,
    /// Whether it still owes more.
    pub mfa_required: bool,
    /// Whether a second factor must be set up next.
    pub mfa_enrollment_required: bool,
    /// Whether it still waits for a mailed link.
    pub email_confirmation_required: bool,
}

impl ConfirmedTenantSignIn {
    /// What the confirmed session still owes.
    #[must_use]
    pub fn owed(&self) -> Owed {
        owed_by(
            self.mfa_required,
            self.email_confirmation_required,
            self.mfa_enrollment_required,
        )
    }
}

/// `POST …/auth/token/refresh`. Holds the token, so it has no `Debug`.
#[derive(Clone, Serialize)]
pub struct RefreshSession {
    /// The current refresh token, spent by the trade.
    pub refresh_token: String,
}

/// The session a refresh started. Holds its token, so it has no `Debug`.
#[derive(Clone, Deserialize)]
pub struct RefreshedSession {
    /// The new session's id.
    pub session_id: String,
    /// Replacement bearer credential issued after spending the previous one.
    pub refresh_token: String,
}

/// `POST …/auth/password/reset-request`: the address a reset link goes to.
#[derive(Debug, Clone, Serialize)]
pub struct PasswordResetFor {
    /// The address.
    pub email: String,
}

/// `POST …/auth/password/reset-status`: what a tenant's reset link is worth.
#[derive(Debug, Clone, Deserialize)]
pub struct ResetLinkWorth {
    /// `Valid`, `Expired`, `AlreadyUsed` or `Invalid`.
    pub status: String,
    /// The rules the reset enforces, only on a `Valid` link.
    #[serde(default)]
    pub password_policy: Option<serde_json::Value>,
}

/// `GET …/auth/sign-in-options`: what a tenant's sign-in page offers.
#[derive(Debug, Clone, Deserialize)]
pub struct SignInOptions {
    /// Whether it offers an emailed sign-in link.
    pub magic_link: bool,
    /// Whether it offers a passkey.
    pub passkey: bool,
    /// The identity providers it offers as buttons.
    pub connections: Vec<SignInConnection>,
}

/// One identity provider a sign-in page offers as a button.
#[derive(Debug, Clone, Deserialize)]
pub struct SignInConnection {
    /// The connection to begin single sign-on with.
    pub id: String,
    /// The name on the button.
    pub name: String,
    /// `oidc` or `saml`.
    pub protocol: String,
}

/// `POST …/auth/password/reset-confirm`. Holds the token and the
/// password, so it has no `Debug`.
#[derive(Clone, Serialize)]
pub struct ConfirmPasswordReset {
    /// The token from the mailed link.
    pub token: String,
    /// Replacement secret chosen by the holder of the mailed reset proof.
    pub new_password: String,
    /// A code from the person's authenticator, when they have one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mfa_code: Option<String>,
}

/// `POST …/auth/password/change`. Holds passwords, so it has no `Debug`.
#[derive(Clone, Serialize)]
pub struct ChangePassword {
    /// The current password, typed again.
    pub old_password: String,
    /// Replacement secret checked against the tenant's current password rules.
    pub new_password: String,
    /// A code from the person's authenticator, when they have one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mfa_code: Option<String>,
}

/// A password set, and what the breach lookup said about it.
#[derive(Debug, Clone, Deserialize)]
pub struct PasswordSet {
    /// What the lookup said.
    pub password_breach: BreachVerdict,
}

/// What the breach lookup said about a new password.
#[derive(Debug, Clone, Deserialize)]
pub struct BreachVerdict {
    /// `not_checked`, `unchecked`, `clean` or `breached`.
    pub status: String,
}

/// What a session owes, from its three flags.
fn owed_by(mfa_required: bool, by_mail: bool, enrol: bool) -> Owed {
    match (mfa_required, by_mail, enrol) {
        (false, _, _) => Owed::Nothing,
        (true, true, _) => Owed::MailedConfirmation,
        (true, false, true) => Owed::FactorEnrolment,
        (true, false, false) => Owed::FactorCode,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A session answer reads as a session, owing a code when the person
    /// has a factor.
    #[test]
    fn a_session_answer_reads_as_a_session() {
        let answer: TenantSignedIn = serde_json::from_str(
            r#"{"session_id":"s","refresh_token":"t","mfa_required":true,
                "mfa_enrollment_required":false,"email_confirmation_required":false,
                "tenant_id":"x","tenant_name":"Prod","display_name":"Ann"}"#,
        )
        .unwrap();

        let TenantSignedIn::Session(session) = answer else {
            panic!("a session answer reads as one");
        };
        assert_eq!(session.owed(), Owed::FactorCode);
    }

    /// An answer owing a new password reads as one.
    #[test]
    fn a_password_change_answer_reads_as_one() {
        let answer: TenantSignedIn = serde_json::from_str(
            r#"{"password_change_required":true,"reason":"set_by_admin","proof":"none",
                "change_token":"c","expires_at":"2026-10-28T10:00:00Z"}"#,
        )
        .unwrap();

        assert!(matches!(answer, TenantSignedIn::PasswordChangeRequired(_)));
    }
}
