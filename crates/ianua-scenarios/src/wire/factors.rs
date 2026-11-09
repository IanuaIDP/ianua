//! A tenant user's second factors: an authenticator app, passkeys and
//! recovery codes, set up, answered and listed.

use serde::{Deserialize, Serialize};

/// What a signed-in person gives to prove who they are again before a
/// change an open session must not make alone. Holds a password, so it
/// has no `Debug`.
#[derive(Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Proof {
    /// Their password typed again, with a code from their authenticator
    /// when they have one.
    Password {
        /// Current account secret proving the session holder's identity again.
        password: String,
        /// A code from their authenticator.
        #[serde(skip_serializing_if = "Option::is_none")]
        code: Option<String>,
    },
    /// Their passkey's answer to a sign-in challenge opened for them.
    Passkey(PasskeyAnswerBody),
}

/// `POST …/auth/mfa/enroll` and `…/mfa/enroll/abandon`: the proof of a
/// signed-in person, or none for a sign-in waiting for the factor. Holds
/// a password, so it has no `Debug`.
#[derive(Clone, Default, Serialize)]
pub struct FactorSetup {
    /// The proof, or nothing for a sign-in that owes the factor.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<Proof>,
}

/// The link an authenticator app scans. Holds its secret, so it has no
/// `Debug`.
#[derive(Clone, Deserialize)]
pub struct TotpSetup {
    /// The `otpauth://` link, carrying the secret.
    pub otpauth_uri: String,
}

/// `POST …/auth/mfa/enroll/confirm`: a code from the new authenticator.
#[derive(Debug, Clone, Serialize)]
pub struct ConfirmFactor {
    /// The code it shows.
    pub code: String,
    /// The sign-in waiting for this first factor, which the code finishes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
}

/// The recovery codes a confirmed factor comes with, shown this once.
/// Holds them, so it has no `Debug`.
#[derive(Clone, Deserialize)]
pub struct RecoveryCodesShown {
    /// Single-use alternatives to the second factor, revealed only at issuance.
    pub recovery_codes: Vec<String>,
}

/// `POST …/auth/recovery-codes/regenerate`. Holds a proof, so it has no
/// `Debug`.
#[derive(Clone, Serialize)]
pub struct RegenerateRecoveryCodes {
    /// The person's proof of who they are.
    pub proof: Proof,
}

/// `POST …/auth/mfa/verify`, `…/auth/recovery-code` and
/// `…/auth/session/resume`: a code for a session's second factor. Holds the
/// code, so it has no `Debug`.
#[derive(Clone, Serialize)]
pub struct SessionCode {
    /// The session the code is for, the caller's own.
    pub session_id: String,
    /// The code as typed: from the authenticator, or a recovery code.
    pub code: String,
}

/// `DELETE …/auth/mfa`: a code from the authenticator being turned off.
#[derive(Debug, Clone, Serialize)]
pub struct FactorCode {
    /// The code it shows.
    pub code: String,
}

/// `GET …/auth/mfa/status`.
#[derive(Debug, Clone, Deserialize)]
pub struct FactorStatus {
    /// Whether a second factor is in force.
    pub enabled: bool,
    /// Its kind, such as `Totp`, when one is.
    #[serde(default)]
    pub method: Option<String>,
}

/// `GET …/auth/mfa/options`: what may be set up, what is held, what a
/// waiting sign-in owes.
#[derive(Debug, Clone, Deserialize)]
pub struct FactorOptions {
    /// The kinds offered: `totp`, `email_code`, `sms_code`.
    pub offered: Vec<String>,
    /// The factor held.
    pub held: HeldFactor,
    /// Whether a waiting sign-in still owes a factor.
    pub mfa_required: bool,
}

/// The factor a person holds, as far as it went.
#[derive(Debug, Clone, Deserialize)]
pub struct HeldFactor {
    /// `none`, `pending` or `in_force`.
    pub state: String,
    /// Its kind, unless there is none.
    #[serde(default)]
    pub method: Option<String>,
}

/// A WebAuthn ceremony begun: the id naming the state the server keeps,
/// and the options for the browser, base64url JSON.
#[derive(Debug, Clone, Deserialize)]
pub struct PasskeyChallenge {
    /// The ceremony's id, sent back with the answer.
    pub ceremony_id: String,
    /// The options for `navigator.credentials`, base64url JSON.
    pub challenge: String,
}

/// `POST …/auth/passkey/register/confirm`. Holds a proof, so it has no
/// `Debug`.
#[derive(Clone, Serialize)]
pub(crate) struct ConfirmPasskey {
    /// The ceremony the answer is for.
    pub(crate) ceremony_id: String,
    /// The browser's answer, base64url JSON.
    pub(crate) response: String,
    /// The name the passkey is listed under.
    pub(crate) passkey_name: String,
    /// The signed-in person's proof of who they are; none for a sign-in
    /// setting up its factor.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) proof: Option<Proof>,
}

/// `POST …/auth/sign-in/passkey/register/confirm`: the attestation a
/// waiting sign-in sends for the factor it owes.
#[derive(Debug, Clone, Serialize)]
pub struct ConfirmWaitingPasskey {
    /// The ceremony the answer is for.
    pub ceremony_id: String,
    /// The browser's answer, base64url JSON.
    pub response: String,
    /// The name the passkey is listed under.
    pub passkey_name: String,
}

/// `PATCH …/auth/passkeys/{id}`: the name a passkey is listed under.
#[derive(Debug, Clone, Serialize)]
pub struct RenamePasskey {
    /// The new name.
    pub name: String,
}

/// `POST …/auth/passkey/login`: whose passkeys the challenge lists.
#[derive(Debug, Clone, Serialize)]
pub struct PasskeySignInFor {
    /// The person's address.
    pub email: String,
}

/// A passkey's answer to a challenge, as the API takes it: on its own to
/// sign in, or inside a [`Proof`].
#[derive(Debug, Clone, Serialize)]
pub struct PasskeyAnswerBody {
    /// The ceremony the answer is for.
    pub ceremony_id: String,
    /// The browser's answer, base64url JSON.
    pub response: String,
    /// The credential that answered, base64url.
    pub credential_id: String,
}

/// `GET …/auth/passkeys`.
#[derive(Debug, Clone, Deserialize)]
pub struct Passkeys {
    /// The passkeys, oldest first.
    pub passkeys: Vec<PasskeyEntry>,
}

/// One passkey of a person's.
#[derive(Debug, Clone, Deserialize)]
pub struct PasskeyEntry {
    /// Handle used to rename or remove the enrolled authenticator.
    pub id: String,
    /// The name it is listed under.
    pub name: String,
    /// `platform` or `cross_platform`.
    pub authenticator_type: String,
    /// When it was last used to sign in, if ever.
    #[serde(default)]
    pub last_used_at: Option<String>,
}
