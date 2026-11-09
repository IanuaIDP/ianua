//! An organization member signing in to the dashboard: the password or a
//! mailed link, the session it opens, confirming that session from the
//! mailbox, the devices a member remembers, moving a session into a
//! tenant, a forgotten password reset by mail, registering a passkey,
//! answering a waiting sign-in with a recovery code, and the puzzle a
//! browser solves before signing in while sign-in is under pressure.

use serde::{Deserialize, Serialize};

/// `POST /api/v1/login`: a member's address and password. Holds a
/// password, so it has no `Debug`.
#[derive(Clone, Serialize)]
pub struct PasswordSignIn {
    /// The address.
    pub email: String,
    /// Account secret checked before opening an organization session.
    pub password: String,
    /// The organization to sign in to, once a sign-in offered a choice.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization: Option<String>,
    /// The tenant to land in.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant_slug: Option<String>,
    /// The secret the browser keeps for itself, by which a device the
    /// member remembered is known again.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint_hash: Option<String>,
    /// The solution to the puzzle an earlier answer asked for, while
    /// sign-in is under pressure: `challenge.counter`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub challenge_proof: Option<String>,
}

impl PasswordSignIn {
    /// A sign-in of `email` with `password`, naming no organization or
    /// tenant and no device: the first sign-in, before any choice was
    /// offered, from a client that keeps no device secret.
    #[must_use]
    pub fn of(email: &str, password: &str) -> Self {
        Self {
            email: email.to_owned(),
            password: password.to_owned(),
            organization: None,
            tenant_slug: None,
            fingerprint_hash: None,
            challenge_proof: None,
        }
    }

    /// The same sign-in from the browser that keeps `device_secret`.
    #[must_use]
    pub fn from_device(mut self, device_secret: &str) -> Self {
        self.fingerprint_hash = Some(device_secret.to_owned());
        self
    }

    /// The same sign-in carrying `proof`, the solution to the puzzle the
    /// platform asked this browser for.
    #[must_use]
    pub fn solving(mut self, proof: &str) -> Self {
        self.challenge_proof = Some(proof.to_owned());
        self
    }
}

/// `POST …/mfa/begin` from a signed-in member: their password typed again
/// as the leave to set up a second factor. Holds the password, so it has
/// no `Debug`.
#[derive(Clone, Serialize)]
pub struct MemberFactorSetup {
    /// The password typed again.
    pub proof: MemberProof,
}

/// A member's password typed again, with a code when they hold a factor.
/// Holds the password, so it has no `Debug`.
#[derive(Clone, Serialize)]
pub struct MemberProof {
    /// Current account secret proving the signed-in member's identity again.
    pub password: String,
    /// The code their authenticator shows, once they have one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
}

/// `POST …/devices`: remember the device signed in from, by the secret its
/// browser keeps. Holds the secret, so it has no `Debug`.
#[derive(Clone, Serialize)]
pub struct RememberDevice {
    /// The browser's secret.
    pub fingerprint_hash: String,
    /// The name shown in the member's device list.
    pub device_name: String,
}

/// What a password sign-in answered. Holds the session's token, so it has
/// no `Debug`.
#[derive(Clone, Deserialize)]
#[serde(tag = "status")]
pub enum SignedIn {
    /// A session was opened, owing what the flags say.
    #[serde(rename = "authenticated")]
    Authenticated(Session),
    /// The password opened accounts in several organizations; sign in
    /// again naming one.
    #[serde(rename = "choose_organization")]
    ChooseOrganization {
        /// The organizations to choose from.
        organizations: Vec<OfferedOrganization>,
    },
}

/// A session a sign-in opened. Holds its token, so it has no `Debug`.
#[derive(Clone, Deserialize)]
pub struct Session {
    /// The session's id.
    pub session_id: String,
    /// The token the session is used with, as `Authorization: Bearer`.
    pub refresh_token: String,
    /// Whether it owes more before it is let in.
    pub mfa_required: bool,
    /// Whether a second factor must be set up first.
    pub mfa_enrollment_required: bool,
    /// Whether it waits for the link mailed to the member.
    pub email_confirmation_required: bool,
    /// The organization's id.
    pub organization_id: String,
    /// The organization's slug.
    pub org_slug: String,
    /// The tenant it works in, when the member reaches one.
    #[serde(default)]
    pub tenant_slug: Option<String>,
}

/// What a session still owes before it is let in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Owed {
    /// All sign-in requirements are satisfied and access may proceed.
    Nothing,
    /// Following the link mailed to the member.
    MailedConfirmation,
    /// Setting up a second factor.
    FactorEnrolment,
    /// A code from the member's second factor.
    FactorCode,
}

impl Session {
    /// What this session still owes, read from its flags.
    #[must_use]
    pub fn owed(&self) -> Owed {
        match (
            self.mfa_required,
            self.email_confirmation_required,
            self.mfa_enrollment_required,
        ) {
            (false, _, _) => Owed::Nothing,
            (true, true, _) => Owed::MailedConfirmation,
            (true, false, true) => Owed::FactorEnrolment,
            (true, false, false) => Owed::FactorCode,
        }
    }
}

/// An organization a sign-in may go on to.
#[derive(Debug, Clone, Deserialize)]
pub struct OfferedOrganization {
    /// Stable organization identifier accompanying the sign-in choice.
    pub organization_id: String,
    /// Its slug, to name when signing in again.
    pub slug: String,
    /// Human-readable label shown when choosing an organization.
    pub name: String,
}

/// `POST /api/v1/login/confirm`: the mailed link's token and the waiting
/// session's. Holds both, so it has no `Debug`.
#[derive(Clone, Serialize)]
pub struct ConfirmSignIn {
    /// The token from the mailed link.
    pub token: String,
    /// The waiting session's token.
    pub refresh_token: String,
}

/// The sign-in a mailed link confirmed.
#[derive(Debug, Clone, Deserialize)]
pub struct ConfirmedSignIn {
    /// The session confirmed.
    pub session_id: String,
    /// Whether a second factor must be set up before it is let in.
    pub mfa_enrollment_required: bool,
}

/// `POST …/organizations/{org}/logout`: the member's own session to end.
#[derive(Debug, Clone, Serialize)]
pub struct SignOut {
    /// The session's id.
    pub session_id: String,
}

/// `POST /api/v1/login/magic-link`: the address a sign-in link goes to.
#[derive(Debug, Clone, Serialize)]
pub struct MagicLinkRequest {
    /// The address.
    pub email: String,
}

/// `POST /api/v1/login/magic-link/verify`: the mailed link followed.
/// Holds its token, so it has no `Debug`.
#[derive(Clone, Serialize)]
pub struct MagicLinkSignIn {
    /// The token from the mailed link.
    pub token: String,
    /// The tenant to land in.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant_slug: Option<String>,
}

/// The device a member remembered, from `POST …/devices`.
#[derive(Debug, Clone, Deserialize)]
pub struct DeviceRemembered {
    /// The device's id.
    pub device_id: String,
}

/// `GET …/devices`: the member's own devices.
#[derive(Debug, Clone, Deserialize)]
pub struct Devices {
    /// The devices, in the order they were remembered.
    pub devices: Vec<Device>,
}

/// One device a member remembered.
#[derive(Debug, Clone, Deserialize)]
pub struct Device {
    /// Handle used to revoke trust in this remembered browser.
    pub id: String,
    /// The name it was remembered under.
    pub name: String,
    /// `trusted` or `revoked`.
    pub status: String,
}

/// `POST …/devices/revoke`: the member's own device to forget.
#[derive(Debug, Clone, Serialize)]
pub struct ForgetDevice {
    /// The device's id.
    pub device_id: String,
}

/// `POST …/switch-tenant`: the tenant to move the session into.
#[derive(Debug, Clone, Serialize)]
pub struct SwitchTenant {
    /// The tenant's id.
    pub tenant_id: String,
}

/// The session that replaced the old one, from `POST …/switch-tenant`.
/// Holds its token, so it has no `Debug`.
#[derive(Clone, Deserialize)]
pub struct MovedSession {
    /// The new session's id.
    pub session_id: String,
    /// Its token, as `Authorization: Bearer`.
    pub refresh_token: String,
    /// The tenant it works in.
    pub tenant_id: String,
}

/// `POST /api/v1/password/reset-request`: the address a member forgot
/// the password of.
#[derive(Debug, Clone, Serialize)]
pub struct MemberPasswordResetFor {
    /// The address.
    pub email: String,
}

/// `POST /api/v1/password/reset-confirm`: the mailed link's token and
/// the new password, with a code from the member's second factor when
/// they have one. Holds secrets, so it has no `Debug`.
#[derive(Clone, Serialize)]
pub struct ConfirmMemberPasswordReset {
    /// The token from the mailed link.
    pub token: String,
    /// The password to set.
    pub password: String,
    /// A code from the member's authenticator, when they have one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mfa_code: Option<String>,
}

/// `POST /api/v1/password/reset-status`: a reset link asked about
/// without spending it. Holds its token, so it has no `Debug`.
#[derive(Clone, Serialize)]
pub struct ResetLinkToken {
    /// The token from the mailed link.
    pub token: String,
}

/// What a reset link is worth.
#[derive(Debug, Clone, Deserialize)]
pub struct ResetLinkStatus {
    /// `Valid`, `Expired`, `AlreadyUsed` or `Invalid`.
    pub status: String,
}

/// The cooldown returned after another reset email is accepted.
#[derive(Debug, Clone, Deserialize)]
pub struct ResetLinkResent {
    /// Seconds before the next replacement may be requested.
    pub retry_after_seconds: u64,
}

/// An organization passkey registration, with the member's password
/// typed again. Holds proof, so it has no `Debug`.
#[derive(Clone, Serialize)]
pub struct ConfirmMemberPasskey {
    /// The server-held ceremony.
    pub ceremony_id: String,
    /// The authenticator's attestation, base64url JSON.
    pub response: String,
    /// The name shown in the member's list.
    pub passkey_name: String,
    /// The member's proof, absent when enrolling during sign-in.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<MemberProof>,
}

/// A recovery code for a waiting member session. Holds a secret, so it
/// has no `Debug`.
#[derive(Clone, Serialize)]
pub struct MemberRecoveryCode {
    /// An unused code from the member's printout.
    pub code: String,
}

/// What a member must do after spending a recovery code.
#[derive(Debug, Clone, Deserialize)]
pub struct MemberRecoveryAccepted {
    /// Whether a new factor must be enrolled before access is allowed.
    pub mfa_enrollment_required: bool,
}

/// `POST /api/v1/sign-in/puzzle`: the puzzle a browser solves before its
/// next sign-in while sign-in is under pressure. The browser finds a
/// decimal counter whose SHA-256 of `challenge:counter` starts with
/// `difficulty_bits` zero bits, and signs in with `challenge.counter`.
#[derive(Debug, Clone, Deserialize)]
pub struct SignInPuzzle {
    /// The sealed challenge.
    pub challenge: String,
    /// The zero bits the hash must start with.
    pub difficulty_bits: u8,
}
