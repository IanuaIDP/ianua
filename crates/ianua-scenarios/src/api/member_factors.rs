//! An organization member's authenticators: enrolling TOTP and passkeys,
//! signing in with a passkey, and answering a factor with a recovery code.
//! The session is the bearer the call carries; a sign-in still owing its
//! factor sends its own.

use super::{OrgPath, Request};
use crate::net::Call;
use crate::wire::factors::{
    ConfirmFactor, FactorCode, FactorStatus, PasskeyAnswerBody, PasskeyChallenge, PasskeySignInFor,
    Passkeys, RecoveryCodesShown, TotpSetup,
};
use crate::wire::sign_in::{
    ConfirmMemberPasskey, MemberFactorSetup, MemberRecoveryAccepted, MemberRecoveryCode, SignedIn,
};

/// `GET …/mfa/status`: whether the calling member holds an active second
/// factor, and which.
#[must_use]
pub fn status(org: &OrgPath) -> Request<FactorStatus> {
    Request::of(Call::get(org.at("/mfa/status")))
}

/// `POST …/mfa/begin`: starts setting up an authenticator app.
#[must_use]
pub fn begin_totp(org: &OrgPath, setup: &MemberFactorSetup) -> Request<TotpSetup> {
    Request::of(Call::post(org.at("/mfa/begin")).json(setup))
}

/// `POST …/mfa/begin`: starts the enrollment owed by the bearer session,
/// without a separate password proof. The returned setup still needs a
/// confirmation code before that session can finish signing in.
#[must_use]
pub fn begin_required_totp(org: &OrgPath) -> Request<TotpSetup> {
    Request::of(Call::post(org.at("/mfa/begin")))
}

/// `POST …/mfa/abandon`: discards an unconfirmed setup after fresh proof.
#[must_use]
pub fn abandon_totp(org: &OrgPath, setup: &MemberFactorSetup) -> Request<()> {
    Request::of(Call::post(org.at("/mfa/abandon")).json(setup))
}

/// `DELETE …/mfa`: turns off the caller's factor after a current code.
#[must_use]
pub fn disable_totp(org: &OrgPath, code: &FactorCode) -> Request<()> {
    Request::of(Call::delete(org.at("/mfa")).json(code))
}

/// `POST …/mfa/confirm`: confirms it with a code it shows.
#[must_use]
pub fn confirm_totp(org: &OrgPath, confirm: &ConfirmFactor) -> Request<RecoveryCodesShown> {
    Request::of(Call::post(org.at("/mfa/confirm")).json(confirm))
}

/// `POST …/mfa/verify`: answers the bearer's waiting sign-in with a code.
#[must_use]
pub fn verify(org: &OrgPath, code: &FactorCode) -> Request<()> {
    Request::of(Call::post(org.at("/mfa/verify")).json(code))
}

/// `POST …/mfa/recovery`: answers a waiting sign-in with a recovery code.
#[must_use]
pub fn redeem_recovery_code(
    org: &OrgPath,
    code: &MemberRecoveryCode,
) -> Request<MemberRecoveryAccepted> {
    Request::of(Call::post(org.at("/mfa/recovery")).json(code))
}

/// `POST …/mfa/recovery-codes`: replaces the member's printout after fresh proof.
#[must_use]
pub fn regenerate_recovery_codes(
    org: &OrgPath,
    proof: &MemberFactorSetup,
) -> Request<RecoveryCodesShown> {
    Request::of(Call::post(org.at("/mfa/recovery-codes")).json(proof))
}

/// `POST …/passkeys/register`: begins adding a passkey while signed in.
#[must_use]
pub fn begin_passkey(org: &OrgPath) -> Request<PasskeyChallenge> {
    Request::of(Call::post(org.at("/passkeys/register")))
}

/// `POST …/passkeys/register`: requests a registration challenge under the
/// waiting sign-in's authority. `WaitingSignIn` selects required enrollment;
/// obtaining the challenge alone does not finish it.
#[must_use]
pub fn begin_required_passkey(org: &OrgPath) -> Request<PasskeyChallenge> {
    Request::of(
        Call::post(org.at("/passkeys/register"))
            .json(&serde_json::json!({"from": "WaitingSignIn"})),
    )
}

/// `POST …/passkeys/register/confirm`: adds the attested passkey.
#[must_use]
pub fn confirm_passkey(org: &OrgPath, confirm: &ConfirmMemberPasskey) -> Request<()> {
    Request::of(Call::post(org.at("/passkeys/register/confirm")).json(confirm))
}

/// `POST /api/v1/passkey/login`: starts sign-in for an email address.
#[must_use]
pub fn begin_passkey_sign_in(whose: &PasskeySignInFor) -> Request<PasskeyChallenge> {
    Request::of(Call::post("/api/v1/passkey/login").json(whose))
}

/// `POST /api/v1/passkey/login/discover`: starts usernameless sign-in.
#[must_use]
pub fn begin_discoverable_sign_in() -> Request<PasskeyChallenge> {
    Request::of(Call::post("/api/v1/passkey/login/discover"))
}

/// `POST /api/v1/passkey/login/confirm`: answers with the passkey.
#[must_use]
pub fn confirm_passkey_sign_in(answer: &PasskeyAnswerBody) -> Request<SignedIn> {
    Request::of(Call::post("/api/v1/passkey/login/confirm").json(answer))
}

/// `GET …/passkeys`: lists the member's own passkeys.
#[must_use]
pub fn passkeys(org: &OrgPath) -> Request<Passkeys> {
    Request::of(Call::get(org.at("/passkeys")))
}

/// `DELETE …/passkeys/{id}`: removes the member's passkey.
#[must_use]
pub fn remove_passkey(org: &OrgPath, id: &str) -> Request<()> {
    Request::of(Call::delete(org.at(&format!("/passkeys/{id}"))))
}
