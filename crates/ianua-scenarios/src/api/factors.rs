//! A tenant user's second factors: setting up an authenticator app,
//! answering a sign-in with it or a recovery code, passkeys, and what they
//! hold.

use super::{Request, TenantPath, with_query};
use crate::net::Call;
use crate::wire::factors::{
    ConfirmFactor, ConfirmPasskey, ConfirmWaitingPasskey, FactorCode, FactorOptions, FactorSetup,
    FactorStatus, PasskeyAnswerBody, PasskeyChallenge, PasskeySignInFor, Passkeys,
    RecoveryCodesShown, RegenerateRecoveryCodes, RenamePasskey, SessionCode, TotpSetup,
};
use crate::wire::tenant_sign_in::TenantSession;

/// `POST …/auth/mfa/enroll`: starts setting up an authenticator app.
#[must_use]
pub fn enroll_totp(tenant: &TenantPath, setup: &FactorSetup) -> Request<TotpSetup> {
    Request::of(Call::post(tenant.at("/auth/mfa/enroll")).json(setup))
}

/// `POST …/auth/mfa/enroll/confirm`: confirms it with a code it shows.
#[must_use]
pub fn confirm_totp(tenant: &TenantPath, confirm: &ConfirmFactor) -> Request<RecoveryCodesShown> {
    Request::of(Call::post(tenant.at("/auth/mfa/enroll/confirm")).json(confirm))
}

/// `POST …/auth/mfa/enroll/abandon`: gives up a setup never confirmed.
#[must_use]
pub fn abandon_totp(tenant: &TenantPath, setup: &FactorSetup) -> Request<()> {
    Request::of(Call::post(tenant.at("/auth/mfa/enroll/abandon")).json(setup))
}

/// `DELETE …/auth/mfa`: turns the factor off with a code from it.
#[must_use]
pub fn disable(tenant: &TenantPath, code: &FactorCode) -> Request<()> {
    Request::of(Call::delete(tenant.at("/auth/mfa")).json(code))
}

/// `GET …/auth/mfa/status`.
#[must_use]
pub fn status(tenant: &TenantPath) -> Request<FactorStatus> {
    Request::of(Call::get(tenant.at("/auth/mfa/status")))
}

/// `GET …/auth/mfa/options`, for the waiting sign-in `session_id` names
/// when it names one.
#[must_use]
pub fn options(tenant: &TenantPath, session_id: Option<&str>) -> Request<FactorOptions> {
    let pairs: Vec<(&str, &str)> = session_id
        .map(|id| ("session_id", id))
        .into_iter()
        .collect();
    Request::of(Call::get(with_query(
        &tenant.at("/auth/mfa/options"),
        &pairs,
    )))
}

/// `POST …/auth/mfa/verify`: answers a waiting sign-in with a code.
#[must_use]
pub fn verify(tenant: &TenantPath, code: &SessionCode) -> Request<()> {
    Request::of(Call::post(tenant.at("/auth/mfa/verify")).json(code))
}

/// `POST …/auth/recovery-code`: answers a waiting sign-in with a recovery
/// code instead.
#[must_use]
pub fn redeem_recovery_code(tenant: &TenantPath, code: &SessionCode) -> Request<()> {
    Request::of(Call::post(tenant.at("/auth/recovery-code")).json(code))
}

/// `POST …/auth/recovery-codes/regenerate`: replaces every recovery code.
#[must_use]
pub fn regenerate_recovery_codes(
    tenant: &TenantPath,
    regenerate: &RegenerateRecoveryCodes,
) -> Request<RecoveryCodesShown> {
    Request::of(Call::post(tenant.at("/auth/recovery-codes/regenerate")).json(regenerate))
}

/// `POST …/auth/session/resume`: lifts a session's suspension with a code.
#[must_use]
pub fn resume_session(tenant: &TenantPath, code: &SessionCode) -> Request<()> {
    Request::of(Call::post(tenant.at("/auth/session/resume")).json(code))
}

/// `POST …/auth/passkey/register`: starts adding a passkey, signed in.
#[must_use]
pub fn begin_passkey(tenant: &TenantPath) -> Request<PasskeyChallenge> {
    Request::of(Call::post(tenant.at("/auth/passkey/register")))
}

/// `POST …/auth/passkey/register/confirm`: finishes adding it.
#[must_use]
pub(crate) fn confirm_passkey(tenant: &TenantPath, confirm: &ConfirmPasskey) -> Request<()> {
    Request::of(Call::post(tenant.at("/auth/passkey/register/confirm")).json(confirm))
}

/// `POST …/auth/sign-in/passkey/register`: a sign-in that must set up a
/// factor starts adding a passkey as that factor.
#[must_use]
pub fn begin_waiting_passkey(tenant: &TenantPath) -> Request<PasskeyChallenge> {
    Request::of(Call::post(tenant.at("/auth/sign-in/passkey/register")))
}

/// `POST …/auth/sign-in/passkey/register/confirm`: finishes the passkey a
/// waiting sign-in set up, with no proof: the sign-in is the leave.
#[must_use]
pub fn confirm_waiting_passkey(
    tenant: &TenantPath,
    confirm: &ConfirmWaitingPasskey,
) -> Request<()> {
    Request::of(Call::post(tenant.at("/auth/sign-in/passkey/register/confirm")).json(confirm))
}

/// `POST …/auth/passkey/login`: a sign-in challenge listing the passkeys
/// of the address.
#[must_use]
pub fn begin_passkey_sign_in(
    tenant: &TenantPath,
    whose: &PasskeySignInFor,
) -> Request<PasskeyChallenge> {
    Request::of(Call::post(tenant.at("/auth/passkey/login")).json(whose))
}

/// `POST …/auth/passkey/login/discover`: a sign-in challenge naming
/// nobody.
#[must_use]
pub fn begin_discoverable_sign_in(tenant: &TenantPath) -> Request<PasskeyChallenge> {
    Request::of(Call::post(tenant.at("/auth/passkey/login/discover")))
}

/// `POST …/auth/passkey/login/confirm`: signs in with the passkey's
/// answer.
#[must_use]
pub fn confirm_passkey_sign_in(
    tenant: &TenantPath,
    answer: &PasskeyAnswerBody,
) -> Request<TenantSession> {
    Request::of(Call::post(tenant.at("/auth/passkey/login/confirm")).json(answer))
}

/// `GET …/auth/passkeys`: the caller's passkeys.
#[must_use]
pub fn passkeys(tenant: &TenantPath) -> Request<Passkeys> {
    Request::of(Call::get(tenant.at("/auth/passkeys")))
}

/// `PATCH …/auth/passkeys/{id}`: changes the name a passkey is listed
/// under.
#[must_use]
pub fn rename_passkey(tenant: &TenantPath, passkey_id: &str, name: &RenamePasskey) -> Request<()> {
    let path = tenant.at(&format!("/auth/passkeys/{passkey_id}"));
    Request::of(Call::patch(path).json(name))
}

/// `DELETE …/auth/passkeys/{id}`.
#[must_use]
pub fn remove_passkey(tenant: &TenantPath, passkey_id: &str) -> Request<()> {
    Request::of(Call::delete(
        tenant.at(&format!("/auth/passkeys/{passkey_id}")),
    ))
}
