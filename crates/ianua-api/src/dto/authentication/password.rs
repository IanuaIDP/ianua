//! Password and mailbox sign-in bodies: signing in with a password or an
//! emailed link, confirming a sign-in by mail, and changing or resetting a
//! password.

use ianua_app::email::{LinkScope, TokenResent};
use ianua_app::ports::authentication::ChallengePuzzle;
use ianua_app::services::authentication::fresh_proof::ReenteredProof;
use ianua_app::services::authentication::sign_in_gate::ClientOrigin;
use ianua_app::use_cases::authentication::password::{
    ChangeRequest, ChangeToken, ConfirmSignInRequest, ConfirmedSignIn, ConsumeMagicLinkRequest,
    LoginAttempt, LoginTenant, MagicLinkLoginSuccess, PasswordChangeOwed, RequestMagicLinkRequest,
    ResendResetRequest, ResetConfirmRequest, ResetMailRequest, TenantChangeDueRequest,
    TenantLoginOutcome, TenantLoginRequest, TenantLoginSuccess,
};
use ianua_domain::domains::authentication::credentials::breach::NewPasswordBreach;
use ianua_domain::domains::authentication::device_trust::{DeviceSecret, PresentedSecret};
use ianua_domain::domains::authentication::recovery::change_proof::ChangeProof;
use ianua_domain::domains::authentication::risk_engine::challenge::ChallengeProof;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{
    Email, PasswordLinkStatus, PasswordPolicy, SessionId, TenantId, TokenStatus,
};
use serde::{Deserialize, Serialize};

use crate::dto::authentication::sign_in::OwedFactors;
use crate::error::ApiError;

/// A password sign-in to a tenant.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct TenantLoginBody {
    /// The email address to authenticate.
    pub email: String,
    /// The password to verify.
    pub password: String,
    /// The secret this browser keeps for itself, if it was trusted before:
    /// 64 hex digits it made at random.
    ///
    /// Matching a device the user has already trusted is what lets the
    /// step-up policy skip a second factor. Absent, unrecognised and revoked
    /// all mean the same thing: challenge them.
    #[serde(default)]
    pub fingerprint_hash: Option<String>,
    /// The proof that this browser passed the challenge an earlier answer
    /// asked for (`challenge_required`), while the tenant's sign-in is
    /// under pressure. Leave it out otherwise.
    #[serde(default)]
    pub challenge_proof: Option<String>,
}

impl TenantLoginBody {
    /// The sign-in to `tenant`, made from `origin`.
    ///
    /// # Errors
    ///
    /// Returns a validation error for an address, a device secret or a
    /// challenge proof that is not well formed.
    pub(crate) fn login(
        self,
        tenant: LoginTenant,
        origin: ClientOrigin,
    ) -> Result<TenantLoginRequest, ApiError> {
        Ok(TenantLoginRequest {
            tenant,
            attempt: LoginAttempt {
                email: Email::new(&self.email).map_err(ApiError::validation)?,
                password: Secret::new(self.password),
                device_secret: dashboard_device(self.fingerprint_hash)?,
                challenge: challenge_proof_of(self.challenge_proof)?,
                origin,
            },
        })
    }
}

/// `raw` as the proof of a passed challenge, when one is given.
///
/// # Errors
///
/// `422` when it is empty, too long or not plain ASCII.
pub(crate) fn challenge_proof_of(raw: Option<String>) -> Result<Option<ChallengeProof>, ApiError> {
    raw.map(ChallengeProof::new)
        .transpose()
        .map_err(ApiError::validation)
}

/// A new session from a tenant user's password sign-in.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct TenantLoginResponse {
    /// The newly created session ID.
    #[schema(value_type = String, format = Uuid)]
    pub session_id: SessionId,
    /// The raw refresh token, to send as the bearer from now on.
    pub refresh_token: String,
    /// What the session still owes before it is finished.
    #[serde(flatten)]
    pub owed: OwedFactors,
    /// The resolved tenant's ID.
    #[schema(value_type = String, format = Uuid)]
    pub tenant_id: TenantId,
    /// The resolved tenant's display name.
    pub tenant_name: String,
    /// The tenant user's display name.
    pub display_name: String,
}

impl From<TenantLoginSuccess> for TenantLoginResponse {
    fn from(success: TenantLoginSuccess) -> Self {
        Self {
            session_id: success.session_id,
            refresh_token: success.refresh_token.expose().to_owned(),
            owed: success.second_factor.into(),
            tenant_id: success.tenant_id,
            tenant_name: success.tenant_name,
            display_name: success.display_name,
        }
    }
}

/// What a password sign-in to a tenant answers: a session, or the new
/// password the sign-in owes before one opens.
#[derive(Serialize, utoipa::ToSchema)]
#[serde(untagged)]
pub(crate) enum TenantLoginAnswer {
    /// A session opened.
    SignedIn(TenantLoginResponse),
    /// The password was right, but must change before a session opens.
    PasswordChangeRequired(PasswordChangeRequiredResponse),
}

impl From<TenantLoginOutcome> for TenantLoginAnswer {
    fn from(outcome: TenantLoginOutcome) -> Self {
        match outcome {
            TenantLoginOutcome::SignedIn(success) => Self::SignedIn(success.into()),
            TenantLoginOutcome::PasswordChangeOwed(owed) => {
                Self::PasswordChangeRequired(owed.into())
            }
        }
    }
}

/// A sign-in whose right password an admin set, or which expired. No
/// session opened; set a new password with the change's token to finish
/// it.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct PasswordChangeRequiredResponse {
    /// Always `true`: tells this answer from a session.
    pub password_change_required: bool,
    /// Why: `set_by_admin` or `expired`.
    pub reason: String,
    /// What the change asks besides the new password: `none`; `own_factor`,
    /// a code from the person's own second factor sent as `code`; or
    /// `mailed_link`, when the token went to the person's mailbox instead
    /// of coming back here.
    pub proof: String,
    /// The single-use token the new password is set with, for this sign-in
    /// only; absent when it was mailed. Keep it in memory; never store or
    /// log it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub change_token: Option<String>,
    /// When the token stops working.
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: time::OffsetDateTime,
}

impl From<PasswordChangeOwed> for PasswordChangeRequiredResponse {
    fn from(owed: PasswordChangeOwed) -> Self {
        let change_token = match owed.token {
            ChangeToken::HandedBack(token) => Some(token.expose().to_owned()),
            ChangeToken::Mailed => None,
        };
        Self {
            password_change_required: true,
            reason: owed.reason.as_str().to_owned(),
            proof: proof_name(owed.proof).to_owned(),
            change_token,
            expires_at: owed.expires_at,
        }
    }
}

/// The name an answer gives `proof`.
pub(crate) fn proof_name(proof: ChangeProof) -> &'static str {
    match proof {
        ChangeProof::PasswordAlone => "none",
        ChangeProof::OwnFactor => "own_factor",
        ChangeProof::MailedLink => "mailed_link",
        ChangeProof::NotPossible => "not_possible",
    }
}

/// The new password a sign-in owes, set with the change's token.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct DuePasswordChangeBody {
    /// The change's token: the `change_token` the sign-in answered with, or
    /// the one in the mailed link.
    pub change_token: String,
    /// The new password. It must meet the tenant's rules and repeat none
    /// of the account's recent ones.
    pub new_password: String,
    /// A code from the person's own second factor, when the sign-in's
    /// `proof` was `own_factor`.
    #[serde(default)]
    pub code: Option<String>,
    /// The secret this browser keeps for itself, if it was trusted before,
    /// as the sign-in sent it.
    #[serde(default)]
    pub fingerprint_hash: Option<String>,
}

impl DuePasswordChangeBody {
    /// The change for the sign-in to `tenant`, made from `origin`.
    ///
    /// # Errors
    ///
    /// Returns a validation error for a device secret that is not well
    /// formed.
    pub(crate) fn change(
        self,
        tenant: LoginTenant,
        origin: ClientOrigin,
    ) -> Result<TenantChangeDueRequest, ApiError> {
        Ok(TenantChangeDueRequest {
            tenant,
            change_token: Secret::new(self.change_token),
            new_password: Secret::new(self.new_password),
            factor_code: self.code,
            device_secret: dashboard_device(self.fingerprint_hash)?,
            origin,
        })
    }
}

/// The remembered browser's secret the dashboard sent, as presented at the
/// dashboard's own sign-in.
///
/// # Errors
///
/// `ApiError` validation when it is not 64 hex digits.
fn dashboard_device(fingerprint_hash: Option<String>) -> Result<Option<PresentedSecret>, ApiError> {
    fingerprint_hash
        .map(|secret| DeviceSecret::new(secret).map(PresentedSecret::on_dashboard))
        .transpose()
        .map_err(ApiError::validation)
}

/// A request for a magic-link (passwordless) sign-in email.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct RequestMagicLinkBody {
    /// The email address to send the sign-in link to.
    pub email: String,
}

impl RequestMagicLinkBody {
    /// The request, with the link landing on `scope`, made from `origin`.
    ///
    /// # Errors
    ///
    /// Returns a validation error for an address that is not well formed.
    pub(crate) fn request(
        self,
        scope: LinkScope,
        origin: ClientOrigin,
    ) -> Result<RequestMagicLinkRequest, ApiError> {
        Ok(RequestMagicLinkRequest {
            email: Email::new(&self.email).map_err(ApiError::validation)?,
            scope,
            origin,
        })
    }
}

/// The token of a magic link being followed.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct ConsumeMagicLinkBody {
    /// The single-use token from the emailed link.
    pub token: String,
}

impl ConsumeMagicLinkBody {
    /// The request following the link, made from `origin`.
    #[must_use]
    pub(crate) fn request(self, origin: ClientOrigin) -> ConsumeMagicLinkRequest {
        ConsumeMagicLinkRequest {
            raw_token: self.token,
            origin,
        }
    }
}

/// A new session from a magic link.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct MagicLinkLoginResponse {
    /// The newly created session ID.
    #[schema(value_type = String, format = Uuid)]
    pub session_id: SessionId,
    /// The raw refresh token.
    pub refresh_token: String,
    /// What the session still owes before it is finished.
    #[serde(flatten)]
    pub owed: OwedFactors,
}

impl From<MagicLinkLoginSuccess> for MagicLinkLoginResponse {
    fn from(success: MagicLinkLoginSuccess) -> Self {
        Self {
            session_id: success.session_id,
            refresh_token: success.refresh_token.expose().to_owned(),
            owed: success.second_factor.into(),
        }
    }
}

/// The link mailed to confirm a sign-in, and the sign-in it confirms.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct ConfirmSignInBody {
    /// The single-use token from the emailed link.
    pub link: String,
    /// The refresh token of the sign-in waiting for the confirmation, as
    /// this browser holds it. The link only finishes the sign-in it was
    /// mailed for, in the browser that began it.
    pub session_token: String,
}

impl ConfirmSignInBody {
    /// The confirmation, made from `origin`.
    #[must_use]
    pub(crate) fn request(self, origin: ClientOrigin) -> ConfirmSignInRequest {
        ConfirmSignInRequest {
            link: Secret::new(self.link),
            session_token: Secret::new(self.session_token),
            origin,
        }
    }
}

/// A sign-in the mailbox confirmed.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct ConfirmedSignInResponse {
    /// The session the link confirmed.
    #[schema(value_type = String, format = Uuid)]
    pub session_id: SessionId,
    /// What the session still owes, such as a factor to set up next.
    #[serde(flatten)]
    pub owed: OwedFactors,
}

impl From<ConfirmedSignIn> for ConfirmedSignInResponse {
    fn from(confirmed: ConfirmedSignIn) -> Self {
        Self {
            session_id: confirmed.session_id,
            owed: confirmed.second_factor.into(),
        }
    }
}

/// A signed-in person's new password, and their current one as proof.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct PasswordChangeBody {
    /// The current password, typed again.
    pub old_password: String,
    /// The new password, held to the tenant's rules.
    pub new_password: String,
    /// A code from the person's authenticator, needed when they have one.
    #[serde(default)]
    pub mfa_code: Option<String>,
}

impl From<PasswordChangeBody> for ChangeRequest {
    fn from(body: PasswordChangeBody) -> Self {
        Self {
            proof: ReenteredProof::Password {
                password: Secret::new(body.old_password),
                code: body.mfa_code,
            },
            new_password: Secret::new(body.new_password),
        }
    }
}

/// The address a forgotten password is reset for.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct PasswordResetRequestBody {
    /// The address the reset link goes to, if it has an account.
    pub email: String,
}

impl PasswordResetRequestBody {
    /// The request, with the link landing on `scope`.
    ///
    /// # Errors
    ///
    /// Returns a validation error for an address that is not well formed.
    pub(crate) fn request(self, scope: LinkScope) -> Result<ResetMailRequest, ApiError> {
        Ok(ResetMailRequest {
            email: Email::new(&self.email).map_err(ApiError::validation)?,
            scope,
        })
    }
}

/// The reset link's token and the new password.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct PasswordResetConfirmBody {
    /// The single-use token from the reset email.
    pub token: String,
    /// The new password, held to the tenant's rules.
    pub new_password: String,
    /// A code from the account's authenticator, required when the account has
    /// an active second factor.
    ///
    /// Whoever holds the reset token also writes this body, so only a code
    /// proves the factor: a mailbox alone must not get past it.
    #[serde(default)]
    pub mfa_code: Option<String>,
}

impl From<PasswordResetConfirmBody> for ResetConfirmRequest {
    fn from(body: PasswordResetConfirmBody) -> Self {
        Self {
            raw_token: body.token,
            new_password: Secret::new(body.new_password),
            mfa_code: body.mfa_code,
        }
    }
}

/// The token from an emailed link, submitted to ask what it is worth or to
/// replace it.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct TokenStatusBody {
    /// The single-use token from the link.
    pub token: String,
}

impl TokenStatusBody {
    /// The request replacing the link, with the new one landing on `scope`.
    #[must_use]
    pub(crate) fn resend(self, scope: LinkScope) -> ResendResetRequest {
        ResendResetRequest {
            raw_token: self.token,
            scope,
        }
    }
}

/// What a link that sets a password is worth, and the rules the new password
/// must meet.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct PasswordLinkStatusResponse {
    /// `Valid`, `Expired`, `AlreadyUsed`, or `Invalid`.
    #[schema(schema_with = crate::dto::schemas::token_status)]
    pub status: TokenStatus,
    /// The policy the new password must meet. Present only when `status` is
    /// `Valid`, the one answer that offers the form, and absent even then for
    /// a tenant without password login, where there is no password to
    /// choose.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<Object>)]
    pub password_policy: Option<PasswordPolicy>,
}

impl From<PasswordLinkStatus> for PasswordLinkStatusResponse {
    fn from(answer: PasswordLinkStatus) -> Self {
        Self {
            status: answer.token_status(),
            password_policy: answer.password_policy().cloned(),
        }
    }
}

/// What the breach lookup said about a password someone set.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct PasswordBreachResponse {
    /// `not_checked` when the tenant does not look new passwords up,
    /// `unchecked` when the lookup could not be made, `clean`, or
    /// `breached`, which a tenant that only warns lets through: tell the
    /// person to choose another.
    pub status: &'static str,
    /// How many times the password appeared in known breaches, for
    /// `breached` only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub occurrences: Option<u64>,
}

impl From<NewPasswordBreach> for PasswordBreachResponse {
    fn from(breach: NewPasswordBreach) -> Self {
        let (status, occurrences) = match breach {
            NewPasswordBreach::NotChecked => ("not_checked", None),
            NewPasswordBreach::Unchecked => ("unchecked", None),
            NewPasswordBreach::Clean => ("clean", None),
            NewPasswordBreach::Breached(count) => ("breached", Some(count)),
        };
        Self {
            status,
            occurrences,
        }
    }
}

/// A password set, and what the breach lookup said about it.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct PasswordSetResponse {
    /// What the breach lookup said about the new password.
    pub password_breach: PasswordBreachResponse,
}

impl From<NewPasswordBreach> for PasswordSetResponse {
    fn from(breach: NewPasswordBreach) -> Self {
        Self {
            password_breach: breach.into(),
        }
    }
}

/// Another link is on its way.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct TokenResentResponse {
    /// Seconds before another may be requested. Count this down rather than
    /// assuming a value: it is the wait the server enforces.
    pub retry_after_seconds: u64,
}

impl From<TokenResent> for TokenResentResponse {
    fn from(resent: TokenResent) -> Self {
        Self {
            retry_after_seconds: resent.retry_after_seconds,
        }
    }
}

/// A puzzle to solve before signing in while sign-in is under pressure.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct SignInPuzzleResponse {
    /// The sealed puzzle. Find a decimal `counter` whose SHA-256 of
    /// `challenge:counter` starts with `difficulty_bits` zero bits, then send
    /// `challenge.counter` as the sign-in's `challenge_proof`.
    pub challenge: String,
    /// The zero bits the hash must start with.
    pub difficulty_bits: u8,
    /// When the puzzle stops counting.
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: time::OffsetDateTime,
}

impl From<ChallengePuzzle> for SignInPuzzleResponse {
    fn from(puzzle: ChallengePuzzle) -> Self {
        Self {
            challenge: puzzle.challenge,
            difficulty_bits: puzzle.difficulty_bits,
            expires_at: puzzle.expires_at,
        }
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authentication::credentials::password_rules::ChangeReason;

    use super::*;

    /// Ann's new password is on a leaked list her tenant only warns about.
    /// She is told it was found, and how often.
    #[test]
    fn a_breached_password_says_how_often_it_was_found() {
        let answer = PasswordBreachResponse::from(NewPasswordBreach::Breached(12));

        assert_eq!(answer.status, "breached");
        assert_eq!(answer.occurrences, Some(12));
    }

    /// A lookup that could not be made says so, with no count, so the page
    /// does not tell Ann her password is safe.
    #[test]
    fn an_unchecked_password_is_not_called_clean() {
        let answer = PasswordBreachResponse::from(NewPasswordBreach::Unchecked);

        assert_eq!(answer.status, "unchecked");
        assert_eq!(answer.occurrences, None);
    }

    /// The JSON a sign-in owing a change of a password an admin set
    /// answers, its token gone out as `token` and asking `proof`.
    fn answer_to(token: ChangeToken, proof: ChangeProof) -> serde_json::Value {
        let owed = PasswordChangeOwed {
            token,
            proof,
            reason: ChangeReason::SetByAdmin,
            expires_at: time::OffsetDateTime::UNIX_EPOCH,
        };
        let answer = TenantLoginAnswer::from(TenantLoginOutcome::PasswordChangeOwed(owed));
        serde_json::to_value(answer).unwrap()
    }

    /// Sam set Ann's password and she holds an authenticator. Her sign-in
    /// answers that it must change, why, the code it asks for, and the
    /// token to change it with, with no session in it.
    #[test]
    fn a_sign_in_owing_a_new_password_answers_the_change_token() {
        let json = answer_to(
            ChangeToken::HandedBack(Secret::new("change-token")),
            ChangeProof::OwnFactor,
        );

        assert_eq!(json["password_change_required"], true);
        assert_eq!(json["reason"], "set_by_admin");
        assert_eq!(json["proof"], "own_factor");
        assert_eq!(json["change_token"], "change-token");
        assert!(json.get("session_id").is_none());
    }

    /// Ann holds no factor and the change's token went to her mailbox. The
    /// answer says so and carries no token.
    #[test]
    fn a_mailed_change_answers_no_token() {
        let json = answer_to(ChangeToken::Mailed, ChangeProof::MailedLink);

        assert_eq!(json["proof"], "mailed_link");
        assert!(json.get("change_token").is_none());
    }
}
