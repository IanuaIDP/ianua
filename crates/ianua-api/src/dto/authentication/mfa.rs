//! Second-factor bodies: what a person may set up, setting up an
//! authenticator app or mailed or texted codes, sending a code, answering a
//! session's second factor or a recovery code, fresh recovery codes,
//! resuming a suspended session, and turning the factor off.

use ianua_app::services::authentication::fresh_proof::ReenteredProof;
use ianua_app::use_cases::authentication::mfa::{
    CodeFactorRequest, CodeSent, ConfirmRequest, DisableRequest, EnrollmentConfirmed, EnrollmentQr,
    FactorOptions, HeldFactor, RecoveryCodeLoginRequest, RegeneratedRecoveryCodes,
    ResumeSessionRequest, SentFactorChoice, SetupProof, Status, VerificationRequest,
};
use ianua_domain::domains::identity::account::profile_values::PhoneNumber;
use ianua_domain::message;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{SessionId, UserId};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::dto::authentication::sign_in::{OwedFactors, ReenteredProofBody};
use crate::error::ApiError;

/// What lets the caller set up, or give up setting up, an authenticator.
///
/// A signed-in person proves who they are again. A sign-in waiting for the
/// factor its workspace requires sends no proof: it began moments ago and
/// owes exactly this factor.
#[derive(Deserialize, Default, utoipa::ToSchema)]
pub(crate) struct MfaSetupBody {
    /// The signed-in person's proof of who they are, or nothing for a
    /// sign-in waiting for the factor.
    #[serde(default)]
    pub proof: Option<ReenteredProofBody>,
}

impl MfaSetupBody {
    /// What lets the caller set up a factor now.
    ///
    /// # Errors
    ///
    /// Returns a validation error for a passkey answer that is not well
    /// formed.
    pub(crate) fn setup_proof(self) -> Result<SetupProof, ApiError> {
        let Some(proof) = self.proof else {
            return Ok(SetupProof::OwedBySignIn);
        };
        Ok(SetupProof::Reentered(proof.try_into()?))
    }
}

/// The QR an authenticator app scans.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct MfaEnrollResponse {
    /// The `otpauth://` URI to render as a QR code. It carries the secret.
    pub otpauth_uri: String,
}

impl From<EnrollmentQr> for MfaEnrollResponse {
    fn from(qr: EnrollmentQr) -> Self {
        Self {
            otpauth_uri: qr.otpauth_uri.as_str().to_owned(),
        }
    }
}

/// A code from the authenticator being confirmed.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct MfaConfirmBody {
    /// The code the authenticator shows.
    pub code: String,
    /// A sign-in that is waiting for this first second factor. Once the code
    /// is accepted, that sign-in is complete.
    #[serde(default)]
    pub session_id: Option<String>,
}

impl MfaConfirmBody {
    /// The sign-in the code finishes, when the body names one.
    ///
    /// # Errors
    ///
    /// Returns a validation error for a session id that is not a UUID.
    pub(crate) fn completing(&self) -> Result<Option<SessionId>, ApiError> {
        self.session_id.as_deref().map(session_id).transpose()
    }

    /// The confirmation the code makes.
    #[must_use]
    pub(crate) fn request(self) -> ConfirmRequest {
        ConfirmRequest { code: self.code }
    }
}

/// The recovery codes a confirmed authenticator comes with.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct MfaConfirmResponse {
    /// One-time recovery codes, shown this once.
    pub recovery_codes: Vec<String>,
}

impl From<EnrollmentConfirmed> for MfaConfirmResponse {
    fn from(confirmed: EnrollmentConfirmed) -> Self {
        Self {
            recovery_codes: confirmed
                .recovery_codes
                .iter()
                .map(|code| code.expose().to_owned())
                .collect(),
        }
    }
}

/// A code from the authenticator being turned off.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct MfaCodeBody {
    /// The code the authenticator shows.
    pub code: String,
}

impl From<MfaCodeBody> for DisableRequest {
    fn from(body: MfaCodeBody) -> Self {
        Self { code: body.code }
    }
}

/// The signed-in user's MFA status.
///
/// The same shape as the organization plane's, so one client reads both.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct MfaStatusResponse {
    /// Whether MFA is enrolled and active.
    pub enabled: bool,
    /// MFA method (e.g. "Totp") if enabled.
    pub method: Option<String>,
}

impl From<Status> for MfaStatusResponse {
    fn from(status: Status) -> Self {
        Self {
            enabled: status.enabled,
            method: status.method,
        }
    }
}

/// A code given for a session's second factor: from the authenticator, or
/// a recovery code in its place.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct SessionCodeBody {
    /// The session the code is for, the caller's own.
    pub session_id: String,
    /// The code as typed.
    pub code: String,
}

impl SessionCodeBody {
    /// The authenticator code offered for `user_id`'s session.
    ///
    /// # Errors
    ///
    /// Returns a validation error for a session id that is not a UUID.
    pub(crate) fn verification(self, user_id: UserId) -> Result<VerificationRequest, ApiError> {
        Ok(VerificationRequest {
            session_id: session_id(&self.session_id)?,
            user_id,
            code: self.code,
        })
    }

    /// The recovery code redeemed for `user_id`'s session.
    ///
    /// # Errors
    ///
    /// Returns a validation error for a session id that is not a UUID.
    pub(crate) fn recovery(self, user_id: UserId) -> Result<RecoveryCodeLoginRequest, ApiError> {
        Ok(RecoveryCodeLoginRequest {
            session_id: session_id(&self.session_id)?,
            user_id,
            raw_code: Secret::new(self.code),
        })
    }

    /// The authenticator code lifting the suspension of `user_id`'s
    /// session.
    ///
    /// # Errors
    ///
    /// Returns a validation error for a session id that is not a UUID.
    pub(crate) fn resumption(self, user_id: UserId) -> Result<ResumeSessionRequest, ApiError> {
        Ok(ResumeSessionRequest {
            session_id: session_id(&self.session_id)?,
            user_id,
            code: self.code,
        })
    }
}

/// The sign-in a second-factor step is for, when it is one still waiting
/// for its factor. A person signed in names none.
#[derive(Deserialize, Default, utoipa::ToSchema, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct WaitingSignInParams {
    /// The session a sign-in answered with, while it waits for its second
    /// factor.
    #[serde(default)]
    pub session_id: Option<String>,
}

impl WaitingSignInParams {
    /// The waiting sign-in named, if any.
    ///
    /// # Errors
    ///
    /// Returns a validation error for a session id that is not a UUID.
    pub(crate) fn completing(&self) -> Result<Option<SessionId>, ApiError> {
        self.session_id.as_deref().map(session_id).transpose()
    }
}

/// The second factors a person may set up, the one they hold, and what
/// their sign-in still owes.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct FactorOptionsResponse {
    /// The kinds the tenant offers them: `totp`, `email_code`, `sms_code`.
    /// Empty when second factors are off.
    pub offered: Vec<&'static str>,
    /// The factor they hold.
    pub held: HeldFactorResponse,
    /// What a waiting sign-in still owes; nothing for a person signed in.
    #[serde(flatten)]
    pub owed: OwedFactors,
}

/// The factor a person holds, as far as it went.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct HeldFactorResponse {
    /// `none`, `pending` (set up, still to be confirmed) or `in_force`.
    pub state: &'static str,
    /// Its kind, unless there is none.
    pub method: Option<&'static str>,
}

impl From<HeldFactor> for HeldFactorResponse {
    fn from(held: HeldFactor) -> Self {
        let (state, method) = match held {
            HeldFactor::None => ("none", None),
            HeldFactor::Pending(method) => ("pending", Some(method.as_str())),
            HeldFactor::InForce(method) => ("in_force", Some(method.as_str())),
        };
        Self { state, method }
    }
}

impl From<FactorOptions> for FactorOptionsResponse {
    fn from(options: FactorOptions) -> Self {
        Self {
            offered: options
                .offered
                .iter()
                .map(|method| method.as_str())
                .collect(),
            held: options.held.into(),
            owed: options.owed.into(),
        }
    }
}

/// Where the codes of a factor being set up go.
#[derive(Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SentFactorKind {
    /// Mailed to the account's address.
    EmailCode,
    /// Texted to `phone_number`.
    SmsCode,
}

/// Starting to set up a factor whose codes are mailed or texted.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct CodeFactorBody {
    /// `email_code` or `sms_code`.
    pub method: SentFactorKind,
    /// The number texted codes go to, in international form, such as
    /// `+4930123456`; for `sms_code` only. The first code proves it reaches
    /// the person.
    #[serde(default)]
    pub phone_number: Option<String>,
    /// The signed-in person's proof of who they are, or nothing for a
    /// sign-in waiting for the factor.
    #[serde(default)]
    pub proof: Option<ReenteredProofBody>,
}

impl CodeFactorBody {
    /// The setup asked for.
    ///
    /// # Errors
    ///
    /// Returns a validation error for a number that is missing, given for
    /// mail, or not in international form, or a passkey answer that is not
    /// well formed.
    pub(crate) fn request(self) -> Result<CodeFactorRequest, ApiError> {
        let choice = match (self.method, self.phone_number) {
            (SentFactorKind::EmailCode, None) => SentFactorChoice::Mail,
            (SentFactorKind::SmsCode, Some(number)) => {
                SentFactorChoice::Text(PhoneNumber::new(number).map_err(ApiError::validation)?)
            }
            (SentFactorKind::EmailCode, Some(_)) => {
                return Err(ApiError::validation(message!(
                    "api-a-mailed-code-takes-no-phone",
                    "a mailed code takes no phone_number"
                )));
            }
            (SentFactorKind::SmsCode, None) => {
                return Err(ApiError::validation(message!(
                    "api-a-texted-code-needs-a-phone",
                    "a texted code needs a phone_number"
                )));
            }
        };
        let proof = MfaSetupBody { proof: self.proof }.setup_proof()?;
        Ok(CodeFactorRequest { choice, proof })
    }
}

/// A code on its way.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct CodeSentResponse {
    /// When the code stops working.
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
}

impl From<CodeSent> for CodeSentResponse {
    fn from(sent: CodeSent) -> Self {
        Self {
            expires_at: sent.expires_at,
        }
    }
}

/// A signed-in person's proof of who they are, for a fresh set of recovery
/// codes.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct RegenerateRecoveryCodesBody {
    /// The person's proof of who they are.
    pub proof: ReenteredProofBody,
}

impl TryFrom<RegenerateRecoveryCodesBody> for ReenteredProof {
    type Error = ApiError;

    fn try_from(body: RegenerateRecoveryCodesBody) -> Result<Self, Self::Error> {
        body.proof.try_into()
    }
}

impl From<RegeneratedRecoveryCodes> for MfaConfirmResponse {
    fn from(regenerated: RegeneratedRecoveryCodes) -> Self {
        Self {
            recovery_codes: regenerated
                .recovery_codes
                .iter()
                .map(|code| code.expose().to_owned())
                .collect(),
        }
    }
}

/// `raw` as a session id.
fn session_id(raw: &str) -> Result<SessionId, ApiError> {
    raw.parse::<uuid::Uuid>()
        .map(SessionId::from_uuid)
        .map_err(|_| ApiError::validation(message!("api-invalid-session-id", "invalid session_id")))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Ann asks for codes by mail and names a number too. The number would
    /// be dropped without her knowing, so it is refused.
    #[test]
    fn mailed_codes_take_no_number() {
        let body = CodeFactorBody {
            method: SentFactorKind::EmailCode,
            phone_number: Some("+4930123456".to_owned()),
            proof: None,
        };

        assert!(body.request().is_err());
    }

    /// Ann asks for texted codes to her number, written with spaces. It is
    /// kept in international form, and a sign-in waiting for the factor
    /// needs no proof.
    #[test]
    fn texted_codes_go_to_the_number_given() {
        let body = CodeFactorBody {
            method: SentFactorKind::SmsCode,
            phone_number: Some("+49 30 123456".to_owned()),
            proof: None,
        };

        let Ok(request) = body.request() else {
            panic!("a number in international form is taken");
        };

        assert!(matches!(
            request.choice,
            SentFactorChoice::Text(ref number) if number.as_str() == "+4930123456"
        ));
        assert!(matches!(request.proof, SetupProof::OwedBySignIn));
    }
}
