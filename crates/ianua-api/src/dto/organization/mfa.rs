//! A member's second factor: its status, setting it up, answering it at
//! sign-in and turning it off.

use ianua_app::services::authentication::fresh_proof::ReenteredProof;
use ianua_app::use_cases::authentication::mfa::{SetupProof, Status};
use ianua_app::use_cases::organization::mfa::{
    OrgConfirmRequest, OrgDisableRequest, OrgEnrollmentConfirmed, OrgMfaEnrollmentStarted,
    OrgRecoveryCodeSignInRequest, OrgVerifyRequest,
};
use ianua_domain::domains::authentication::mfa::owed::SecondFactor;
use ianua_domain::message;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::SessionId;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::dto::organization::proof::ReenteredProofBody;
use crate::error::ApiError;
use crate::extractors::json::Json;

/// Whether the member has an active second factor and which method they enrolled.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct OrgMfaStatusResponse {
    /// Whether MFA is enrolled and active.
    pub enabled: bool,
    /// MFA method (e.g. "Totp") if enabled.
    pub method: Option<String>,
}

impl From<Status> for OrgMfaStatusResponse {
    fn from(status: Status) -> Self {
        Self {
            enabled: status.enabled,
            method: status.method,
        }
    }
}

/// What lets a member set up or give up a second factor now.
///
/// A member signed in sends `proof`, their password typed again with a code
/// from any factor they hold. A sign-in waiting for the factor the
/// organization requires sends no body, or one without `proof`: the
/// sign-in itself is its leave, for a few minutes after it began.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct OrgFactorSetupBody {
    /// The member's password typed again, when they are signed in.
    #[serde(default)]
    pub proof: Option<ReenteredProofBody>,
}

impl OrgFactorSetupBody {
    /// The leave `body` gives, an absent body being a waiting sign-in's.
    #[must_use]
    pub(crate) fn setup_proof(body: Option<Json<Self>>) -> SetupProof {
        let Some(proof) = body.and_then(|Json(body)| body.proof) else {
            return SetupProof::OwedBySignIn;
        };
        SetupProof::Reentered(ReenteredProof::from(proof))
    }
}

/// Response for MFA enrollment begin.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct OrgMfaBeginResponse {
    /// The `otpauth://` URI for the authenticator app. It carries the
    /// secret: render it as a QR code and do not keep it.
    pub otpauth_uri: String,
}

impl From<OrgMfaEnrollmentStarted> for OrgMfaBeginResponse {
    fn from(started: OrgMfaEnrollmentStarted) -> Self {
        Self {
            otpauth_uri: started.otpauth_uri.as_str().to_owned(),
        }
    }
}

/// Request body for MFA confirm.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct OrgMfaConfirmBody {
    /// The TOTP code from the authenticator app.
    pub code: String,
    /// A sign-in that is waiting for this first second factor. Once the
    /// code is accepted, that sign-in is complete. Leave it out when signed
    /// in.
    #[serde(default)]
    pub session_id: Option<String>,
}

impl OrgMfaConfirmBody {
    /// The confirmation, and the waiting sign-in it finishes, if any.
    ///
    /// # Errors
    ///
    /// `422` when `session_id` is not a session id.
    pub(crate) fn into_parts(self) -> Result<(OrgConfirmRequest, Option<SessionId>), ApiError> {
        let waiting = self
            .session_id
            .as_deref()
            .map(Uuid::parse_str)
            .transpose()
            .map_err(|_| {
                ApiError::validation(message!("api-invalid-session-id", "invalid session_id"))
            })?
            .map(SessionId::from_uuid);
        Ok((OrgConfirmRequest { code: self.code }, waiting))
    }
}

/// Response for MFA enrollment confirm.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct OrgMfaConfirmResponse {
    /// Recovery codes: shown once, never again.
    pub recovery_codes: Vec<String>,
}

impl From<OrgEnrollmentConfirmed> for OrgMfaConfirmResponse {
    fn from(confirmed: OrgEnrollmentConfirmed) -> Self {
        Self {
            recovery_codes: confirmed
                .recovery_codes
                .iter()
                .map(|code| code.expose().to_owned())
                .collect(),
        }
    }
}

/// Request body for MFA verification during login.
///
/// The sign-in answered is the one whose refresh token is the bearer; a
/// `session_id` the client still sends is ignored.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct OrgMfaVerifyBody {
    /// The TOTP code from the authenticator app.
    pub code: String,
}

impl From<OrgMfaVerifyBody> for OrgVerifyRequest {
    fn from(body: OrgMfaVerifyBody) -> Self {
        Self { code: body.code }
    }
}

/// Request body answering a sign-in's second factor with a recovery code.
/// Holds the code, so it has no `Debug`.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct OrgRecoveryCodeBody {
    /// One of the member's unused recovery codes, as typed.
    pub code: String,
}

impl From<OrgRecoveryCodeBody> for OrgRecoveryCodeSignInRequest {
    fn from(body: OrgRecoveryCodeBody) -> Self {
        Self {
            raw_code: Secret::new(body.code),
        }
    }
}

/// What a sign-in still owes once a recovery code stood in for its factor.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct OrgRecoveryCodeResponse {
    /// Whether the member must set up a new second factor before the
    /// session is let in, as the organization requires one.
    pub mfa_enrollment_required: bool,
}

impl From<SecondFactor> for OrgRecoveryCodeResponse {
    fn from(owed: SecondFactor) -> Self {
        Self {
            mfa_enrollment_required: !owed.is_satisfied(),
        }
    }
}

/// Request body replacing the caller's recovery codes.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct OrgRegenerateCodesBody {
    /// The member's password typed again, with a code from their second
    /// factor.
    pub proof: ReenteredProofBody,
}

impl From<OrgRegenerateCodesBody> for ReenteredProof {
    fn from(body: OrgRegenerateCodesBody) -> Self {
        Self::from(body.proof)
    }
}

/// A new set of recovery codes.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct OrgRecoveryCodesResponse {
    /// The codes: shown once, never again. Every earlier code stopped
    /// working.
    pub recovery_codes: Vec<String>,
}

impl From<Vec<Secret>> for OrgRecoveryCodesResponse {
    fn from(codes: Vec<Secret>) -> Self {
        Self {
            recovery_codes: codes.iter().map(|code| code.expose().to_owned()).collect(),
        }
    }
}

/// Request body for turning off the caller's own second factor.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct OrgMfaDisableBody {
    /// A current code from the authenticator being removed.
    pub code: String,
}

impl From<OrgMfaDisableBody> for OrgDisableRequest {
    fn from(body: OrgMfaDisableBody) -> Self {
        Self { code: body.code }
    }
}
