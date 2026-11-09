//! Passkey bodies: the challenges a ceremony begins with, adding a passkey,
//! signing in with one, and the caller's own list.

use ianua_app::services::authentication::sign_in_gate::ClientOrigin;
use ianua_app::use_cases::authentication::passkeys::{
    LoginConfirmRequest, LoginStarted, LoginSuccess, RegistrationChallenge,
    RegistrationConfirmRequest, RenameRequest, SetupProof,
};
use ianua_domain::domains::authentication::credentials::passkey::{
    AuthenticatorType, PasskeyCredential,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::{CeremonyId, Email, Label, PasskeyId, SessionId, TenantId};
use serde::{Deserialize, Serialize};

use crate::codec;
use crate::dto::authentication::sign_in::{OwedFactors, PasskeyAnswerBody, ReenteredProofBody};
use crate::error::ApiError;

/// The challenge a passkey ceremony begins with.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct PasskeyChallengeResponse {
    /// Names the server-held ceremony. Send it back on confirm: it is the
    /// only handle the client gets; the state it names stays here.
    pub ceremony_id: uuid::Uuid,
    /// Base64url options for `navigator.credentials.create()` / `.get()`.
    pub challenge: String,
}

impl From<LoginStarted> for PasskeyChallengeResponse {
    fn from(started: LoginStarted) -> Self {
        Self {
            ceremony_id: *started.ceremony_id.as_uuid(),
            challenge: codec::url_safe_no_pad_encode(&started.challenge),
        }
    }
}

impl From<RegistrationChallenge> for PasskeyChallengeResponse {
    fn from(started: RegistrationChallenge) -> Self {
        Self {
            ceremony_id: *started.ceremony_id.as_uuid(),
            challenge: codec::url_safe_no_pad_encode(&started.challenge),
        }
    }
}

/// The authenticator's answer to a registration ceremony.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct PasskeyRegisterConfirmBody {
    /// The `ceremony_id` from the begin call. Names the server-held challenge
    /// this attestation answers.
    pub ceremony_id: uuid::Uuid,
    /// The attestation from `navigator.credentials.create()`, base64url.
    pub response: String,
    /// The name the passkey is listed under.
    pub passkey_name: String,
    /// The signed-in person's proof of who they are. A sign-in waiting for
    /// this passkey as its second factor sends none.
    #[serde(default)]
    pub proof: Option<ReenteredProofBody>,
}

impl TryFrom<PasskeyRegisterConfirmBody> for RegistrationConfirmRequest {
    type Error = ApiError;

    fn try_from(body: PasskeyRegisterConfirmBody) -> Result<Self, Self::Error> {
        let proof = match body.proof {
            Some(proof) => SetupProof::Reentered(proof.try_into()?),
            None => SetupProof::WaitingSignIn,
        };
        Ok(Self {
            ceremony_id: CeremonyId::from_uuid(body.ceremony_id),
            response: codec::url_safe_no_pad_decode(&body.response)?,
            passkey_name: Label::new("passkey_name", body.passkey_name)
                .map_err(ApiError::validation)?,
            proof,
        })
    }
}

/// Whose passkeys a sign-in challenges.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct PasskeyLoginBeginBody {
    /// The address the account signs in with.
    pub email: String,
}

impl PasskeyLoginBeginBody {
    /// The address, checked.
    ///
    /// # Errors
    ///
    /// Returns a validation error for an address that is not well formed.
    pub(crate) fn email(&self) -> Result<Email, ApiError> {
        Email::new(&self.email).map_err(ApiError::validation)
    }
}

impl PasskeyAnswerBody {
    /// The sign-in this answer makes, from `origin`.
    ///
    /// # Errors
    ///
    /// Returns a validation error for an answer that is not base64url or a
    /// credential id that is not one.
    pub fn sign_in(self, origin: ClientOrigin) -> Result<LoginConfirmRequest, ApiError> {
        Ok(LoginConfirmRequest {
            assertion: self.try_into()?,
            origin,
        })
    }
}

/// A new session from a passkey sign-in.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct PasskeyLoginResponse {
    /// The newly created session ID.
    #[schema(value_type = String, format = Uuid)]
    pub session_id: SessionId,
    /// The raw refresh token.
    pub refresh_token: String,
    /// What the session still owes. A passkey proves possession and user
    /// verification, so usually nothing.
    #[serde(flatten)]
    pub owed: OwedFactors,
    /// The resolved tenant's ID.
    #[schema(value_type = String, format = Uuid)]
    pub tenant_id: TenantId,
    /// The resolved tenant's display name.
    pub tenant_name: String,
    /// The credential owner's display name.
    pub display_name: String,
}

impl From<LoginSuccess> for PasskeyLoginResponse {
    fn from(success: LoginSuccess) -> Self {
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

/// The caller's passkeys.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct PasskeyListResponse {
    /// Each passkey, without its key material.
    pub passkeys: Vec<PasskeyEntry>,
}

impl From<Vec<PasskeyCredential<ResolvedTenant>>> for PasskeyListResponse {
    fn from(passkeys: Vec<PasskeyCredential<ResolvedTenant>>) -> Self {
        Self {
            passkeys: passkeys.iter().map(PasskeyEntry::from).collect(),
        }
    }
}

/// One passkey in the caller's list.
#[derive(Serialize, utoipa::ToSchema)]
pub struct PasskeyEntry {
    /// The passkey's id.
    pub id: String,
    /// The name it is listed under.
    pub name: String,
    /// `platform` (Touch ID, Windows Hello) or `cross_platform` (security key).
    pub authenticator_type: String,
    /// When it was added.
    pub created_at: String,
    /// When it last signed in, if it ever did.
    pub last_used_at: Option<String>,
}

impl From<&PasskeyCredential<ResolvedTenant>> for PasskeyEntry {
    fn from(passkey: &PasskeyCredential<ResolvedTenant>) -> Self {
        let authenticator_type = match passkey.authenticator_type() {
            AuthenticatorType::Platform => "platform",
            AuthenticatorType::CrossPlatform => "cross_platform",
        };
        Self {
            id: passkey.id().to_string(),
            name: passkey.name().as_str().to_owned(),
            authenticator_type: authenticator_type.to_owned(),
            created_at: passkey.created_at().to_string(),
            last_used_at: passkey.last_used_at().map(|at| at.to_string()),
        }
    }
}

/// A passkey's new name.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct RenamePasskeyBody {
    /// The name to list it under.
    pub name: String,
}

impl RenamePasskeyBody {
    /// The rename of `passkey_id`.
    ///
    /// # Errors
    ///
    /// Returns a validation error for a name that is empty or too long.
    pub(crate) fn request(self, passkey_id: PasskeyId) -> Result<RenameRequest, ApiError> {
        Ok(RenameRequest {
            passkey_id,
            name: Label::new("passkey_name", self.name).map_err(ApiError::validation)?,
        })
    }
}
