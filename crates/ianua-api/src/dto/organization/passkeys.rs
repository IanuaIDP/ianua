//! A member's passkeys: adding one, listing, renaming, and signing in with
//! one on the management login page.

use ianua_app::services::authentication::fresh_proof::ReenteredProof;
use ianua_app::services::authentication::passkey_answer::PresentedAssertion;
use ianua_app::use_cases::organization::passkeys::challenge::OrgPasskeyStarted;
use ianua_app::use_cases::organization::passkeys::{
    MemberSetupProof, OrgLoginConfirmRequest, OrgRegisterConfirmRequest, OrgRenameRequest,
};
use ianua_domain::domains::authentication::credentials::passkey::{
    AuthenticatorType, PasskeyCredential,
};
use ianua_domain::isolation::organization::scope::ResolvedOrganization;
use ianua_domain::types::{CeremonyId, Email, Label, PasskeyCredentialId, PasskeyId};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::codec;
use crate::dto::organization::proof::ReenteredProofBody;
use crate::dto::organization::sign_in::origin_of;
use crate::error::ApiError;
use crate::extractors::callers::RequestMeta;
use crate::extractors::organization::sign_in::Holding;

/// The challenge a passkey ceremony begins with.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct OrgPasskeyChallengeResponse {
    /// Names the server-held ceremony. Send it back on confirm: it is the
    /// only handle the client gets; the state it names stays here.
    pub ceremony_id: Uuid,
    /// Base64url options for `navigator.credentials.create()` / `.get()`.
    pub challenge: String,
}

impl From<OrgPasskeyStarted> for OrgPasskeyChallengeResponse {
    fn from(started: OrgPasskeyStarted) -> Self {
        Self {
            ceremony_id: *started.ceremony_id.as_uuid(),
            challenge: codec::url_safe_no_pad_encode(&started.challenge),
        }
    }
}

/// Request body to begin adding a passkey. Optional: without it the member
/// adds the passkey from their finished sign-in.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct OrgPasskeyRegisterBeginBody {
    /// `SignedIn` (the default) from a finished sign-in, or
    /// `WaitingSignIn` from a sign-in that waits for the second factor the
    /// organization requires, which this passkey will finish.
    #[serde(default)]
    pub from: PasskeySetupFrom,
}

/// Which sign-in a passkey is added from.
#[derive(Deserialize, utoipa::ToSchema, Default, Clone, Copy)]
pub(crate) enum PasskeySetupFrom {
    /// A finished sign-in.
    #[default]
    SignedIn,
    /// A sign-in waiting for a second factor to be set up.
    WaitingSignIn,
}

impl From<PasskeySetupFrom> for Holding {
    fn from(from: PasskeySetupFrom) -> Self {
        match from {
            PasskeySetupFrom::SignedIn => Self::FinishedSignIn,
            PasskeySetupFrom::WaitingSignIn => Self::WaitingSignIn,
        }
    }
}

/// Request body to finish adding a passkey.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct OrgPasskeyRegisterConfirmBody {
    /// The `ceremony_id` from the begin call. Names the server-held
    /// challenge this attestation answers.
    pub ceremony_id: Uuid,
    /// The authenticator's attestation response, base64url.
    pub response: String,
    /// The name the passkey is listed under.
    pub passkey_name: String,
    /// The member's password typed again, when they are signed in. A
    /// sign-in waiting for its second factor sends none.
    #[serde(default)]
    pub proof: Option<ReenteredProofBody>,
}

impl TryFrom<OrgPasskeyRegisterConfirmBody> for OrgRegisterConfirmRequest {
    type Error = ApiError;

    fn try_from(body: OrgPasskeyRegisterConfirmBody) -> Result<Self, Self::Error> {
        let proof = match body.proof {
            Some(proof) => MemberSetupProof::Reentered(ReenteredProof::from(proof)),
            None => MemberSetupProof::WaitingSignIn,
        };
        Ok(Self {
            ceremony_id: CeremonyId::from_uuid(body.ceremony_id),
            response: codec::url_safe_no_pad_decode(&body.response)?,
            name: Label::new("passkey_name", body.passkey_name).map_err(ApiError::validation)?,
            proof,
        })
    }
}

/// The member's passkeys.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct OrgPasskeyListResponse {
    /// Each passkey, without its key material.
    pub passkeys: Vec<OrgPasskeyEntry>,
}

impl OrgPasskeyListResponse {
    /// One entry per passkey of `passkeys`, in the order given.
    #[must_use]
    pub(crate) fn of(passkeys: &[PasskeyCredential<ResolvedOrganization>]) -> Self {
        Self {
            passkeys: passkeys.iter().map(OrgPasskeyEntry::from).collect(),
        }
    }
}

/// One of the member's passkeys.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct OrgPasskeyEntry {
    /// Passkey ID.
    pub id: String,
    /// The name it is listed under.
    pub name: String,
    /// `platform` (Touch ID, Windows Hello) or `cross_platform` (security key).
    pub authenticator_type: String,
    /// When it was added.
    pub created_at: String,
    /// When it last signed in, if ever.
    pub last_used_at: Option<String>,
}

impl From<&PasskeyCredential<ResolvedOrganization>> for OrgPasskeyEntry {
    fn from(passkey: &PasskeyCredential<ResolvedOrganization>) -> Self {
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

/// Request body for renaming a passkey.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct OrgRenamePasskeyBody {
    /// Its new name.
    pub name: String,
}

impl OrgRenamePasskeyBody {
    /// The rename of `passkey` this body asks for.
    ///
    /// # Errors
    ///
    /// `422` when the name is empty or too long.
    pub(crate) fn into_request(self, passkey: PasskeyId) -> Result<OrgRenameRequest, ApiError> {
        Ok(OrgRenameRequest {
            passkey_id: passkey,
            name: Label::new("passkey_name", self.name).map_err(ApiError::validation)?,
        })
    }
}

/// Request body to begin a passkey sign-in from a typed address.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct OrgPasskeyLoginBeginBody {
    /// The address the member signs in with.
    pub email: String,
}

impl TryFrom<OrgPasskeyLoginBeginBody> for Email {
    type Error = ApiError;

    fn try_from(body: OrgPasskeyLoginBeginBody) -> Result<Self, Self::Error> {
        Self::new(body.email).map_err(ApiError::validation)
    }
}

/// Request body to finish a passkey sign-in.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct OrgPasskeyLoginConfirmBody {
    /// The `ceremony_id` from the begin call. Names the server-held
    /// challenge this assertion answers: the challenge itself is never sent
    /// back, because a caller who could choose it could choose what their
    /// own signature is checked against.
    pub ceremony_id: Uuid,
    /// The authenticator's signed answer, base64url.
    pub response: String,
    /// The passkey that answered, as the authenticator names it, base64url.
    pub credential_id: String,
}

impl OrgPasskeyLoginConfirmBody {
    /// The answer this body carries, from where `meta` says the request
    /// came.
    ///
    /// # Errors
    ///
    /// `422` when the response or credential id is not base64url, or the
    /// credential id is empty.
    pub(crate) fn into_request(
        self,
        meta: RequestMeta,
    ) -> Result<OrgLoginConfirmRequest, ApiError> {
        let credential_id = codec::url_safe_no_pad_decode(&self.credential_id)?;
        Ok(OrgLoginConfirmRequest {
            assertion: PresentedAssertion {
                ceremony_id: CeremonyId::from_uuid(self.ceremony_id),
                credential_id: PasskeyCredentialId::new(credential_id)
                    .map_err(ApiError::validation)?,
                response: codec::url_safe_no_pad_decode(&self.response)?,
            },
            origin: origin_of(meta),
        })
    }
}
