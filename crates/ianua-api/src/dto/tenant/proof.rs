//! What a person types again to prove who they are before changing how a
//! tenant is protected.

use ianua_app::services::authentication::fresh_proof::ReenteredProof;
use ianua_app::services::authentication::passkey_answer::PresentedAssertion;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{CeremonyId, PasskeyCredentialId};
use serde::Deserialize;
use uuid::Uuid;

use crate::codec::url_safe_no_pad_decode;
use crate::error::ApiError;

/// A fresh proof of the person making the change, the way they sign in:
/// their password with a code from their second factor when they have
/// one, a sign-in link mailed to them and just followed, or their
/// passkey's answer to a challenge opened for them. Holds secrets, so it
/// has no `Debug`.
#[derive(Deserialize, utoipa::ToSchema)]
#[serde(untagged)]
pub(crate) enum FreshProofBody {
    /// Their password typed again.
    Password {
        /// The password, as typed.
        password: String,
        /// The code their authenticator shows; required when they have a
        /// second factor.
        #[serde(default)]
        code: Option<String>,
    },
    /// A sign-in link mailed to them, for an account whose mailbox is how
    /// it signs in.
    Mailbox {
        /// The link's token, as followed.
        link: String,
        /// The code their authenticator shows; required when they have a
        /// second factor.
        #[serde(default)]
        code: Option<String>,
    },
    /// Their passkey's answer to a sign-in challenge.
    Passkey {
        /// The ceremony the challenge came from.
        ceremony_id: Uuid,
        /// The passkey that answered, URL-safe base64 without padding.
        credential_id: String,
        /// The authenticator's signed answer, URL-safe base64 without
        /// padding.
        response: String,
    },
}

impl TryFrom<FreshProofBody> for ReenteredProof {
    type Error = ApiError;

    fn try_from(body: FreshProofBody) -> Result<Self, Self::Error> {
        match body {
            FreshProofBody::Password { password, code } => Ok(Self::Password {
                password: Secret::new(password),
                code,
            }),
            FreshProofBody::Mailbox { link, code } => Ok(Self::Mailbox {
                link: Secret::new(link),
                code,
            }),
            FreshProofBody::Passkey {
                ceremony_id,
                credential_id,
                response,
            } => Ok(Self::Passkey(PresentedAssertion {
                ceremony_id: CeremonyId::from_uuid(ceremony_id),
                credential_id: PasskeyCredentialId::new(url_safe_no_pad_decode(&credential_id)?)
                    .map_err(ApiError::validation)?,
                response: url_safe_no_pad_decode(&response)?,
            })),
        }
    }
}
