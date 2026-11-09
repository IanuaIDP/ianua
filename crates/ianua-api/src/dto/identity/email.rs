//! Email change bodies: a person asking to move their own account to a
//! new address, proving who they are again.

use ianua_app::email::LinkScope;
use ianua_app::services::authentication::fresh_proof::ReenteredProof;
use ianua_app::use_cases::identity::email::RequestChangeRequest;
use ianua_domain::message;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::Email;
use serde::Deserialize;

use crate::error::ApiError;

/// Asks to move the signed-in person's own account to a new address.
///
/// Asking needs more than an open session: the person proves who they are
/// again, with their password or a sign-in link mailed to them just now,
/// and a code from their second factor when they have one.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct RequestEmailChangeBody {
    /// The new email address.
    pub new_email: String,
    /// Their password, typed again.
    #[serde(default)]
    pub password: Option<String>,
    /// The token of a sign-in link mailed to them and followed just now,
    /// for an account that signs in through its mailbox.
    #[serde(default)]
    pub link: Option<String>,
    /// A code from their second factor, when they have one.
    #[serde(default)]
    pub code: Option<String>,
}

impl RequestEmailChangeBody {
    /// The change asked for, its links landing on `scope`.
    ///
    /// # Errors
    ///
    /// [`ApiError::validation`] for an address that is not a valid one, or
    /// a body that proves nothing: neither a password nor a link.
    pub(crate) fn request(self, scope: LinkScope) -> Result<RequestChangeRequest, ApiError> {
        let new_email = Email::new(self.new_email).map_err(ApiError::validation)?;
        let proof = match (self.password, self.link) {
            (Some(password), _) => ReenteredProof::Password {
                password: Secret::new(password),
                code: self.code,
            },
            (None, Some(link)) => ReenteredProof::Mailbox {
                link: Secret::new(link),
                code: self.code,
            },
            (None, None) => {
                return Err(ApiError::validation(message!(
                    "api-prove-it-is-you-give-your",
                    "prove it is you: give your password or a sign-in link"
                )));
            }
        };
        Ok(RequestChangeRequest {
            new_email,
            proof,
            scope,
        })
    }
}
