//! What a signed-in member types again to prove who they are before a
//! change to how they or their organization sign in.

use ianua_app::services::authentication::fresh_proof::ReenteredProof;
use ianua_domain::shared::security::secret::Secret;
use serde::Deserialize;

/// A member's password typed again, with a code from their second factor
/// when they have one. Holds a secret, so it has no `Debug`.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct ReenteredProofBody {
    /// The member's password, as typed.
    #[schema(format = Password)]
    pub password: String,
    /// The code their authenticator shows; required when they have a
    /// second factor.
    #[serde(default)]
    pub code: Option<String>,
}

impl From<ReenteredProofBody> for ReenteredProof {
    fn from(body: ReenteredProofBody) -> Self {
        Self::Password {
            password: Secret::new(body.password),
            code: body.code,
        }
    }
}
