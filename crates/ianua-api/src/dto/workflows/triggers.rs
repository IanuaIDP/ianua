//! A workflow's webhook secret on the wire: shown once, when it is made.

use ianua_app::use_cases::workflows::triggers::IssuedTriggerSecret;
use serde::Serialize;
use uuid::Uuid;

/// A webhook secret just made, with the id the webhook's address names.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct TriggerSecretResponse {
    /// The id the webhook's address names:
    /// `POST .../workflows/triggers/{trigger_id}`.
    pub trigger_id: Uuid,
    /// The secret the caller sends in the `Ianua-Trigger-Secret` header. It
    /// is shown this once; only its digest is kept.
    pub secret: String,
}

impl From<IssuedTriggerSecret> for TriggerSecretResponse {
    fn from(issued: IssuedTriggerSecret) -> Self {
        Self {
            trigger_id: *issued.trigger_id.as_uuid(),
            secret: issued.secret.expose().to_owned(),
        }
    }
}
