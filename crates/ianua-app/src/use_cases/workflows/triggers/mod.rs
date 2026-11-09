//! Webhook secrets: issuing, rotating and revoking the secret a workflow's
//! webhook is called with.

use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::WorkflowTriggerId;

pub(crate) mod issue_secret;
pub(crate) mod revoke_secret;
pub(crate) mod rotate_secret;

/// A webhook secret just made: the id the webhook's address names, and the
/// raw secret, shown this once. Holds a secret, so it has no `Debug`.
pub struct IssuedTriggerSecret {
    /// The secret's id, which the webhook's address names.
    pub trigger_id: WorkflowTriggerId,
    /// The raw secret, for the caller to copy to whatever calls the webhook.
    pub secret: Secret,
}

pub use issue_secret::{IssueSecretPorts, IssueSecretUseCase};
pub use revoke_secret::{RevokeSecretPorts, RevokeSecretUseCase};
pub use rotate_secret::{RotateSecretPorts, RotateSecretUseCase};
