//! Identity domain events.

/// Events about a person's account: registration, status, address and profile.
pub mod account;
/// Events about the attributes a tenant declares and stores on its users.
pub mod attributes;
/// Events about requests for a copy of a person's data.
pub mod export;
/// Events about a tenant admin acting as one of the tenant's people.
pub mod impersonation;
/// Events about invitations to join a tenant.
pub mod invitations;
/// Events about consent and erasure.
pub mod privacy;
/// Events about what an account records about its holder, and imported
/// accounts.
pub mod profile;

use crate::shared::events::data::{RefKind, Reference};
use crate::types::UserId;

/// References the user an action was done to, labelled as they were then.
///
/// Only for events where the user is the one acted on. In a self-service
/// event the user is the actor, and the audit record already names them.
fn user_reference(user_id: &UserId, label: &str) -> Reference {
    Reference::new(RefKind::USER, user_id.to_string(), label)
}
