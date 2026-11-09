//! The stores of the notifications context: the three inboxes, one per kind
//! of user, the channels each person chose, and the places outside the app
//! an organization's notifications go to.
//!
//! A tenant user's inbox and choices live with the tenant, in its own
//! database when it has one. An operator's and an organization member's,
//! and the organization's destinations, live in the platform database.

mod destinations;
mod inbox;
mod preferences;
mod words;

pub use destinations::PgNotificationDestinationStore;
pub use inbox::{PgOrgNotificationStore, PgPlatformNotificationStore, PgTenantNotificationStore};
pub use preferences::{
    PgMemberPreferenceStore, PgNotificationPreferenceStore, PgOperatorPreferenceStore,
};
