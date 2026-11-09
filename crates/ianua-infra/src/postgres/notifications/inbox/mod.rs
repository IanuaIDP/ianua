//! The three inboxes: an operator's, an organization member's and a tenant
//! user's. Each is a table of its own, in the database its reader lives
//! in, and each row is read and written through the one mapping in
//! [`record`], so a notification reads the same whichever inbox holds it.
//!
//! A notification is only ever added, then marked read in one statement;
//! adding it again, as a retried fan-out does, changes nothing.

mod listing;
mod members;
mod operators;
mod record;
mod users;
mod words;

pub use members::PgOrgNotificationStore;
pub use operators::PgPlatformNotificationStore;
pub use users::PgTenantNotificationStore;
