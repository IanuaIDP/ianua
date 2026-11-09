//! The channel each person chose per category: a tenant user's with the
//! tenant, an organization member's and an operator's in the platform
//! database. Each person's choices are one row per category, read through
//! the one mapping in [`choice`], and replaced in one statement, so a save
//! cut short leaves the choices as they were or as they are now, never
//! half of each.

mod choice;
mod members;
mod operators;
mod users;
mod words;

pub use members::PgMemberPreferenceStore;
pub use operators::PgOperatorPreferenceStore;
pub use users::PgNotificationPreferenceStore;
