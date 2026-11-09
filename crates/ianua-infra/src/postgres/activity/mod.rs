//! The stores of the activity context: the counts behind the activity
//! calendar, read from the audit records of a tenant or of an organization
//! and its tenants.

mod calendar;

pub use calendar::PgActivityStore;
