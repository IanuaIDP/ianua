//! A person's account in a tenant and its address.

/// An account's address, and whether its owner was shown to hold it.
pub mod address;
/// Leave to replace the password of an account someone else acts on.
pub mod admin_password_reset;
/// The rules an action on an account or its profile must pass first.
pub mod control;
/// Who may open a new account in a tenant.
pub mod creator;
pub mod email_change;
/// Opening accounts from another system's records, password hashes
/// included.
pub mod import;
/// The values a profile holds beyond the name it shows.
pub mod profile_values;
/// What a stored user row must keep before it is rebuilt.
mod row_rules;
/// The user aggregate: a person's account in one tenant.
pub mod user;
/// What an account records about its holder beyond the name it shows.
pub mod user_profile;
/// Where a tenant user's account stands.
pub mod user_status;
pub mod verified_email;
/// Whether a trusted route still vouches for an account's next sign-in.
pub mod vouching;
