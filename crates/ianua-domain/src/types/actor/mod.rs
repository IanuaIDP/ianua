//! Who acts: a person, an account, an agent, the platform.

/// Who performed a domain action, as recorded on events and audit entries.
pub mod actor_ref;
/// Who a human is across the accounts they hold.
pub mod person;
/// A subject that can hold or delegate authority.
pub mod principal_ref;
