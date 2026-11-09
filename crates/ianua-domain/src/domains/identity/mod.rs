/// A person's account in a tenant and its address.
pub mod account;
pub mod attribute;
/// Domain events for users, invitations, consent, erasure, exports and
/// attributes.
pub mod events;
pub mod impersonation;
/// Invitations to join a tenant.
pub mod invitations;
pub mod metadata_value;
/// Consent, erasure and export: what a person agreed to, having their data
/// deleted, and getting a copy of it.
pub mod privacy;
/// The mark that keeps identity's rule traits to this crate.
pub(crate) mod sealed;
/// Single-use tokens for email verification, magic links and password resets.
pub mod tokens;
