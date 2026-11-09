//! Identity use cases: registering users, inviting them, confirming and
//! changing their addresses, their custom attributes, and their privacy
//! requests.

pub(in crate::use_cases) mod account_control;
/// A tenant's custom user attributes: their declarations and the values
/// people hold.
pub mod attributes;
mod audit_label;
/// Confirming addresses and moving users onto new ones.
pub mod email;
/// Tenant admins acting as one of the tenant's people for support.
pub mod impersonation;
/// Bringing accounts over from another system, worked through by the
/// worker in chunks.
pub mod imports;
/// Inviting people into a tenant, and their invitations.
pub mod invitations;
mod lookup;
/// Consent records and data erasure.
pub mod privacy;
pub(in crate::use_cases) mod renewal;
/// Creating, reading, changing and removing a tenant's users.
pub mod users;
/// Whose account a request is about.
pub mod whose;
