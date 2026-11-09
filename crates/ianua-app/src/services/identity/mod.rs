//! What identity and provisioning use cases share about a tenant's users:
//! whether an address is free, whose sign-ins a record is, and where the
//! links mailed to them point.

pub(crate) mod address_free;
pub mod link_scopes;
pub mod sign_ins;
