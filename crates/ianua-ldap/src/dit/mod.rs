//! The synthetic directory information tree — DN handling, the entries a
//! tenant's directory materializes into, and LDAP filter evaluation against
//! them.
//!
//! This is the facade's wire-format/DTO layer: it knows how tenant/org/user
//! data maps onto LDAP's DN and attribute model, and nothing about the
//! network or the application use cases that supply the data.

pub mod dn;
pub mod entries;
pub mod filter;
