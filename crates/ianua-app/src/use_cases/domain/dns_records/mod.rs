//! Managing the records inside a zone a tenant has delegated to us.
//!
//! Delegation takes a hostname off the tenant's hands. These use cases give
//! them the inside of it back: everything under the delegated name is theirs
//! to fill, minus the few records that make the hostname work at all.
//!
//! Every operation starts the same way: find the domain, confirm it is
//! delegated, and build the zone policy that decides what may be written.
//! That shared opening lives in `zone::DelegatedZone` rather than being
//! repeated three times, because a guard applied twice out of three times is
//! the bug this exists to prevent.

pub(crate) mod list;
pub(crate) mod remove;
pub(crate) mod set;
pub mod zone;

pub use list::{ListUseCase, ManagedRecordSet};
pub use remove::{RemoveRequest, RemoveUseCase};
pub use set::{SetPorts, SetRequest, SetUseCase};

#[cfg(test)]
mod tests;
