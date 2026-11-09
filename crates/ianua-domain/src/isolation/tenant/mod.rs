//! The tenant scope marker.
//!
//! Marks an entity as belonging to the tenant plane. Keeping one tenant's
//! data from another's happens at run time, in the stores and the
//! database; see [`crate::isolation`].

/// The tenant scope proof every tenant-branded type carries.
pub mod scope;
