//! The organization scope marker.
//!
//! Organizations are the top-level entity and own tenants. The marker keeps
//! organization records apart from tenant records. Keeping one
//! organization's data from another's happens at run time, by comparing
//! organization ids. See [`crate::isolation`].

/// The type marker that keeps organization credentials distinct from tenant credentials.
pub mod scope;
