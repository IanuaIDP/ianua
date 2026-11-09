//! Fakes for the authorization ports: in-memory stores that keep what is
//! saved, tenant by tenant.
//!
//! What a caller may do is not faked here. Use cases ask `acting` for it,
//! and its fakes live in `test_support::acting`.

mod catalogue;
mod copies;
mod groups;
pub(crate) mod policies;
mod records;
mod relationships;
mod requests;
mod roles;
mod separation;
mod use_cases;

pub use catalogue::*;
pub use groups::*;
pub use policies::*;
pub use records::*;
pub use relationships::*;
pub use requests::*;
pub use roles::*;
pub use separation::*;
