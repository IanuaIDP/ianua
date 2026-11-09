//! SCIM provisioning: a tenant's endpoint, and the users and groups a
//! directory's filter picks. The stores of `ports/federation/scim.rs`.
//!
//! The finders read the identity and authorization tables, by position as
//! RFC 7644 has a directory page; how a filter becomes a condition on them
//! is written once, in `filters`.

mod endpoints;
mod filters;
mod groups;
mod users;

pub use endpoints::PgScimStore;
pub use groups::PgScimGroupQueries;
pub use users::PgScimUserQueries;
