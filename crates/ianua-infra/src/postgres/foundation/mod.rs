//! What every store stands on: the databases and their pools, the unit of
//! work every store call runs through, row-level security, the audit
//! chain's locks and seals, the schema's migrations and the roles the app
//! and the audit purge sign in as, keyset paging (with filters shaped as trees and SCIM's one
//! stretch by position), tenants' own schemas with their trail and purge,
//! how stored values are read back into the domain, and what a database
//! failure means to it.

pub(crate) mod audit_chain;
pub(crate) mod envelope;
pub(crate) mod errors;
pub mod migrations;
pub(crate) mod paging;
pub mod pool;
pub mod roles;
pub(crate) mod security;
pub(crate) mod stored;
pub(crate) mod tenant_databases;
pub mod unit;
pub mod workers;
