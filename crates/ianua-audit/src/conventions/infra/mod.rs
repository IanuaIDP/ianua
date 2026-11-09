//! The conventions infra keeps, checked over its source so a file that
//! drifts fails the build instead of waiting for a reviewer.
//!
//! - Names and folders read as one phrase, and an adapter is named by its
//!   provider and its port: [`naming`].
//! - The code style the domain and the app keep: [`style`].
//! - The outside world stays outside the ports, and every call out is
//!   bounded: [`boundaries`].
//! - Every query is lean as written, and kept in a file of its own under
//!   its table: [`sql`]. Whether it can use an index is asked of Postgres
//!   in the plan tests.
//! - The schema keeps every tenant table under row-level security, every
//!   table keyed, and the migrations in one sequence: [`schema`].
//! - A released migration never changes and is never removed:
//!   [`released`].
//! - Tables point at each other honestly: no link across tenants, a delete
//!   rule and an index on every link, and every id a link or explained:
//!   [`relationships`].
//! - Every store has the one shape: a mapper rebuilding through the
//!   domain, its JSON shapes pinned, its tests through the real stores:
//!   [`stores`].
//! - Every bus subject, stream and cache key is put under the deployment's
//!   namespace in one place: [`namespaces`].
//! - Every column is written by a query and read back by one: [`fields`].
//! - Every kind of reference the domain names, the audit store reads
//!   back: [`references`].

pub(crate) mod boundaries;
pub(crate) mod fields;
pub(crate) mod namespaces;
pub(crate) mod naming;
pub(crate) mod references;
pub(crate) mod relationships;
pub(crate) mod released;
pub(crate) mod schema;
pub(crate) mod source;
pub(crate) mod sql;
pub(crate) mod stores;
pub(crate) mod style;
