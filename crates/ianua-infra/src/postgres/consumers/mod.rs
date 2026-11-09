//! The stores of the consumers context: the non-human callers a tenant lets
//! through, each table under row-level security.

mod registry;

pub use registry::PgConsumerStore;
