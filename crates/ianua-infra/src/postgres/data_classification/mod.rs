//! The stores of the data classification context: the rules a tenant
//! classifies its data by, each table under row-level security.

mod rule_sets;

pub use rule_sets::PgClassificationStore;
