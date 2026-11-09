//! The stores of the cloud context: the connections organizations made to
//! their own cloud accounts, kept in the platform database with their
//! secrets sealed.

mod accounts;

pub use accounts::PgCloudAccountStore;
