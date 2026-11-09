//! Custom domain bodies: a registered domain and the records that point it
//! here, where its proof stands, a handover between tenants, and the
//! record sets of a delegated zone.

pub mod certificates;
pub mod dns_records;
pub mod handover;
pub mod registration;
pub mod verification;
