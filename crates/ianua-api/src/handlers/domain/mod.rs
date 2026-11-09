//! Custom domain handlers, one file per app folder: registration,
//! verification, certificates, handover and the records of a delegated
//! zone.

pub mod certificates;
pub mod dns_records;
pub mod handover;
pub mod registration;
pub mod verification;
