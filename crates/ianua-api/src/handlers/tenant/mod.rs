//! Tenant handlers, one file per app folder: a tenant's life, its
//! settings, copies of its setup into another tenant, and the streams of
//! its audit records.

pub mod audit_streams;
pub mod clones;
pub mod lifecycle;
pub mod settings;
