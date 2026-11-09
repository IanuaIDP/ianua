//! Tenant bodies: a tenant's life and overview, its settings, where its
//! data lives, the fresh proof a protection change asks for, copies of its
//! setup into another tenant, and the streams of its audit records.

pub mod audit_streams;
pub mod clones;
pub mod lifecycle;
pub mod proof;
pub mod residency;
pub mod settings;
