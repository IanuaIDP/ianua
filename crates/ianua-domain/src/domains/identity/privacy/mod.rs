//! Consent, erasure and export: what a person agreed to, having their data
//! deleted, and getting a copy of it.

/// Consent records: what a person agreed to, and when they withdrew it.
pub mod consent;
pub mod erasure;
/// Where a request to erase a person's data stands (GDPR Article 17).
pub mod erasure_status;
pub mod export;
/// Where a request for a copy of a person's data stands.
pub mod export_state;
