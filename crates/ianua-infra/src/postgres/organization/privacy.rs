//! An organization member's erasure requests and consent records: the
//! stores of `ports/organization/privacy.rs`.

mod consents;
mod erasure_requests;

pub use consents::PgOrgConsentStore;
pub use erasure_requests::PgOrgErasureRequestStore;
