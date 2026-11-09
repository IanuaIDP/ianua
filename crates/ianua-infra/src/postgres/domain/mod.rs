//! The stores of the domain context: the hostnames tenants register, their
//! certificates, ACME challenges and the accounts held with certificate
//! authorities, handover offers, and the DNS zones of the names tenants
//! delegated to us.
//!
//! The registrations are tenant rows; everything a hostname is found by
//! with no tenant in hand is kept in the platform database: the claims on
//! names, the certificates beside them, the challenges, the offers, and
//! the zones with their records.

mod acme;
pub(crate) mod certificates;
mod handovers;
pub(crate) mod platform;
mod registrations;
mod zones;

pub use acme::{PgAcmeAccountStore, PgAcmeChallengeStore};
pub use certificates::{PgCertificateStore, PgCrossTenantCertificateStore};
pub use handovers::PgHandoverOfferStore;
pub use platform::{PgPlatformCertificateStore, PgPlatformDnsChallenges};
pub use registrations::{PgCrossTenantDomainStore, PgRegisteredDomainStore};
pub use zones::{PgDnsZoneReader, PgDnsZoneWriter};
