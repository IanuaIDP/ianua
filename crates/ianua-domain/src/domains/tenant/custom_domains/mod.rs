//! A tenant's own domains: registration, proof, certificates and DNS.

pub mod acme_challenge;
/// TLS certificates for a tenant's custom domains.
pub mod certificate;
pub mod dns_zone;
pub mod handover;
pub mod handover_offer;
pub mod owned_domain;
/// Who holds the DNS for a domain a tenant registered.
pub mod registered_domain;
pub mod traffic_record;
pub mod trusted_domains;
pub mod uploaded_certificate;
/// DNS verification and TLS certificate status of a registered domain.
pub mod verification_status;
