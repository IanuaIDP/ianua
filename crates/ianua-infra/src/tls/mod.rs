//! TLS certificates for the hostnames tenants bring: issued by an ACME
//! authority, proved over HTTP-01 for a domain the tenant points at us and
//! over DNS-01 for one delegated to us, or signed by themselves in
//! development.

mod accounts;
mod proofs;
mod provisioner;
mod seams;
mod self_signed;
mod transport;
mod unavailable;
mod zones;

pub use proofs::{DnsProofs, VisibilityWait};
pub use provisioner::{AcmeSettings, AcmeTlsProvisioner};
pub use seams::{AcmeAccountStore, AcmeDirectory, AcmeDnsChallengeStore};
pub use self_signed::SelfSignedTlsProvisioner;
pub use unavailable::NoTlsProvisioner;
pub use zones::ZoneAcmeDnsChallengeStore;
