//! Custom domain use cases: registering, proving, removing and handing over
//! a tenant's domains, their certificates and the DNS records of delegated
//! ones, and the catalog the nameservers answer from. A tenant lets go of a
//! primary domain that is removed or loses its proof.

pub mod certificates;
pub mod dns_records;
pub mod handover;
mod limits;
mod lookup;
pub mod nameservers;
mod primary;
pub mod registration;
pub mod verification;
