//! Reading the public DNS: the records that prove a tenant controls a
//! domain, the delegation the zone above a name writes for it, and that a
//! certificate authority will find a DNS-01 proof.
//!
//! The zones tenants delegated to us are Postgres stores, in
//! `postgres/domain/zones.rs`; this folder only asks the world, and the
//! backends a service names by SRV or A/AAAA records.

mod discovery;
mod referral;
mod resolver;

pub use discovery::DnsBackendDiscovery;
pub(crate) use resolver::address_resolver;
pub use resolver::{LookupBounds, RecursiveDnsResolver};
