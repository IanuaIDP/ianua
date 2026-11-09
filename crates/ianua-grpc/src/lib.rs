//! The gRPC face of the control plane.
//!
//! A second driving adapter beside the HTTP API, for callers that are
//! machines rather than people: the data planes. They live on other hosts,
//! authenticate with certificates rather than sessions, and need streams
//! rather than requests — a nameserver that had to ask "has anything changed"
//! every few seconds would be stale for exactly as long as the gap.
//!
//! Nothing here holds business rules. Each service maps the contract in
//! `ianua-proto` onto a port and back, the same way the HTTP handlers map
//! their DTOs.

#![cfg_attr(not(test), warn(clippy::too_many_lines))]

/// Streams the zone catalog to the authoritative nameservers.
pub mod dns_zones;
/// Listening for the data planes, over mutual TLS.
pub mod serve;

pub use dns_zones::DnsZonesService;
pub use serve::{GrpcConfig, GrpcError, GrpcListener, GrpcTls};
