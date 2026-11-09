//! The backends a service forwards to: upstreams, discovery and health checks.

pub mod assertion;
pub mod balancing;
pub mod circuit_breaker;
pub mod discovery;
pub mod health_check;
pub mod retry;
pub mod tls;
/// Upstreams: the backends a service forwards to, and how it spreads load
/// across them.
pub mod upstream;
