//! Routing use cases: routes, the services they forward to, stream routes
//! and egress policies of the tenant's proxy.

/// Private-network connectors the gateway reaches upstreams through.
pub mod connectors;
pub(crate) mod destinations;
/// Where a service agents can reach may send traffic.
pub mod egress;
pub(crate) mod lookup;
/// HTTP routes: what the proxy answers, and where it forwards.
pub mod routes;
/// The backends routes forward to, and how people sign in on them.
pub mod services;
/// Ports the proxy listens on below HTTP.
pub mod stream_routes;
mod tenant_domains;
