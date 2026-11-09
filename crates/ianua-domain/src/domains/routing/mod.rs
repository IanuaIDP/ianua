/// The backends a service forwards to: upstreams, discovery and health checks.
pub mod backend;
pub mod connector;
/// Who may change routing, and the right each change needs.
pub mod control;
pub mod egress;
/// Domain events for routes, services, stream routes, egress policies, app
/// sign-in and private-network connectors.
pub mod events;
pub mod import;
/// How a request is matched to a route: paths, hosts and parameters.
pub mod matching;
/// Route policy: what a request must prove before a route forwards it.
pub mod policy;
/// Routes: path patterns in a tenant that forward to a service.
pub mod route;
/// Tenant route status: active or disabled.
pub mod route_status;
pub(crate) mod sealed;
pub mod service;
/// Signing people in on a service's own domain.
pub mod sign_in;
pub mod stream;

#[cfg(test)]
pub(crate) mod fixtures;
