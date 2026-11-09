//! A request as the pipeline reads and changes it.

/// What the proxy read of a body before deciding on it.
pub mod body;
/// The data a request carries from one pipeline stage to the next.
pub mod context;
/// Whether a request a cookie authenticated was sent by a page allowed to.
pub mod cross_site;
pub mod device;
pub mod forwarded;
pub mod graphql;
pub mod identification;
pub mod trace;
pub mod transform;
