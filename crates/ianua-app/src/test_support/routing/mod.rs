//! Fakes for the routing use cases: routes, the services they forward to,
//! stream routes and egress policies, and the records tests start from.

mod connector_certificates;
mod connectors;
mod egress;
mod health;
mod held;
mod records;
mod routes;
mod services;
mod stream_routes;

pub use connector_certificates::*;
pub use connectors::*;
pub use egress::*;
pub use health::*;
pub use records::*;
pub use routes::*;
pub use services::*;
pub use stream_routes::*;
