//! Fakes for the proxy use cases: pipelines and their stages, device
//! posture, the request log and log shipping.

mod log_shipping;
mod pipelines;
mod posture;
mod records;

pub use log_shipping::*;
pub use pipelines::*;
pub use posture::*;
pub use records::*;
