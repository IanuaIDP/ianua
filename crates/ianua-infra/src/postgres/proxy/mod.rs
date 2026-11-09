//! The stores of the proxy context: a tenant's pipelines and the WASM
//! modules its stages run, the places it ships request records to, the
//! records of its proxied requests, written by the gateway and searched by
//! its admins, and what the gateway serves across every tenant.

mod log_shipping;
mod pipelines;
mod requests;
mod serving;
mod wasm;

pub use log_shipping::PgLogShippingStore;
pub use pipelines::PgPipelineStore;
pub use requests::{PgProxyAccessLogSink, PgProxyRequestLog, PgRequestRecordRetention};
pub use serving::{PgCrossTenantHosts, PgCrossTenantServedCertificates};
pub use wasm::PgWasmModuleStore;
