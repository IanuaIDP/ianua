pub mod access;
pub mod assertion;
pub mod events;
/// The narrowed token the TokenExchange stage hands an upstream.
pub mod exchange;
/// Canary decoys and WASM modules handed to a tenant for its stages.
pub mod issued;
pub mod log_shipping;
pub mod observation;
pub mod pipeline;
/// Proxy pipeline status: draft, active, disabled.
pub mod pipeline_status;
/// A request as the pipeline reads and changes it.
pub mod request;
/// The stages a pipeline runs, their settings and what each decides.
pub mod stages;

#[cfg(test)]
pub(crate) mod fixtures;
