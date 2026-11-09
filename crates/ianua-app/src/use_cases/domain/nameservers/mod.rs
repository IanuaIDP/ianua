//! What the nameservers answer from: the zones tenants delegated to us,
//! read whole and settled by the domain's rules.

pub(crate) mod catalog;

pub use catalog::{LoadCatalogPorts, LoadCatalogUseCase};
