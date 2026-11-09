//! A company's own images: the registries a tenant's administrator allows,
//! versions saved pinned to an image's digest, and the login an image is
//! pulled with when it is resolved, scanned or run.

pub(crate) mod pulls;
pub mod registries;
pub(crate) mod save;

pub use pulls::ImagePulls;
pub use save::{SavePorts, SaveRequest, SaveUseCase};
