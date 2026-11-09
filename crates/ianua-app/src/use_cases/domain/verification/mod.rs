//! Proving a tenant controls a domain, and checking it keeps doing so.

pub(crate) mod health_check;
pub mod proof;
mod recorded;
pub(crate) mod retry;
pub mod verified;
pub(crate) mod verify;

pub use health_check::{DomainHealthCheckPorts, DomainHealthCheckUseCase};
pub use retry::{RetryPorts, RetryUseCase};
pub use verify::{VerifyDomainPorts, VerifyDomainUseCase};
