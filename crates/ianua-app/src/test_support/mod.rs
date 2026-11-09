//! Shared test fakes and helpers for app-layer use case tests.

pub mod acting;
mod listing;

pub mod agents;
pub mod audit;
pub mod authentication;
pub mod authorization;
pub mod branding;
pub mod consumers;
pub mod crypto;
pub mod data_classification;
pub mod directory;
pub mod directory_service;
pub mod domain;
pub mod federation;
pub mod files;
pub mod identity;
pub mod messaging;
pub mod notification_delivery;
pub mod notifications;
pub mod oauth;
pub mod operator;
pub mod organization;
pub mod pages;
pub mod proxy;
pub mod retention;
pub mod routing;
pub mod scheduling;
pub mod scim;
pub mod signals;
pub mod tenant;
pub mod webhooks;
pub mod workflows;

mod audit_labels;
mod callers;
mod doubles;
mod events;
mod existence;
mod limits;
mod mail;
mod metrics;
mod races;
mod realtime;
mod runtime;
mod uniqueness;
mod wording;
mod work;

pub use audit_labels::*;
pub use callers::*;
pub use doubles::*;
pub use events::*;
pub use existence::*;
pub use limits::*;
pub use mail::*;
pub use metrics::*;
pub use races::*;
pub use realtime::*;
pub use runtime::*;
pub use uniqueness::*;
pub use wording::*;
pub use work::*;

/// A port's neutral test double, the one a use case's `Ports::fakes()` fills
/// that port with: an empty store, a check that passes, a sender that only
/// records. A test overrides the ports it is about and takes the rest:
///
/// ```ignore
/// AddMemberPorts {
///     groups: Arc::new(InMemoryGroupStore::holding(group)),
///     ..AddMemberPorts::fakes()
/// }
/// ```
pub trait Fake {
    /// The neutral double.
    fn fake() -> Self;
}

/// Polls a ready future to completion without an async runtime.
pub fn block_on<F: std::future::Future>(f: F) -> F::Output {
    let mut f = std::pin::pin!(f);
    let waker = std::task::Waker::noop();
    let mut cx = std::task::Context::from_waker(waker);
    match f.as_mut().poll(&mut cx) {
        std::task::Poll::Ready(v) => v,
        std::task::Poll::Pending => panic!("future should resolve immediately"),
    }
}
