//! Where the API reports the requests it answered, for the process's own
//! metrics.
//!
//! The proxy reports its traffic as a
//! [`RequestObservation`](ianua_domain::domains::proxy::observation::RequestObservation);
//! the API's own requests are smaller facts: which route answered, by its
//! template, with which method and status, and how long it took. Never the
//! path as sent, which carries ids and whatever a client typed.

use std::time::Duration;

/// The route a request was answered by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServedRoute<'a> {
    /// The route's template as the router declares it, such as
    /// `/api/v1/tenants/{tenant_id}/users`, never the path as sent.
    Template(&'a str),
    /// No route matched.
    Unmatched,
}

/// One request the API answered, reduced to what may become a metric.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServedRequest<'a> {
    /// The route that answered it.
    pub route: ServedRoute<'a>,
    /// The method as it arrived. Any token a client sent; the observer
    /// narrows it to a closed set.
    pub method: &'a str,
    /// The status the client was answered with.
    pub status: u16,
    /// How long answering took.
    pub latency: Duration,
}

/// Somewhere the API's answered requests are reported to.
///
/// Synchronous and infallible, as [`RequestObserver`](crate::ports::runtime::RequestObserver)
/// is: it runs at the end of every request, so it must neither block the
/// answer nor give a reason to fail one already given.
pub trait ServedRequestObserver: Send + Sync {
    /// Reports one answered request. Must not block and must not panic.
    fn observe(&self, served: &ServedRequest<'_>);
}
