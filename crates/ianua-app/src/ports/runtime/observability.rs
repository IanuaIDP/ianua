//! Where finished requests get reported.
//!
//! The proxy has a growing number of things that want to hear about traffic:
//! structured logs, the tenant's live dashboard, the access log behind usage
//! metrics, a Prometheus scrape, a trace exporter, a log shipper. Each is a
//! separate concern with a separate failure mode, and none of them is allowed
//! to affect the request that produced it.
//!
//! One port, one value, many implementations. Adding a destination is writing
//! an observer and wiring it in; nothing that collects the facts changes.

use std::sync::Arc;

use ianua_domain::domains::proxy::observation::{RequestObservation, TunnelClose};

/// Somewhere finished requests are reported to.
///
/// Deliberately synchronous and infallible. Every implementation is called
/// from the end of a request, so one that blocks delays a client's response
/// and one that returns an error invites a caller to treat reporting as a
/// reason to fail a request it has already served. An observer that needs to
/// do slow work owns the queue for it.
pub trait RequestObserver: Send + Sync {
    /// Reports one finished request. Must not block and must not panic.
    fn observe(&self, observation: &RequestObservation);

    /// Reports that the gateway closed the connection `observation`'s
    /// request upgraded, as `closed` says. It comes after the request's own
    /// report and is no second request: only a destination that keeps the
    /// request's record needs it, so the default ignores it. Must not block
    /// and must not panic.
    fn observe_tunnel_close(&self, _observation: &RequestObservation, _closed: TunnelClose) {}
}

/// Reports every request to each of several observers.
///
/// The proxy holds one of these and knows nothing about what is inside it,
/// which is the point: how many destinations a deployment has configured is a
/// wiring decision, not something the request path is aware of.
#[derive(Default, Clone)]
pub struct RequestObservers {
    observers: Vec<Arc<dyn RequestObserver>>,
}

impl RequestObservers {
    /// Reports to nobody.
    ///
    /// The honest default: a proxy with no observability configured still
    /// runs, and does not pretend to be reporting anywhere.
    #[must_use]
    pub fn none() -> Self {
        Self::default()
    }

    /// Adds a destination.
    #[must_use]
    pub fn and(mut self, observer: Arc<dyn RequestObserver>) -> Self {
        self.observers.push(observer);
        self
    }

    /// Adds a destination that a deployment may not have configured.
    #[must_use]
    pub fn and_maybe(self, observer: Option<Arc<dyn RequestObserver>>) -> Self {
        match observer {
            Some(observer) => self.and(observer),
            None => self,
        }
    }

    /// How many destinations are configured.
    #[must_use]
    pub fn len(&self) -> usize {
        self.observers.len()
    }

    /// Whether nothing is listening.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.observers.is_empty()
    }
}

impl RequestObserver for RequestObservers {
    fn observe(&self, observation: &RequestObservation) {
        for observer in &self.observers {
            observer.observe(observation);
        }
    }

    fn observe_tunnel_close(&self, observation: &RequestObservation, closed: TunnelClose) {
        for observer in &self.observers {
            observer.observe_tunnel_close(observation, closed);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use ianua_domain::domains::proxy::observation::RequestOutcome;
    use ianua_domain::types::CorrelationId;

    use super::*;

    struct Counting(AtomicUsize);

    impl RequestObserver for Counting {
        fn observe(&self, _observation: &RequestObservation) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    struct Recording(Mutex<Vec<CorrelationId>>);

    impl RequestObserver for Recording {
        fn observe(&self, observation: &RequestObservation) {
            self.0
                .lock()
                .expect("test mutex")
                .push(observation.correlation_id);
        }
    }

    fn observation() -> RequestObservation {
        crate::test_support::request_observation(RequestOutcome::Allowed {
            upstream_status: 200,
        })
    }

    /// Two places are set up to receive request reports. Each one hears about
    /// both requests.
    #[test]
    fn every_observer_sees_every_request() {
        let first = Arc::new(Counting(AtomicUsize::new(0)));
        let second = Arc::new(Counting(AtomicUsize::new(0)));
        let observers = RequestObservers::none()
            .and(first.clone())
            .and(second.clone());

        observers.observe(&observation());
        observers.observe(&observation());

        assert_eq!(first.0.load(Ordering::SeqCst), 2);
        assert_eq!(second.0.load(Ordering::SeqCst), 2);
    }

    /// A request is reported as it happened, with its own correlation id.
    #[test]
    fn observers_all_see_the_same_request() {
        let recorder = Arc::new(Recording(Mutex::new(Vec::new())));
        let observers = RequestObservers::none().and(recorder.clone());
        let observed = observation();

        observers.observe(&observed);

        assert_eq!(
            recorder.0.lock().expect("test mutex").as_slice(),
            [observed.correlation_id]
        );
    }

    /// A deployment with nothing configured still serves traffic.
    #[test]
    fn reporting_to_nobody_is_allowed() {
        let observers = RequestObservers::none();

        observers.observe(&observation());

        assert!(observers.is_empty());
    }

    /// A report destination that was never set up is left out, and only the
    /// one that was set up is counted.
    #[test]
    fn an_unconfigured_destination_is_simply_absent() {
        let observers = RequestObservers::none()
            .and_maybe(None)
            .and_maybe(Some(Arc::new(Counting(AtomicUsize::new(0)))));

        assert_eq!(observers.len(), 1);
        assert!(!observers.is_empty());
    }

    /// With two report destinations set up, both are counted.
    #[test]
    fn every_configured_destination_is_counted() {
        let observers = RequestObservers::none()
            .and(Arc::new(Counting(AtomicUsize::new(0))))
            .and(Arc::new(Counting(AtomicUsize::new(0))));

        assert_eq!(observers.len(), 2);
    }
}
