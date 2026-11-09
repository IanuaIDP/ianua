//! What keeps the process's request metrics small: the closed sets a
//! client's words are narrowed to, and the cap on how many label
//! combinations a metric may track.
//!
//! A metrics store is brought down by its number of series long before it
//! is brought down by volume, and a label value a client can choose is a
//! series a client can open. So a method becomes one the proxy knows or
//! `other`, a status becomes its class, and past a metric's cap every new
//! combination is folded into one `overflow` series. Totals stay right;
//! only the labels of the traffic past the cap are lost.
//!
//! Both the proxy's observer and the API's use these, so the two scrapes
//! bound their labels the same way.

use std::collections::HashSet;
use std::hash::Hash;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{PoisonError, RwLock};

use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::HttpMethod;
use prometheus::core::Collector;
use prometheus::{HistogramOpts, HistogramVec, IntCounterVec, Opts, Registry};

/// The label value of traffic past a metric's cap.
pub(crate) const OVERFLOW: &str = "overflow";

/// The method label of a token the proxy has no name for.
pub(crate) const OTHER_METHOD: &str = "other";

/// Latency buckets, in seconds, from a millisecond to ten seconds: the
/// question is whether a request took milliseconds or seconds, and the tail
/// matters more than the middle.
pub(crate) const LATENCY_BUCKETS: [f64; 12] = [
    0.001, 0.005, 0.010, 0.025, 0.050, 0.100, 0.250, 0.500, 1.0, 2.5, 5.0, 10.0,
];

/// A counter named `name`, labelled by `labels`.
pub(crate) fn counter(
    name: &str,
    help: &str,
    labels: &[&str],
) -> Result<IntCounterVec, DomainError> {
    IntCounterVec::new(Opts::new(name, help), labels).map_err(DomainError::infra)
}

/// A latency histogram named `name` over [`LATENCY_BUCKETS`], labelled by
/// `labels`.
pub(crate) fn histogram(
    name: &str,
    help: &str,
    labels: &[&str],
) -> Result<HistogramVec, DomainError> {
    HistogramVec::new(
        HistogramOpts::new(name, help).buckets(LATENCY_BUCKETS.to_vec()),
        labels,
    )
    .map_err(DomainError::infra)
}

/// Adds every one of `metrics` to `registry`.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when `registry` already holds a
/// metric of one of their names: an observer registered twice would count
/// every request twice.
pub(crate) fn register(
    registry: &Registry,
    metrics: Vec<Box<dyn Collector>>,
) -> Result<(), DomainError> {
    metrics
        .into_iter()
        .try_for_each(|metric| registry.register(metric))
        .map_err(DomainError::infra)
}

/// The method label, narrowed to the methods the proxy knows: a client may
/// send any token, and a series per invented one fills the store.
pub(crate) fn method_label(method: &str) -> &'static str {
    HttpMethod::parse(method).map_or(OTHER_METHOD, |known| known.as_str())
}

/// Whether a label combination keeps its own series.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Admitted {
    /// It is tracked, or there was room to track it.
    Own,
    /// The cap is reached: count it under the overflow series.
    Folded,
}

/// The label combinations one metric tracks, at most `most` of them.
pub(crate) struct SeriesCap<K> {
    tracked: RwLock<HashSet<K>>,
    most: usize,
    metric: &'static str,
    overflowed: AtomicBool,
}

impl<K: Eq + Hash + Clone> SeriesCap<K> {
    /// A cap of `most` combinations for the metric named `metric`.
    pub(crate) fn new(metric: &'static str, most: usize) -> Self {
        Self {
            tracked: RwLock::new(HashSet::new()),
            most,
            metric,
            overflowed: AtomicBool::new(false),
        }
    }

    /// Whether `key` keeps its own series, tracking it when there is room.
    /// Says once, in a warning, that the cap was reached.
    pub(crate) fn admit(&self, key: &K) -> Admitted {
        let is_tracked = self
            .tracked
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .contains(key);
        if is_tracked || self.track(key) {
            return Admitted::Own;
        }
        self.warn_once();
        Admitted::Folded
    }

    /// Whether traffic is being folded into the overflow series.
    pub(crate) fn has_overflowed(&self) -> bool {
        self.overflowed.load(Ordering::Relaxed)
    }

    /// Starts tracking `key`, when the cap leaves room for it.
    fn track(&self, key: &K) -> bool {
        let mut tracked = self.tracked.write().unwrap_or_else(PoisonError::into_inner);
        if tracked.contains(key) {
            return true;
        }
        if tracked.len() >= self.most {
            return false;
        }
        tracked.insert(key.clone())
    }

    /// Warns the first time the cap is reached, and never again.
    fn warn_once(&self) {
        if self.overflowed.swap(true, Ordering::Relaxed) {
            return;
        }
        tracing::warn!(
            metric = self.metric,
            cap = self.most,
            "a metric reached its series cap; further label combinations are counted under `overflow`"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two combinations fit a cap of two; a third is folded, while the
    /// first two keep their own series.
    #[test]
    fn combinations_past_the_cap_are_folded() {
        let cap = SeriesCap::new("test_total", 2);

        let first = cap.admit(&"a");
        let second = cap.admit(&"b");
        let third = cap.admit(&"c");

        assert_eq!(
            (first, second, third),
            (Admitted::Own, Admitted::Own, Admitted::Folded)
        );
        assert_eq!(cap.admit(&"a"), Admitted::Own);
        assert!(cap.has_overflowed());
    }

    /// A cap not yet reached says nothing has overflowed.
    #[test]
    fn a_cap_with_room_has_not_overflowed() {
        let cap = SeriesCap::new("test_total", 2);

        cap.admit(&"a");

        assert!(!cap.has_overflowed());
    }

    /// Unknown or empty method names share the other label while GET retains its name.
    #[test]
    fn an_invented_method_is_labelled_other() {
        assert_eq!(method_label("GET"), "GET");
        for invented in ["BREW", "PROPFIND", ""] {
            assert_eq!(method_label(invented), OTHER_METHOD, "{invented}");
        }
    }
}
