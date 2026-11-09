//! Proxied requests counted into the process's own metrics registry, for
//! the Prometheus scrape [`LocalMetricsExporter`](crate::runtime::LocalMetricsExporter)
//! writes out.
//!
//! Three metrics, all kept in memory and read only when a scrape asks:
//!
//! - `ianua_proxy_requests_total`, by tenant, route, method, status class
//!   and outcome;
//! - `ianua_proxy_request_duration_seconds`, a latency histogram by tenant
//!   and route;
//! - `ianua_proxy_denials_total`, by tenant and the check that refused.
//!
//! # What may be a label
//!
//! A metrics store is brought down by its number of series long before it
//! is brought down by volume, and every label value here is chosen by
//! someone. So each label is either bounded by configuration (the tenant
//! and the route, by their ids) or narrowed to a small closed set: the
//! method to the ones the proxy knows, the status to its class, the
//! outcome to three words, the refusing check to its stable name. No user,
//! agent or consumer id, no path, no client address, no denial reason and
//! no rule name is ever a label: those are what a client controls, or what
//! names a person. And the number of label combinations is capped outright
//! by [`SeriesCap`]; everything past the cap is folded into one overflow
//! series, so totals stay right while the series count stops growing.

use ianua_app::ports::runtime::RequestObserver;
use ianua_domain::domains::proxy::observation::{RequestObservation, RequestOutcome, RouteMatch};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{Fact, TenantId};
use prometheus::{HistogramVec, IntCounterVec, Registry};

use crate::runtime::series::{
    Admitted, OTHER_METHOD, OVERFLOW, SeriesCap, counter, histogram, method_label, register,
};

/// How many distinct label combinations are tracked before the rest are
/// folded into the overflow series.
///
/// Ten thousand route, method and status combinations is more than any
/// deployment this is built for serves. A proxy that reaches it is most
/// likely being probed.
const MAX_SERIES: usize = 10_000;

/// The tenant or route label of a request that resolved none.
const NONE: &str = "none";

/// Counts every finished proxied request into a Prometheus registry.
pub struct LocalRequestObserver {
    requests: IntCounterVec,
    latency: HistogramVec,
    denials: IntCounterVec,
    series: SeriesCap<Series>,
}

/// One combination of labels a request is counted under.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Series {
    tenant: String,
    route: String,
    method: &'static str,
    status_class: &'static str,
    outcome: &'static str,
}

impl Series {
    /// The labels `observation` would be counted under, before the cap.
    fn of(observation: &RequestObservation) -> Self {
        Self {
            tenant: tenant_label(&observation.tenant_id),
            route: route_label(observation.route),
            method: method_label(observation.method.as_str()),
            status_class: observation.status_class(),
            outcome: outcome_label(&observation.outcome),
        }
    }

    /// The same request, counted under the overflow series.
    fn folded(self) -> Self {
        Self {
            tenant: OVERFLOW.to_owned(),
            route: OVERFLOW.to_owned(),
            method: OTHER_METHOD,
            ..self
        }
    }
}

impl LocalRequestObserver {
    /// An observer whose metrics are registered in `registry`, the one the
    /// process's [`LocalMetricsExporter`](crate::runtime::LocalMetricsExporter)
    /// reads.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when `registry` already holds a
    /// metric of one of these names, such as when two observers are
    /// registered in one registry.
    pub fn register(registry: &Registry) -> Result<Self, DomainError> {
        let observer = Self {
            requests: counter(
                "ianua_proxy_requests_total",
                "Requests the proxy finished, by outcome.",
                &["tenant", "route", "method", "status_class", "outcome"],
            )?,
            latency: histogram(
                "ianua_proxy_request_duration_seconds",
                "How long the proxy took to finish a request.",
                &["tenant", "route"],
            )?,
            denials: counter(
                "ianua_proxy_denials_total",
                "Requests the proxy refused, by the check that refused them.",
                &["tenant", "decided_by"],
            )?,
            series: SeriesCap::new("ianua_proxy_requests_total", MAX_SERIES),
        };
        register(
            registry,
            vec![
                Box::new(observer.requests.clone()),
                Box::new(observer.latency.clone()),
                Box::new(observer.denials.clone()),
            ],
        )?;
        Ok(observer)
    }

    /// Whether traffic is being folded into the overflow series.
    #[must_use]
    pub fn has_overflowed(&self) -> bool {
        self.series.has_overflowed()
    }

    /// The series `observation` is counted under: its own while it is
    /// tracked or room is left, the overflow series past the cap.
    fn series_for(&self, observation: &RequestObservation) -> Series {
        let candidate = Series::of(observation);
        match self.series.admit(&candidate) {
            Admitted::Own => candidate,
            Admitted::Folded => candidate.folded(),
        }
    }

    /// Counts `observation` as the request it was under `series`.
    fn count(&self, series: &Series, observation: &RequestObservation) {
        if let Ok(counter) = self.requests.get_metric_with_label_values(&[
            &series.tenant,
            &series.route,
            series.method,
            series.status_class,
            series.outcome,
        ]) {
            counter.inc();
        }
        if let Ok(histogram) = self
            .latency
            .get_metric_with_label_values(&[&series.tenant, &series.route])
        {
            histogram.observe(observation.latency.as_seconds_f64().max(0.0));
        }
    }

    /// Counts the refusal of `observation`, when it was refused.
    fn count_denial(&self, series: &Series, observation: &RequestObservation) {
        let Some(decided_by) = observation.decided_by() else {
            return;
        };
        if let Ok(counter) = self
            .denials
            .get_metric_with_label_values(&[&series.tenant, decided_by.name()])
        {
            counter.inc();
        }
    }
}

impl RequestObserver for LocalRequestObserver {
    fn observe(&self, observation: &RequestObservation) {
        let series = self.series_for(observation);
        self.count(&series, observation);
        self.count_denial(&series, observation);
    }
}

/// The tenant label: its id, or `none` when the request resolved none.
fn tenant_label(tenant: &Fact<TenantId>) -> String {
    match tenant {
        Fact::Known(tenant_id) => tenant_id.to_string(),
        Fact::Unknown => NONE.to_owned(),
    }
}

/// The route label: its id, or `none` when no route matched.
fn route_label(route: RouteMatch) -> String {
    match route {
        RouteMatch::Matched { route_id, .. } => route_id.to_string(),
        RouteMatch::NoRoute => NONE.to_owned(),
    }
}

/// The outcome label: allowed, denied, or undecided.
fn outcome_label(outcome: &RequestOutcome) -> &'static str {
    match outcome {
        RequestOutcome::Allowed { .. } => "allowed",
        RequestOutcome::Denied { .. } => "denied",
        RequestOutcome::Undecided => "undecided",
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::ports::runtime::MetricsExporter;
    use ianua_app::test_support::request_observation;
    use ianua_domain::domains::proxy::observation::{
        DecidingRule, DecidingStage, GatewayCheck, ObservedPath, ObservedPrincipal,
    };
    use ianua_domain::types::{Label, RouteId, ServiceId, UntrustedText, UserId};
    use prometheus::proto::MetricFamily;

    use super::*;
    use crate::runtime::LocalMetricsExporter;

    fn allowed() -> RequestObservation {
        let mut observed = request_observation(RequestOutcome::Allowed {
            upstream_status: 200,
        });
        observed.tenant_id = Fact::Known(TenantId::new());
        observed.route = RouteMatch::Matched {
            route_id: RouteId::new(),
            service_id: ServiceId::new(),
        };
        observed
    }

    fn denied_by_route_check() -> RequestObservation {
        let mut observed = allowed();
        observed.outcome = RequestOutcome::Denied {
            status: 403,
            reason: "contractor ann@acme.test refused by off hours".to_owned(),
            decided_by: DecidingStage::Gateway(GatewayCheck::Route),
            rule: DecidingRule::Named(Label::new("name", "contractors off hours").unwrap()),
        };
        observed
    }

    fn scrape(registry: &Registry) -> String {
        LocalMetricsExporter::new(registry.clone())
            .render()
            .unwrap()
            .into_string()
    }

    fn requests_counted(registry: &Registry) -> u64 {
        registry
            .gather()
            .iter()
            .filter(|family| family.get_name() == "ianua_proxy_requests_total")
            .flat_map(MetricFamily::get_metric)
            .map(|metric| metric.get_counter().get_value() as u64)
            .sum()
    }

    /// Two served requests are counted as allowed `2xx` under their route,
    /// and the scrape shows the counter and the latency histogram.
    #[test]
    fn served_requests_are_counted_with_their_latency() {
        let registry = Registry::new();
        let observer = LocalRequestObserver::register(&registry).unwrap();
        let served = allowed();
        let RouteMatch::Matched { route_id, .. } = served.route else {
            panic!("a matched route");
        };

        observer.observe(&served);
        observer.observe(&served);

        let text = scrape(&registry);
        assert!(text.contains(&format!("route=\"{route_id}\"")), "{text}");
        assert!(text.contains("outcome=\"allowed\""), "{text}");
        assert!(text.contains("status_class=\"2xx\""), "{text}");
        assert!(
            text.contains("ianua_proxy_request_duration_seconds_bucket"),
            "{text}"
        );
        assert!(
            text.contains("ianua_proxy_request_duration_seconds_count"),
            "{text}"
        );
        assert_eq!(requests_counted(&registry), 2);
    }

    /// A request the route check refused is counted as denied `4xx`, and
    /// the refusal under the check's stable name.
    #[test]
    fn a_refused_request_is_counted_by_the_check_that_refused_it() {
        let registry = Registry::new();
        let observer = LocalRequestObserver::register(&registry).unwrap();

        observer.observe(&denied_by_route_check());

        let text = scrape(&registry);
        assert!(text.contains("outcome=\"denied\""), "{text}");
        assert!(text.contains("status_class=\"4xx\""), "{text}");
        assert!(text.contains("ianua_proxy_denials_total"), "{text}");
        assert!(text.contains("decided_by=\"route\""), "{text}");
    }

    /// A denied request's metrics omit the person's id, path, client address,
    /// email-bearing reason and rule name.
    #[test]
    fn no_person_path_or_reason_becomes_a_label() {
        let registry = Registry::new();
        let observer = LocalRequestObserver::register(&registry).unwrap();
        let ann = UserId::new();
        let mut observed = denied_by_route_check();
        observed.principal = ObservedPrincipal::User(ann);
        observed.path = ObservedPath::record("/reports/ann-salary-2026");

        observer.observe(&observed);

        let text = scrape(&registry);
        for leaked in [
            ann.to_string().as_str(),
            "ann-salary",
            "10.0.0.1",
            "ann@acme.test",
            "contractors off hours",
        ] {
            assert!(!text.contains(leaked), "{leaked} leaked into {text}");
        }
    }

    /// Requests with unknown methods produce an other label without exposing BREW;
    /// the GET method retains its standard label.
    #[test]
    fn an_invented_method_is_counted_as_other() {
        let registry = Registry::new();
        let observer = LocalRequestObserver::register(&registry).unwrap();

        for method in ["BREW", "PROPFIND", ""] {
            let mut observed = allowed();
            observed.method = UntrustedText::record(method);
            observer.observe(&observed);
        }

        let text = scrape(&registry);
        assert!(text.contains("method=\"other\""), "{text}");
        assert!(!text.contains("BREW"), "{text}");
        assert_eq!(method_label("GET"), "GET");
    }

    /// A request that resolved no tenant and matched no route still counts,
    /// under `none` for both.
    #[test]
    fn a_request_that_matched_nothing_is_still_counted() {
        let registry = Registry::new();
        let observer = LocalRequestObserver::register(&registry).unwrap();

        observer.observe(&request_observation(RequestOutcome::Allowed {
            upstream_status: 404,
        }));

        let text = scrape(&registry);
        assert!(text.contains("tenant=\"none\""), "{text}");
        assert!(text.contains("route=\"none\""), "{text}");
    }

    /// A request without a decision is labelled undecided with a server-error status class.
    #[test]
    fn an_undecided_request_is_counted_as_a_server_error() {
        let registry = Registry::new();
        let observer = LocalRequestObserver::register(&registry).unwrap();
        let mut observed = allowed();
        observed.outcome = RequestOutcome::Undecided;

        observer.observe(&observed);

        let text = scrape(&registry);
        assert!(text.contains("outcome=\"undecided\""), "{text}");
        assert!(text.contains("status_class=\"5xx\""), "{text}");
    }

    /// Requests beyond the series cap use the overflow route label while every request is counted.
    #[test]
    fn label_combinations_past_the_cap_fold_into_overflow() {
        let registry = Registry::new();
        let observer = LocalRequestObserver::register(&registry).unwrap();
        let served = MAX_SERIES + 50;

        for _ in 0..served {
            observer.observe(&allowed());
        }

        assert!(observer.has_overflowed());
        assert!(scrape(&registry).contains("route=\"overflow\""));
        assert_eq!(requests_counted(&registry), served as u64);
    }

    /// Registering a second request observer in the same registry returns an infrastructure error.
    #[test]
    fn a_second_observer_in_one_registry_is_refused() {
        let registry = Registry::new();
        LocalRequestObserver::register(&registry).unwrap();

        let second = LocalRequestObserver::register(&registry);

        assert!(matches!(second, Err(DomainError::Infrastructure(_))));
    }
}
