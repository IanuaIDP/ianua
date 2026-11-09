//! The API's answered requests counted into the process's own metrics
//! registry, for the scrape the API's `/metrics` serves through
//! [`LocalMetricsExporter`](crate::runtime::LocalMetricsExporter).
//!
//! Two metrics:
//!
//! - `ianua_api_requests_total`, by route template, method and status
//!   class;
//! - `ianua_api_request_duration_seconds`, a latency histogram by route
//!   template and method.
//!
//! The route is its template as the router declares it, so the number of
//! routes is set by the code, not by what clients send; a request no route
//! matched is `unmatched`. Methods and statuses are narrowed as the proxy's
//! are, through the shared `runtime/series.rs`, and the combinations are
//! capped the same way.

use ianua_app::ports::runtime::{ServedRequest, ServedRequestObserver, ServedRoute};
use ianua_domain::domains::proxy::observation::status_class;
use ianua_domain::shared::errors::DomainError;
use prometheus::{HistogramVec, IntCounterVec, Registry};

use crate::runtime::series::{
    Admitted, OTHER_METHOD, OVERFLOW, SeriesCap, counter, histogram, method_label, register,
};

/// How many route, method and status combinations are tracked. The API
/// declares a few hundred routes; past this, something is wrong.
const MAX_SERIES: usize = 4_000;

/// The route label of a request no route matched.
const UNMATCHED: &str = "unmatched";

/// One combination of labels an answered request is counted under.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Series {
    route: String,
    method: &'static str,
    status_class: &'static str,
}

impl Series {
    /// The labels `served` would be counted under, before the cap.
    fn of(served: &ServedRequest<'_>) -> Self {
        let route = match served.route {
            ServedRoute::Template(template) => template.to_owned(),
            ServedRoute::Unmatched => UNMATCHED.to_owned(),
        };
        Self {
            route,
            method: method_label(served.method),
            status_class: status_class(served.status),
        }
    }

    /// The same request, counted under the overflow series.
    fn folded(self) -> Self {
        Self {
            route: OVERFLOW.to_owned(),
            method: OTHER_METHOD,
            ..self
        }
    }
}

/// Counts every request the API answered into a Prometheus registry.
pub struct LocalServedRequestObserver {
    requests: IntCounterVec,
    latency: HistogramVec,
    series: SeriesCap<Series>,
}

impl LocalServedRequestObserver {
    /// An observer whose metrics are registered in `registry`, the one the
    /// API's metrics exporter reads.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when `registry` already holds a
    /// metric of one of these names.
    pub fn register(registry: &Registry) -> Result<Self, DomainError> {
        let observer = Self {
            requests: counter(
                "ianua_api_requests_total",
                "Requests the API answered, by route template, method and status class.",
                &["route", "method", "status_class"],
            )?,
            latency: histogram(
                "ianua_api_request_duration_seconds",
                "How long the API took to answer a request.",
                &["route", "method"],
            )?,
            series: SeriesCap::new("ianua_api_requests_total", MAX_SERIES),
        };
        register(
            registry,
            vec![
                Box::new(observer.requests.clone()),
                Box::new(observer.latency.clone()),
            ],
        )?;
        Ok(observer)
    }

    /// Whether traffic is being folded into the overflow series.
    #[must_use]
    pub fn has_overflowed(&self) -> bool {
        self.series.has_overflowed()
    }

    /// The series `served` is counted under.
    fn series_for(&self, served: &ServedRequest<'_>) -> Series {
        let candidate = Series::of(served);
        match self.series.admit(&candidate) {
            Admitted::Own => candidate,
            Admitted::Folded => candidate.folded(),
        }
    }
}

impl ServedRequestObserver for LocalServedRequestObserver {
    fn observe(&self, served: &ServedRequest<'_>) {
        let series = self.series_for(served);
        if let Ok(counter) = self.requests.get_metric_with_label_values(&[
            &series.route,
            series.method,
            series.status_class,
        ]) {
            counter.inc();
        }
        if let Ok(histogram) = self
            .latency
            .get_metric_with_label_values(&[&series.route, series.method])
        {
            histogram.observe(served.latency.as_secs_f64());
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use ianua_app::ports::runtime::MetricsExporter;
    use prometheus::proto::MetricFamily;

    use super::*;
    use crate::runtime::LocalMetricsExporter;

    const USERS: &str = "/api/v1/tenants/{tenant_id}/users";

    fn served<'a>(route: ServedRoute<'a>, method: &'a str, status: u16) -> ServedRequest<'a> {
        ServedRequest {
            route,
            method,
            status,
            latency: Duration::from_millis(8),
        }
    }

    fn scrape(registry: &Registry) -> String {
        LocalMetricsExporter::new(registry.clone())
            .render()
            .unwrap()
            .into_string()
    }

    fn counted(registry: &Registry) -> u64 {
        registry
            .gather()
            .iter()
            .filter(|family| family.get_name() == "ianua_api_requests_total")
            .flat_map(MetricFamily::get_metric)
            .map(|metric| metric.get_counter().get_value() as u64)
            .sum()
    }

    /// A user listing answered 200 is counted under its route template,
    /// `GET` and `2xx`, with its latency in the histogram.
    #[test]
    fn an_answered_request_is_counted_under_its_template() {
        let registry = Registry::new();
        let observer = LocalServedRequestObserver::register(&registry).unwrap();

        observer.observe(&served(ServedRoute::Template(USERS), "GET", 200));

        let text = scrape(&registry);
        assert!(text.contains(&format!("route=\"{USERS}\"")), "{text}");
        assert!(text.contains("method=\"GET\""), "{text}");
        assert!(text.contains("status_class=\"2xx\""), "{text}");
        assert!(
            text.contains("ianua_api_request_duration_seconds_bucket"),
            "{text}"
        );
    }

    /// A request no route matched is counted as `unmatched`, and an
    /// invented method as `other`.
    #[test]
    fn an_unmatched_route_and_an_invented_method_are_bounded() {
        let registry = Registry::new();
        let observer = LocalServedRequestObserver::register(&registry).unwrap();

        observer.observe(&served(ServedRoute::Unmatched, "BREW", 404));

        let text = scrape(&registry);
        assert!(text.contains("route=\"unmatched\""), "{text}");
        assert!(text.contains("method=\"other\""), "{text}");
        assert!(!text.contains("BREW"), "{text}");
    }

    /// Route templates beyond the cap use the overflow label while every request is counted.
    #[test]
    fn templates_past_the_cap_fold_into_overflow() {
        let registry = Registry::new();
        let observer = LocalServedRequestObserver::register(&registry).unwrap();
        let templates: Vec<String> = (0..MAX_SERIES + 20)
            .map(|n| format!("/api/v1/generated/{n}"))
            .collect();

        for template in &templates {
            observer.observe(&served(ServedRoute::Template(template), "GET", 200));
        }

        assert!(observer.has_overflowed());
        assert!(scrape(&registry).contains("route=\"overflow\""));
        assert_eq!(counted(&registry), templates.len() as u64);
    }

    /// The API's metrics and the proxy's live side by side in one registry,
    /// under names of their own.
    #[test]
    fn the_api_and_the_proxy_share_one_registry() {
        let registry = Registry::new();

        let api = LocalServedRequestObserver::register(&registry);
        let proxy = crate::runtime::LocalRequestObserver::register(&registry);

        assert!(api.is_ok());
        assert!(proxy.is_ok());
    }

    /// Registering an API request observer twice returns an infrastructure error.
    #[test]
    fn a_second_observer_in_one_registry_is_refused() {
        let registry = Registry::new();
        LocalServedRequestObserver::register(&registry).unwrap();

        let second = LocalServedRequestObserver::register(&registry);

        assert!(matches!(second, Err(DomainError::Infrastructure(_))));
    }
}
