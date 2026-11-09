//! Fakes for running the service: a readiness probe that answers what it
//! is told, a metrics exporter that writes out fixed text or fails, and an
//! observer recording the API requests it hears about.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::shared::errors::DomainError;

use crate::ports::runtime::{
    MetricsExporter, MetricsText, Readiness, ReadinessProbe, ServedRequest, ServedRequestObserver,
    ServedRoute, UnreadyReason,
};
use crate::test_support::Fake;

/// A readiness probe answering the same every time.
pub struct FakeReadinessProbe {
    answer: Readiness,
}

impl FakeReadinessProbe {
    /// A dependency that answers as it should.
    #[must_use]
    pub fn ready() -> Self {
        Self {
            answer: Readiness::Ready,
        }
    }

    /// A dependency that does not answer, for `reason`.
    #[must_use]
    pub fn not_ready(reason: &str) -> Self {
        Self {
            answer: Readiness::NotReady(UnreadyReason::new(reason)),
        }
    }
}

#[async_trait]
impl ReadinessProbe for FakeReadinessProbe {
    async fn check(&self) -> Readiness {
        self.answer.clone()
    }
}

impl Fake for Arc<dyn ReadinessProbe> {
    fn fake() -> Self {
        Arc::new(FakeReadinessProbe::ready())
    }
}

/// The text [`FakeMetricsExporter::writing`] writes out by default: one
/// counter, as a Prometheus registry writes it.
pub const METRICS_TEXT: &str = "# TYPE ianua_requests_total counter\nianua_requests_total 3\n";

/// A metrics exporter writing out fixed text, or failing.
pub struct FakeMetricsExporter {
    text: Option<String>,
}

impl FakeMetricsExporter {
    /// An exporter writing out `text`.
    #[must_use]
    pub fn writing(text: &str) -> Self {
        Self {
            text: Some(text.to_owned()),
        }
    }

    /// An exporter whose registry cannot be written out.
    #[must_use]
    pub fn failing() -> Self {
        Self { text: None }
    }
}

impl MetricsExporter for FakeMetricsExporter {
    fn render(&self) -> Result<MetricsText, DomainError> {
        self.text
            .as_deref()
            .map(MetricsText::new)
            .ok_or_else(|| DomainError::infra_msg("the registry cannot be written out"))
    }
}

impl Fake for Arc<dyn MetricsExporter> {
    fn fake() -> Self {
        Arc::new(FakeMetricsExporter::writing(METRICS_TEXT))
    }
}

/// One request a [`RecordingServedRequests`] heard about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeardRequest {
    /// The route's template, or `None` when no route matched.
    pub route: Option<String>,
    /// The method as it arrived.
    pub method: String,
    /// The status it was answered with.
    pub status: u16,
}

/// Records every answered request it is told about.
#[derive(Default)]
pub struct RecordingServedRequests {
    heard: Mutex<Vec<HeardRequest>>,
}

impl RecordingServedRequests {
    /// What it heard so far, in order.
    #[must_use]
    pub fn heard(&self) -> Vec<HeardRequest> {
        self.heard.lock().unwrap().clone()
    }
}

impl ServedRequestObserver for RecordingServedRequests {
    fn observe(&self, served: &ServedRequest<'_>) {
        let route = match served.route {
            ServedRoute::Template(template) => Some(template.to_owned()),
            ServedRoute::Unmatched => None,
        };
        self.heard.lock().unwrap().push(HeardRequest {
            route,
            method: served.method.to_owned(),
            status: served.status,
        });
    }
}

impl Fake for Arc<dyn ServedRequestObserver> {
    fn fake() -> Self {
        Arc::new(RecordingServedRequests::default())
    }
}
