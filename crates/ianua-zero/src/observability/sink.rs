//! Finished requests sent to the deployment's own log collector, the one
//! `LOG_SINK_URL` names, as JSON batches.
//!
//! The collector is the operator's, set at start, so it may sit inside the
//! deployment's network; a tenant's log stores go through the shipping use
//! case instead, screened for the public internet. Queued and batched like
//! the request records: a collector that is slow or gone costs records in
//! the collector, never a request's time. Each batch carries the header the
//! settings give, which is never logged.

use std::sync::Arc;
use std::time::Duration;

use http::header::CONTENT_TYPE;
use http::{HeaderName, HeaderValue, Method, Request, Uri};
use http_body_util::Full;
use hyper::body::Bytes;
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use ianua_app::ports::runtime::{DroppedRecords, RequestObserver};
use ianua_boot::shutdown::Shutdown;
use ianua_domain::domains::proxy::observation::{
    DecidingStage, ObservedPrincipal, RequestObservation, RouteMatch,
};
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::Fact;
use serde_json::{Value, json};
use time::format_description::well_known::Rfc3339;

use crate::observability::batching::{BatchLimits, Batched, Deliver, Queueing};

/// The longest one batch may take to reach the collector.
const SEND_TIMEOUT: Duration = Duration::from_secs(10);

/// Where batches go and the header they carry.
#[derive(Clone)]
pub(crate) struct LogSink {
    /// The collector's address.
    pub endpoint: Uri,
    /// The header the collector authenticates the gateway by, when it asks
    /// for one.
    pub header: Option<(HeaderName, Secret)>,
}

impl std::fmt::Debug for LogSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LogSink")
            .field("endpoint", &self.endpoint)
            .finish_non_exhaustive()
    }
}

/// Sends every finished request to the deployment's collector.
pub(crate) struct SinkLog {
    queue: Batched<Value>,
}

impl SinkLog {
    /// Starts sending to `sink` until `shutdown` stops, counting what the
    /// queue drops into `dropped`.
    #[must_use]
    pub(crate) fn start(
        sink: LogSink,
        dropped: Arc<dyn DroppedRecords>,
        shutdown: &Shutdown,
    ) -> Self {
        let collector = Collector {
            client: Client::builder(TokioExecutor::new()).build(connector()),
            sink,
        };
        let queueing = Queueing::new(BatchLimits::DEFAULT, dropped);
        Self {
            queue: Batched::start(collector, queueing, shutdown),
        }
    }
}

impl RequestObserver for SinkLog {
    fn observe(&self, observation: &RequestObservation) {
        self.queue.record(line_of(observation));
    }
}

/// A connector reaching the collector over TLS, or plain HTTP when its
/// address says so, as one beside the gateway often is.
fn connector() -> HttpsConnector<HttpConnector> {
    hyper_rustls::HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_or_http()
        .enable_http1()
        .build()
}

/// The collector a batch is posted to.
struct Collector {
    client: Client<HttpsConnector<HttpConnector>, Full<Bytes>>,
    sink: LogSink,
}

impl Collector {
    /// The request carrying `body`, with the collector's header.
    fn request(&self, body: Vec<u8>) -> Request<Full<Bytes>> {
        let mut request = Request::new(Full::new(Bytes::from(body)));
        *request.method_mut() = Method::POST;
        *request.uri_mut() = self.sink.endpoint.clone();
        let headers = request.headers_mut();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        let Some((name, value)) = &self.sink.header else {
            return request;
        };
        if let Ok(mut value) = HeaderValue::from_str(value.expose()) {
            value.set_sensitive(true);
            headers.insert(name.clone(), value);
        }
        request
    }
}

impl Deliver<Value> for Collector {
    async fn deliver(&self, batch: Vec<Value>) {
        let records = batch.len();
        let body = Value::Array(batch).to_string().into_bytes();
        let sent = tokio::time::timeout(SEND_TIMEOUT, self.client.request(self.request(body)));
        match sent.await {
            Ok(Ok(answer)) if answer.status().is_success() => {}
            Ok(Ok(answer)) => {
                let status = answer.status().as_u16();
                tracing::warn!(records, status, "the log collector refused records");
            }
            Ok(Err(error)) => {
                tracing::warn!(records, %error, "the log collector cannot be reached")
            }
            Err(_) => tracing::warn!(records, "the log collector did not answer in time"),
        }
    }

    fn name(&self) -> &'static str {
        "log collector"
    }
}

/// One finished request as the collector reads it: who, what, the
/// decision and why, never a token, cookie, header or body.
fn line_of(observation: &RequestObservation) -> Value {
    let tenant = match observation.tenant_id {
        Fact::Known(tenant) => Value::from(tenant.to_string()),
        Fact::Unknown => Value::Null,
    };
    let (route, service) = route_fields(&observation.route);
    json!({
        "correlation_id": observation.correlation_id.to_string(),
        "tenant_id": tenant,
        "route_id": route,
        "service_id": service,
        "method": observation.method.as_str(),
        "path": observation.path.as_str(),
        "client": observation.client.to_string(),
        "caller": caller_of(&observation.principal),
        "status": observation.status(),
        "allowed": observation.is_allowed(),
        "reason": observation.denial_reason(),
        "decided_by": observation.decided_by().map(DecidingStage::name),
        "latency_ms": i64::try_from(observation.latency.whole_milliseconds()).unwrap_or(i64::MAX),
        "occurred_at": observation.occurred_at.format(&Rfc3339).ok(),
    })
}

/// Names both matched resources, leaving both collector fields null for unmatched traffic.
fn route_fields(route: &RouteMatch) -> (Value, Value) {
    match route {
        RouteMatch::Matched {
            route_id,
            service_id,
        } => (
            Value::from(route_id.to_string()),
            Value::from(service_id.to_string()),
        ),
        RouteMatch::NoRoute => (Value::Null, Value::Null),
    }
}

/// The kind of caller a record names.
fn caller_of(principal: &ObservedPrincipal) -> &'static str {
    match principal {
        ObservedPrincipal::Anonymous => "anonymous",
        ObservedPrincipal::User(_) => "user",
        ObservedPrincipal::Agent { .. } => "agent",
        ObservedPrincipal::Consumer { .. } => "consumer",
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::test_support::request_observation;
    use ianua_domain::domains::proxy::observation::RequestOutcome;

    use super::*;

    /// A finished request's line names its decision and nothing it carried.
    #[test]
    fn a_line_names_the_decision_and_nothing_carried() {
        let observation = request_observation(RequestOutcome::Allowed {
            upstream_status: 204,
        });

        let line = line_of(&observation);

        assert_eq!(line["status"], 204);
        assert_eq!(line["allowed"], true);
        assert!(line.get("headers").is_none());
    }
}
