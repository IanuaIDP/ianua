//! The gateway's span of each traced request, exported to the operator's
//! trace collector over OTLP/HTTP in its JSON encoding.
//!
//! Only a request the caller is tracing and recording gets a span: the
//! gateway keeps the caller's sampling choice rather than making its own,
//! so an unsampled request takes no room in the queue. A span carries what
//! the request record carries and nothing more: the decision, the check
//! that made it, the route and the status, never a header, a token or the
//! query string.

use std::sync::Arc;
use std::time::Duration;

use http::header::CONTENT_TYPE;
use http::{HeaderValue, Method, Request, Uri};
use http_body_util::Full;
use hyper::body::Bytes;
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use ianua_app::ports::runtime::{DroppedRecords, RequestObserver};
use ianua_boot::shutdown::Shutdown;
use ianua_domain::domains::proxy::observation::{
    DecidingRule, RequestObservation, RequestOutcome, RouteMatch, Traced,
};
use ianua_domain::domains::proxy::request::trace::TraceContext;
use serde::Serialize;

use crate::observability::batching::{BatchLimits, Batched, Deliver, Queueing};

/// The longest one export may take, connecting included.
const EXPORT_TIMEOUT: Duration = Duration::from_secs(10);

/// The instrumentation scope the spans are made in: the gateway's own
/// code, whatever service name the deployment reports them under.
const SCOPE_NAME: &str = "ianua-zero";

/// The name of every span: one per request, named for what it is rather
/// than for anything the client sent.
const SPAN_NAME: &str = "gateway request";

/// A span the gateway served a request in: `SPAN_KIND_SERVER`.
const SERVER: u8 = 2;

/// A span that ended well, or that nothing says otherwise of:
/// `STATUS_CODE_UNSET`.
const UNSET: u8 = 0;

/// A span that ended in a server error: `STATUS_CODE_ERROR`.
const ERROR: u8 = 2;

/// Exports the gateway's span of each sampled request.
pub(crate) struct TraceExport {
    queue: Batched<Span>,
}

impl TraceExport {
    /// Starts exporting to the collector `collector` names until `shutdown`
    /// stops, counting what the queue drops into `dropped`.
    #[must_use]
    pub(crate) fn start(
        collector: TraceCollector,
        dropped: Arc<dyn DroppedRecords>,
        shutdown: &Shutdown,
    ) -> Self {
        let collector = Collector {
            client: Client::builder(TokioExecutor::new()).build(connector()),
            endpoint: collector.endpoint,
            service: collector.service,
        };
        let queueing = Queueing::new(BatchLimits::DEFAULT, dropped);
        Self {
            queue: Batched::start(collector, queueing, shutdown),
        }
    }
}

impl RequestObserver for TraceExport {
    fn observe(&self, observation: &RequestObservation) {
        let Some(span) = Span::of(observation) else {
            return;
        };
        self.queue.record(span);
    }
}

/// A connector reaching the collector over TLS, or plain HTTP when the
/// endpoint says so, as a collector beside the gateway often is.
fn connector() -> HttpsConnector<HttpConnector> {
    hyper_rustls::HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_or_http()
        .enable_http1()
        .build()
}

/// Where spans are exported and the service they are reported as.
#[derive(Debug, Clone)]
pub(crate) struct TraceCollector {
    /// The collector's traces endpoint, such as
    /// `https://collector:4318/v1/traces`.
    pub endpoint: Uri,
    /// The service the spans are reported as.
    pub service: String,
}

/// The trace collector a batch of spans is posted to.
struct Collector {
    client: Client<HttpsConnector<HttpConnector>, Full<Bytes>>,
    endpoint: Uri,
    service: String,
}

impl Collector {
    /// The export request carrying `body`.
    fn request(&self, body: Vec<u8>) -> Request<Full<Bytes>> {
        let mut request = Request::new(Full::new(Bytes::from(body)));
        *request.method_mut() = Method::POST;
        *request.uri_mut() = self.endpoint.clone();
        request
            .headers_mut()
            .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        request
    }
}

impl Deliver<Span> for Collector {
    async fn deliver(&self, batch: Vec<Span>) {
        let spans = batch.len();
        let body = match serde_json::to_vec(&Export::of(batch, &self.service)) {
            Ok(body) => body,
            Err(error) => {
                tracing::warn!(spans, %error, "spans not written out");
                return;
            }
        };
        let sent = tokio::time::timeout(EXPORT_TIMEOUT, self.client.request(self.request(body)));
        match sent.await {
            Ok(Ok(answer)) if answer.status().is_success() => {}
            Ok(Ok(answer)) => {
                let status = answer.status().as_u16();
                tracing::warn!(spans, status, "the collector refused spans");
            }
            Ok(Err(error)) => tracing::warn!(spans, %error, "the collector cannot be reached"),
            Err(_) => tracing::warn!(spans, "the collector did not answer in time"),
        }
    }

    fn name(&self) -> &'static str {
        "trace collector"
    }
}

/// One OTLP traces export: every span under the gateway's resource.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Export {
    resource_spans: [ResourceSpans; 1],
}

impl Export {
    /// The export of `spans`, reported as `service`.
    fn of(spans: Vec<Span>, service: &str) -> Self {
        Self {
            resource_spans: [ResourceSpans {
                resource: Resource {
                    attributes: vec![Attribute::text("service.name", service.to_owned())],
                },
                scope_spans: [ScopeSpans {
                    scope: Scope { name: SCOPE_NAME },
                    spans,
                }],
            }],
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ResourceSpans {
    resource: Resource,
    scope_spans: [ScopeSpans; 1],
}

#[derive(Serialize)]
struct Resource {
    attributes: Vec<Attribute>,
}

#[derive(Serialize)]
struct ScopeSpans {
    scope: Scope,
    spans: Vec<Span>,
}

#[derive(Serialize)]
struct Scope {
    name: &'static str,
}

/// The gateway's span of one request.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Span {
    trace_id: String,
    span_id: String,
    name: &'static str,
    kind: u8,
    start_time_unix_nano: String,
    end_time_unix_nano: String,
    attributes: Vec<Attribute>,
    status: SpanStatus,
}

#[derive(Debug, Serialize)]
struct SpanStatus {
    code: u8,
}

impl Span {
    /// The span of `observation`, or `None` when the request was in no
    /// trace or in one the caller is not recording.
    fn of(observation: &RequestObservation) -> Option<Self> {
        let Traced::In(context) = observation.trace else {
            return None;
        };
        if !context.is_sampled() {
            return None;
        }
        Some(Self::in_trace(&context, observation))
    }

    /// The span of `observation`, under `context`.
    fn in_trace(context: &TraceContext, observation: &RequestObservation) -> Self {
        let ended = observation.occurred_at.unix_timestamp_nanos();
        let started = ended - observation.latency.whole_nanoseconds();
        Self {
            trace_id: context.trace_id().to_string(),
            span_id: context.span_id().to_string(),
            name: SPAN_NAME,
            kind: SERVER,
            start_time_unix_nano: started.to_string(),
            end_time_unix_nano: ended.to_string(),
            attributes: attributes_of(observation),
            status: SpanStatus {
                code: status_code(observation.status()),
            },
        }
    }
}

/// What a span says of `observation`.
fn attributes_of(observation: &RequestObservation) -> Vec<Attribute> {
    let mut attributes = request_attributes(observation);
    if let Some(tenant) = observation.tenant_id.known() {
        attributes.push(Attribute::text("ianua.tenant_id", tenant.to_string()));
    }
    if let RouteMatch::Matched { route_id, .. } = observation.route {
        attributes.push(Attribute::text("ianua.route_id", route_id.to_string()));
    }
    if let Some(decided_by) = observation.decided_by() {
        attributes.push(Attribute::text(
            "ianua.decided_by",
            decided_by.name().to_owned(),
        ));
    }
    if let DecidingRule::Named(rule) = observation.deciding_rule() {
        attributes.push(Attribute::text("ianua.rule", rule.as_str().to_owned()));
    }
    attributes
}

/// The HTTP and correlation fields present even when no tenant or rule matched.
fn request_attributes(observation: &RequestObservation) -> Vec<Attribute> {
    vec![
        Attribute::text(
            "ianua.correlation_id",
            observation.correlation_id.to_string(),
        ),
        Attribute::text(
            "http.request.method",
            observation.method.as_str().to_owned(),
        ),
        Attribute::text("url.path", observation.path.as_str().to_owned()),
        Attribute::number("http.response.status_code", observation.status()),
        Attribute::text(
            "ianua.decision",
            decision_of(&observation.outcome).to_owned(),
        ),
    ]
}

/// What was decided, as one word.
fn decision_of(outcome: &RequestOutcome) -> &'static str {
    match outcome {
        RequestOutcome::Allowed { .. } => "allowed",
        RequestOutcome::Denied { .. } => "denied",
        RequestOutcome::Undecided => "undecided",
    }
}

/// The span status a server span takes for `status`: an error only for a
/// server error, since a refusal is the gateway working as it should.
fn status_code(status: u16) -> u8 {
    match status {
        500.. => ERROR,
        _ => UNSET,
    }
}

/// One key and value of an OTLP attribute list.
#[derive(Debug, Serialize)]
struct Attribute {
    key: &'static str,
    value: AnyValue,
}

impl Attribute {
    fn text(key: &'static str, value: String) -> Self {
        Self {
            key,
            value: AnyValue::StringValue(value),
        }
    }

    /// An integer attribute; OTLP's JSON writes 64-bit integers as strings.
    fn number(key: &'static str, value: u16) -> Self {
        Self {
            key,
            value: AnyValue::IntValue(value.to_string()),
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
enum AnyValue {
    StringValue(String),
    IntValue(String),
}

#[cfg(test)]
mod tests {
    use ianua_app::test_support::request_observation;
    use ianua_domain::domains::proxy::request::trace::{Sampling, SpanId, TraceId};
    use serde_json::{Value, json};

    use super::*;

    fn traced(sampling: Sampling) -> RequestObservation {
        let context = TraceContext::new(
            TraceId::parse("4bf92f3577b34da6a3ce929d0e0e4736").unwrap(),
            SpanId::parse("00f067aa0ba902b7").unwrap(),
            sampling,
        );
        RequestObservation {
            trace: Traced::In(context),
            ..request_observation(RequestOutcome::Allowed {
                upstream_status: 200,
            })
        }
    }

    /// A sampled request is one server span in the caller's trace, with the
    /// gateway's span id and the status the client saw.
    #[test]
    fn a_sampled_request_is_one_span_of_its_trace() {
        let span = Span::of(&traced(Sampling::Sampled)).unwrap();

        let sent: Value = serde_json::to_value(Export::of(vec![span], "edge-eu")).unwrap();
        let resource = &sent["resourceSpans"][0]["resource"]["attributes"];
        let service = json!({"key": "service.name", "value": {"stringValue": "edge-eu"}});
        assert!(resource.as_array().unwrap().contains(&service));
        let span = &sent["resourceSpans"][0]["scopeSpans"][0]["spans"][0];
        assert_eq!(span["traceId"], json!("4bf92f3577b34da6a3ce929d0e0e4736"));
        assert_eq!(span["spanId"], json!("00f067aa0ba902b7"));
        assert_eq!(span["kind"], json!(2));
        let status = json!({"key": "http.response.status_code", "value": {"intValue": "200"}});
        assert!(span["attributes"].as_array().unwrap().contains(&status));
    }

    /// Span creation returns none for both a request marked unsampled and
    /// a request without trace context.
    #[test]
    fn an_unsampled_or_untraced_request_makes_no_span() {
        let untraced = request_observation(RequestOutcome::Undecided);

        assert!(Span::of(&traced(Sampling::NotSampled)).is_none());
        assert!(Span::of(&untraced).is_none());
    }

    /// A refusal is the gateway working; only a server error marks the span
    /// as failed.
    #[test]
    fn only_a_server_error_marks_the_span_as_failed() {
        assert_eq!(status_code(403), UNSET);
        assert_eq!(status_code(200), UNSET);
        assert_eq!(status_code(503), ERROR);
    }
}
