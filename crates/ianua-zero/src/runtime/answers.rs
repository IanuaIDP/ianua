//! What the internal listener answers: whether the process lives, whether
//! it may take traffic, and its metrics.

use std::time::Duration;

use http::header::CONTENT_TYPE;
use http::{HeaderValue, Method, Request, Response, StatusCode};
use http_body_util::Full;
use hyper::body::Bytes;
use ianua_app::use_case::Query as _;
use ianua_app::use_cases::runtime::{
    CheckReadinessUseCase, ExportMetricsPorts, ExportMetricsUseCase, ServiceReadiness,
};
use ianua_boot::shutdown::Shutdown;

use crate::runtime::RuntimePorts;
use crate::runtime::tables::TablesLoaded;

/// Where an orchestrator asks whether the process runs.
const LIVE_PATH: &str = "/health/live";

/// Where an orchestrator asks whether the process may take traffic.
const READY_PATH: &str = "/health/ready";

/// Where the scraper reads the metrics.
const METRICS_PATH: &str = "/metrics";

/// The longest the readiness check may take; past it the process is not
/// ready. Each probe bounds its own wait below this.
const READINESS_TIMEOUT: Duration = Duration::from_secs(3);

/// The content type of the plain answers.
const PLAIN: &str = "text/plain; charset=utf-8";

/// The content type a Prometheus scraper reads the format version from.
const PROMETHEUS: &str = "text/plain; version=0.0.4";

/// Answers the internal listener's three paths.
pub(super) struct Runtime {
    readiness: CheckReadinessUseCase,
    metrics: ExportMetricsUseCase,
    tables: TablesLoaded,
    shutdown: Shutdown,
}

impl Runtime {
    /// Answers through `ports`, not ready once `shutdown` stops.
    pub(super) fn new(ports: RuntimePorts, shutdown: Shutdown) -> Self {
        Self {
            readiness: CheckReadinessUseCase::new(ports.readiness),
            metrics: ExportMetricsUseCase::new(ExportMetricsPorts {
                exporter: ports.exporter,
            }),
            tables: ports.tables,
            shutdown,
        }
    }

    /// The answer to `request`. Generic over the body, which it never reads.
    pub(super) async fn answer<B>(&self, request: &Request<B>) -> Response<Full<Bytes>> {
        if !matches!(*request.method(), Method::GET | Method::HEAD) {
            return plain(StatusCode::METHOD_NOT_ALLOWED, "");
        }
        match request.uri().path() {
            LIVE_PATH => plain(StatusCode::OK, "ok"),
            READY_PATH => self.ready().await,
            METRICS_PATH => self.scrape().await,
            _ => plain(StatusCode::NOT_FOUND, ""),
        }
    }

    /// `200` when the process may take traffic, `503` otherwise, with no
    /// body either way: why is in the operator's logs, never the answer.
    async fn ready(&self) -> Response<Full<Bytes>> {
        match self.readiness().await {
            ServiceReadiness::Ready => plain(StatusCode::OK, ""),
            ServiceReadiness::NotReady => plain(StatusCode::SERVICE_UNAVAILABLE, ""),
        }
    }

    /// Whether the process may take traffic: not while it stops, not before
    /// its tables are loaded, and only when the database, the bus and the
    /// cache each answer in time.
    async fn readiness(&self) -> ServiceReadiness {
        if self.shutdown.is_stopping() {
            return ServiceReadiness::NotReady;
        }
        if !self.tables.is_loaded() {
            tracing::debug!("not ready: the tables are not loaded yet");
            return ServiceReadiness::NotReady;
        }
        tokio::time::timeout(READINESS_TIMEOUT, self.readiness.execute(&(), ()))
            .await
            .unwrap_or(ServiceReadiness::NotReady)
    }

    /// The metrics in the Prometheus text format, or `500` when they cannot
    /// be written out: an empty scrape would read as a quiet process.
    async fn scrape(&self) -> Response<Full<Bytes>> {
        match self.metrics.execute(&(), ()).await {
            Ok(text) => with_type(StatusCode::OK, text.into_string(), PROMETHEUS),
            Err(error) => {
                tracing::warn!(%error, "the metrics could not be written out");
                plain(StatusCode::INTERNAL_SERVER_ERROR, "")
            }
        }
    }
}

/// A plain-text answer.
fn plain(status: StatusCode, body: &'static str) -> Response<Full<Bytes>> {
    with_type(status, body.to_owned(), PLAIN)
}

/// An answer of `status` carrying `body` as `content_type`.
fn with_type(
    status: StatusCode,
    body: String,
    content_type: &'static str,
) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(Bytes::from(body)));
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static(content_type));
    response
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use http_body_util::BodyExt as _;
    use ianua_app::test_support::{FakeMetricsExporter, FakeReadinessProbe, METRICS_TEXT};
    use ianua_app::use_cases::runtime::CheckReadinessPorts;

    use super::*;

    fn ports(readiness: CheckReadinessPorts, tables: &TablesLoaded) -> RuntimePorts {
        RuntimePorts {
            readiness,
            exporter: Arc::new(FakeMetricsExporter::writing(METRICS_TEXT)),
            tables: tables.clone(),
        }
    }

    fn runtime(readiness: CheckReadinessPorts, tables: &TablesLoaded) -> Runtime {
        Runtime::new(
            ports(readiness, tables),
            Shutdown::new(Duration::from_secs(1)),
        )
    }

    fn get(path: &str) -> Request<()> {
        Request::get(path).body(()).unwrap()
    }

    fn loaded() -> TablesLoaded {
        let tables = TablesLoaded::not_yet();
        tables.mark_loaded();
        tables
    }

    async fn body_of(response: Response<Full<Bytes>>) -> String {
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    /// Readiness changes from 503 to 200 when the gateway's tables are marked loaded.
    #[tokio::test]
    async fn not_ready_until_the_tables_are_loaded() {
        let tables = TablesLoaded::not_yet();
        let runtime = runtime(CheckReadinessPorts::fakes(), &tables);

        let before = runtime.answer(&get(READY_PATH)).await.status();
        tables.mark_loaded();
        let after = runtime.answer(&get(READY_PATH)).await.status();

        assert_eq!(before, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(after, StatusCode::OK);
    }

    /// A failed database readiness probe produces 503 with an empty response body.
    #[tokio::test]
    async fn not_ready_when_the_database_does_not_answer() {
        let runtime = runtime(
            CheckReadinessPorts {
                database: Arc::new(FakeReadinessProbe::not_ready("connection refused")),
                ..CheckReadinessPorts::fakes()
            },
            &loaded(),
        );

        let response = runtime.answer(&get(READY_PATH)).await;

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body_of(response).await, "");
    }

    /// A shutdown request changes readiness to 503 even with loaded tables and healthy probes.
    #[tokio::test]
    async fn not_ready_once_stopping() {
        let shutdown = Shutdown::new(Duration::from_secs(1));
        let runtime = Runtime::new(
            ports(CheckReadinessPorts::fakes(), &loaded()),
            shutdown.clone(),
        );

        shutdown.stop();

        let status = runtime.answer(&get(READY_PATH)).await.status();
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    }

    /// The process lives whatever its dependencies say: the cache is down
    /// and the tables are not loaded, and it still answers it lives.
    #[tokio::test]
    async fn alive_whatever_the_dependencies_say() {
        let runtime = runtime(
            CheckReadinessPorts {
                cache: Arc::new(FakeReadinessProbe::not_ready("ping timed out")),
                ..CheckReadinessPorts::fakes()
            },
            &TablesLoaded::not_yet(),
        );

        let response = runtime.answer(&get(LIVE_PATH)).await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(body_of(response).await, "ok");
    }

    /// The scraper reads the registry's text, with the content type it
    /// takes the format version from.
    #[tokio::test]
    async fn a_scrape_answers_the_metrics() {
        let runtime = runtime(CheckReadinessPorts::fakes(), &loaded());

        let response = runtime.answer(&get(METRICS_PATH)).await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[CONTENT_TYPE], PROMETHEUS);
        assert_eq!(body_of(response).await, METRICS_TEXT);
    }

    /// The listener proxies nothing: every other path is not found, and
    /// anything but a read is not allowed.
    #[tokio::test]
    async fn every_other_path_and_method_is_refused() {
        let runtime = runtime(CheckReadinessPorts::fakes(), &loaded());
        let post = Request::post(METRICS_PATH).body(()).unwrap();

        let unknown = runtime.answer(&get("/admin")).await.status();
        let posted = runtime.answer(&post).await.status();

        assert_eq!(unknown, StatusCode::NOT_FOUND);
        assert_eq!(posted, StatusCode::METHOD_NOT_ALLOWED);
    }
}
