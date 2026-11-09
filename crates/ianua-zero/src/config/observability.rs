//! What the gateway says about the requests it served: the request records
//! written in batches, the spans it exports, and the finished requests it
//! ships to a log collector.
//!
//! None of the addresses may carry a credential: an address is printed with
//! the configuration, so a credential goes in its own secret setting.

use std::fmt;
use std::time::Duration;

use http::{HeaderName, HeaderValue};
use ianua_boot::env::{ConfigError, Env, Read};
use ianua_domain::shared::security::secret::Secret;
use url::Url;

/// How request records are batched on their way to the database.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RecordBatching {
    /// `GATEWAY_REQUEST_RECORD_BUFFER` (10000): records held before new
    /// ones are dropped and counted.
    pub buffer: usize,
    /// `GATEWAY_REQUEST_RECORD_BATCH_SIZE` (256): records written at once.
    pub batch: usize,
    /// `GATEWAY_REQUEST_RECORD_FLUSH_MS` (500): the longest a record waits
    /// to be written.
    pub flush: Duration,
}

/// Where the gateway's spans go.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TraceExport {
    /// `OTLP_ENDPOINT`: an OTLP/HTTP endpoint, such as
    /// `http://collector:4318/v1/traces`.
    pub endpoint: Url,
    /// `OTLP_SERVICE_NAME` (`ianua-zero`): the name the spans are recorded
    /// under.
    pub service_name: String,
}

/// The header a log collector authenticates the gateway by. `Debug` shows
/// its name and never its value.
#[derive(Clone)]
pub(crate) struct SinkHeader {
    /// The header's name.
    pub name: HeaderName,
    /// The header's value, the credential.
    pub value: Secret,
}

impl fmt::Debug for SinkHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SinkHeader")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

/// Where finished requests are shipped.
#[derive(Debug, Clone)]
pub(crate) struct LogShipping {
    /// `LOG_SINK_URL`: the endpoint JSON batches of records are posted to.
    pub endpoint: Url,
    /// `LOG_SINK_AUTH`, as `Name: value`: the header sent with each batch;
    /// none for a collector that takes none.
    pub header: Option<SinkHeader>,
}

/// What the gateway says about the requests it served.
#[derive(Debug, Clone)]
pub(crate) struct ObservabilityConfig {
    /// How request records are batched.
    pub request_records: RecordBatching,
    /// Where spans are exported; none exports none, and the caller's trace
    /// is still joined and passed on.
    pub traces: Option<TraceExport>,
    /// Where finished requests are shipped; none ships none.
    pub log_shipping: Option<LogShipping>,
}

impl ObservabilityConfig {
    /// The observability settings `vars` holds.
    ///
    /// # Errors
    ///
    /// A number out of its range, a batch larger than the buffer, an
    /// address that is no URL or carries a credential, a header that is not
    /// `Name: value`, or a setting for an export or a collector not set.
    pub(crate) fn read(vars: &Env) -> Read<Self> {
        Ok(Self {
            request_records: request_records(vars)?,
            traces: traces(vars)?,
            log_shipping: log_shipping(vars)?,
        })
    }
}

/// How request records are batched, the batch no larger than the buffer.
fn request_records(vars: &Env) -> Read<RecordBatching> {
    let batching = RecordBatching {
        buffer: vars.number_in("GATEWAY_REQUEST_RECORD_BUFFER", 10_000, 1..=1_000_000)?,
        batch: vars.number_in("GATEWAY_REQUEST_RECORD_BATCH_SIZE", 256, 1..=10_000)?,
        flush: vars.millis_in(
            "GATEWAY_REQUEST_RECORD_FLUSH_MS",
            Duration::from_millis(500),
            1..=60_000,
        )?,
    };
    if batching.batch > batching.buffer {
        return Err(ConfigError::contradicts(
            "GATEWAY_REQUEST_RECORD_BATCH_SIZE",
            "is larger than GATEWAY_REQUEST_RECORD_BUFFER, so no batch could ever fill",
        ));
    }
    Ok(batching)
}

/// Where spans go, when `OTLP_ENDPOINT` is set.
fn traces(vars: &Env) -> Read<Option<TraceExport>> {
    let endpoint = vars.url("OTLP_ENDPOINT")?;
    let service_name = vars.optional("OTLP_SERVICE_NAME")?;
    match (endpoint, service_name) {
        (None, Some(_)) => Err(ConfigError::contradicts(
            "OTLP_SERVICE_NAME",
            "is set without OTLP_ENDPOINT",
        )),
        (None, None) => Ok(None),
        (Some(endpoint), service_name) => Ok(Some(TraceExport {
            endpoint,
            service_name: service_name.unwrap_or_else(|| "ianua-zero".to_owned()),
        })),
    }
}

/// Where finished requests are shipped, when `LOG_SINK_URL` is set.
fn log_shipping(vars: &Env) -> Read<Option<LogShipping>> {
    let endpoint = vars.url("LOG_SINK_URL")?;
    let header = sink_header(vars)?;
    match (endpoint, header) {
        (None, Some(_)) => Err(ConfigError::contradicts(
            "LOG_SINK_AUTH",
            "is set without LOG_SINK_URL",
        )),
        (None, None) => Ok(None),
        (Some(endpoint), header) => Ok(Some(LogShipping { endpoint, header })),
    }
}

/// `LOG_SINK_AUTH`, a secret, as a header name and its value. No refusal
/// repeats the value.
fn sink_header(vars: &Env) -> Read<Option<SinkHeader>> {
    let name = "LOG_SINK_AUTH";
    let Some(given) = vars.secret(name)? else {
        return Ok(None);
    };
    let refused = || ConfigError::invalid(name, "must be a header as Name: value");
    let (header, value) = given.expose().split_once(':').ok_or_else(refused)?;
    let header = HeaderName::from_bytes(header.trim().as_bytes()).map_err(|_| refused())?;
    let value = value.trim();
    if value.is_empty() || HeaderValue::from_str(value).is_err() {
        return Err(refused());
    }
    Ok(Some(SinkHeader {
        name: header,
        value: Secret::new(value),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// With nothing set, records are batched as documented and nothing is
    /// exported or shipped.
    #[test]
    fn with_nothing_set_records_are_batched_and_nothing_leaves() {
        let config = ObservabilityConfig::read(&Env::of([])).unwrap();

        assert_eq!(config.request_records.buffer, 10_000);
        assert_eq!(config.request_records.batch, 256);
        assert_eq!(config.request_records.flush, Duration::from_millis(500));
        assert!(config.traces.is_none());
        assert!(config.log_shipping.is_none());
    }

    /// A record batch larger than its buffer is rejected with the batch setting named.
    #[test]
    fn a_batch_larger_than_the_buffer_is_refused() {
        let vars = Env::of([
            ("GATEWAY_REQUEST_RECORD_BUFFER", "100"),
            ("GATEWAY_REQUEST_RECORD_BATCH_SIZE", "200"),
        ]);

        let read = ObservabilityConfig::read(&vars);

        assert!(
            matches!(read, Err(ConfigError::Contradicts { name, .. }) if name == "GATEWAY_REQUEST_RECORD_BATCH_SIZE")
        );
    }

    /// Spans go to the endpoint named, under the gateway's name by default.
    #[test]
    fn spans_go_to_the_endpoint_under_the_gateways_name() {
        let config = ObservabilityConfig::read(&Env::of([(
            "OTLP_ENDPOINT",
            "http://collector:4318/v1/traces",
        )]))
        .unwrap();

        let traces = config.traces.unwrap();
        assert_eq!(traces.service_name, "ianua-zero");
        assert_eq!(traces.endpoint.as_str(), "http://collector:4318/v1/traces");
    }

    /// A service name with no endpoint is refused: nothing would use it.
    #[test]
    fn a_service_name_without_an_endpoint_is_refused() {
        let read = ObservabilityConfig::read(&Env::of([("OTLP_SERVICE_NAME", "edge")]));

        assert!(
            matches!(read, Err(ConfigError::Contradicts { name, .. }) if name == "OTLP_SERVICE_NAME")
        );
    }

    /// Finished requests are shipped with the header given, its value never
    /// printed.
    #[test]
    fn requests_are_shipped_with_the_header_never_printed() {
        let vars = Env::of([
            ("LOG_SINK_URL", "https://logs.example.com/loki/api/v1/push"),
            ("LOG_SINK_AUTH", "Authorization: Bearer s3cret-sink"),
        ]);

        let config = ObservabilityConfig::read(&vars).unwrap();

        let header = config
            .log_shipping
            .as_ref()
            .unwrap()
            .header
            .as_ref()
            .unwrap();
        assert_eq!(header.name.as_str(), "authorization");
        assert_eq!(header.value.expose(), "Bearer s3cret-sink");
        assert!(!format!("{config:?}").contains("s3cret-sink"));
    }

    /// A malformed collector header is rejected with its setting named and
    /// its credential omitted from the error.
    #[test]
    fn a_header_that_is_no_header_is_refused_without_repeating_it() {
        let vars = Env::of([
            ("LOG_SINK_URL", "https://logs.example.com/push"),
            ("LOG_SINK_AUTH", "s3cret-sink"),
        ]);

        let message = ObservabilityConfig::read(&vars).unwrap_err().to_string();

        assert!(message.starts_with("LOG_SINK_AUTH"));
        assert!(!message.contains("s3cret-sink"));
    }

    /// A header with no collector is refused: nothing would send it.
    #[test]
    fn a_header_without_a_collector_is_refused() {
        let read = ObservabilityConfig::read(&Env::of([("LOG_SINK_AUTH", "X-Key: abc")]));

        assert!(
            matches!(read, Err(ConfigError::Contradicts { name, .. }) if name == "LOG_SINK_AUTH")
        );
    }

    /// A collector URL containing a password is rejected without exposing
    /// that password in the error.
    #[test]
    fn an_address_with_a_password_is_refused() {
        let read = ObservabilityConfig::read(&Env::of([(
            "LOG_SINK_URL",
            "https://user:hunter2@logs.example.com/push",
        )]));

        let error = read.unwrap_err();
        assert!(matches!(&error, ConfigError::Invalid { name, .. } if name == "LOG_SINK_URL"));
        assert!(!error.to_string().contains("hunter2"));
    }
}
