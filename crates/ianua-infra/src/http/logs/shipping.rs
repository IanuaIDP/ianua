//! Shipping a tenant's request records to its log destination: a
//! collector that takes batches by `POST`, an S3-compatible bucket, or
//! Datadog's log intake.
//!
//! A collector and a bucket are addresses the tenant chose, so they are
//! called through the screened client, the address checked first and every
//! name screened as it resolves. Datadog's intake is a host the platform
//! picks from the account's site, so it goes through the fixed client. The
//! credential is opened by the use case for this send alone; it goes into
//! one header and nowhere else, never into a log line or an error, and a
//! destination's answer is never read back.

mod bucket;
mod lines;
mod otlp;

use std::fmt;
use std::time::Duration;

use async_trait::async_trait;
use ianua_app::ports::proxy::{LogShipper, Shipment};
use ianua_domain::domains::audit::streaming::DatadogSite;
use ianua_domain::domains::proxy::log_shipping::{
    BucketName, BucketRegion, LogDestination, LogFormat,
};
use ianua_domain::domains::proxy::observation::RequestObservation;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::shared::security::ssrf::UpstreamNetworks;
use serde::Serialize;

use crate::http::calls::{reachable, succeeded};
use crate::http::client::{fixed, screened};
use crate::http::logs::shipping::bucket::{Upload, access_key, object_url, signed_headers};
use crate::http::logs::shipping::lines::{RecordLine, json_lines};

/// The source Datadog files the records under.
const DATADOG_SOURCE: &str = "ianua";

/// The service Datadog files the records under.
const DATADOG_SERVICE: &str = "ianua-gateway";

/// Sends batches of request records to a tenant's log destination.
pub struct HttpLogShipper {
    screened: reqwest::Client,
    fixed: reqwest::Client,
    networks: UpstreamNetworks,
}

impl fmt::Debug for HttpLogShipper {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpLogShipper")
            .field("networks", &self.networks)
            .finish_non_exhaustive()
    }
}

impl HttpLogShipper {
    /// A shipper whose every send gives up after `timeout`, and which
    /// reaches a tenant's address only when it is public or in `networks`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a client cannot be built.
    pub fn new(networks: UpstreamNetworks, timeout: Duration) -> Result<Self, DomainError> {
        Ok(Self {
            screened: screened(timeout, networks.clone())?,
            fixed: fixed(timeout)?,
            networks,
        })
    }

    /// Posts `batch` to the collector at `url`, the credential as the whole
    /// `Authorization` header when there is one.
    async fn to_collector(&self, url: url::Url, batch: &Batch<'_>) -> Result<(), DomainError> {
        let (content_type, body) = batch.body()?;
        let mut request = self
            .screened
            .post(url)
            .header(reqwest::header::CONTENT_TYPE, content_type)
            .body(body);
        if let Some(credential) = batch.credential {
            request = request.header(reqwest::header::AUTHORIZATION, sensitive(credential)?);
        }
        succeeded(request.send().await).map(drop)
    }

    /// Writes `batch` as one new object into `bucket`, signed for the
    /// bucket's region.
    async fn to_bucket(&self, bucket: &Bucket<'_>, batch: &Batch<'_>) -> Result<(), DomainError> {
        let credential = batch.credential.ok_or_else(|| {
            DomainError::invalid(message!(
                "infra-a-bucket-takes-records-only-with",
                "a bucket takes records only with a credential"
            ))
        })?;
        let key = access_key(credential)?;
        let (content_type, body) = batch.body()?;
        let at = time::OffsetDateTime::now_utc();
        let url = object_url(bucket.endpoint, bucket.name, at, batch.extension());
        let signed = signed_headers(
            &Upload {
                url: &url,
                region: bucket.region,
                content_type,
                body: &body,
                at,
            },
            &key,
        )?;
        let request = self
            .screened
            .put(url)
            .header(reqwest::header::CONTENT_TYPE, content_type)
            .headers(signed);
        succeeded(request.body(body).send().await).map(drop)
    }

    /// Posts `batch` to the Datadog intake at `url` with the API key.
    async fn to_datadog(&self, url: &str, batch: &Batch<'_>) -> Result<(), DomainError> {
        let api_key = batch.credential.ok_or_else(|| {
            DomainError::invalid(message!(
                "infra-datadog-takes-records-only-with-an",
                "Datadog takes records only with an API key"
            ))
        })?;
        let body = datadog_entries(batch.records)?;
        let request = self
            .fixed
            .post(url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header("DD-API-KEY", sensitive(api_key)?)
            .body(body);
        succeeded(request.send().await).map(drop)
    }
}

#[async_trait]
impl LogShipper for HttpLogShipper {
    async fn ship(&self, shipment: Shipment<'_>) -> Result<(), DomainError> {
        let batch = Batch {
            credential: shipment.credential,
            format: shipment.format,
            records: shipment.records,
        };
        match shipment.destination {
            LogDestination::Https(url) => {
                self.to_collector(reachable(url.as_str(), &self.networks)?, &batch)
                    .await
            }
            LogDestination::Bucket {
                endpoint,
                region,
                bucket,
            } => {
                let endpoint = reachable(endpoint.as_str(), &self.networks)?;
                let bucket = Bucket {
                    endpoint: &endpoint,
                    region,
                    name: bucket,
                };
                self.to_bucket(&bucket, &batch).await
            }
            LogDestination::Datadog(site) => self.to_datadog(&datadog_intake(*site), &batch).await,
        }
    }
}

/// A bucket destination, its endpoint checked as reachable.
struct Bucket<'a> {
    endpoint: &'a url::Url,
    region: &'a BucketRegion,
    name: &'a BucketName,
}

/// One batch, with what it is sent with.
struct Batch<'a> {
    credential: Option<&'a Secret>,
    format: LogFormat,
    records: &'a [RequestObservation],
}

impl Batch<'_> {
    /// The batch's body in its format, with the content type it is sent as.
    fn body(&self) -> Result<(&'static str, Vec<u8>), DomainError> {
        match self.format {
            LogFormat::JsonLines => Ok(("application/x-ndjson", json_lines(self.records)?)),
            LogFormat::OpenTelemetry => Ok(("application/json", otlp::export(self.records)?)),
        }
    }

    /// The extension an object of this format is named with.
    fn extension(&self) -> &'static str {
        match self.format {
            LogFormat::JsonLines => "jsonl",
            LogFormat::OpenTelemetry => "json",
        }
    }
}

/// The address of `site`'s log intake.
fn datadog_intake(site: DatadogSite) -> String {
    format!("https://{}/api/v2/logs", site.log_intake_host())
}

/// One record as Datadog's intake takes it.
#[derive(Serialize)]
struct DatadogEntry<'a> {
    ddsource: &'static str,
    service: &'static str,
    message: String,
    #[serde(flatten)]
    record: RecordLine<'a>,
}

/// The batch as the JSON array Datadog's intake takes. Datadog reads its
/// own shape, so the target's format does not change it.
fn datadog_entries(records: &[RequestObservation]) -> Result<Vec<u8>, DomainError> {
    let entries = records
        .iter()
        .map(|observed| -> Result<DatadogEntry<'_>, DomainError> {
            let record = RecordLine::of(observed)?;
            Ok(DatadogEntry {
                ddsource: DATADOG_SOURCE,
                service: DATADOG_SERVICE,
                message: record.summary(),
                record,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    serde_json::to_vec(&entries).map_err(DomainError::infra)
}

/// `secret` as a header value marked sensitive, so the client never prints
/// it.
///
/// # Errors
///
/// Returns `DomainError::Validation` when it cannot be a header value. The
/// refusal never repeats it.
fn sensitive(secret: &Secret) -> Result<reqwest::header::HeaderValue, DomainError> {
    let mut value = reqwest::header::HeaderValue::from_str(secret.expose()).map_err(|_| {
        DomainError::invalid(message!(
            "infra-the-credential-cannot-be-sent-as",
            "the credential cannot be sent as a header"
        ))
    })?;
    value.set_sensitive(true);
    Ok(value)
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use ianua_domain::domains::proxy::observation::{
        ObservedPath, ObservedPrincipal, RequestOutcome, RouteMatch, Traced,
    };
    use ianua_domain::types::{CorrelationId, Fact, TenantId, UntrustedText};
    use wiremock::matchers::{header, header_exists, method, path_regex};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::http::calls::tests::{by_name, loopback};

    fn shipper(networks: UpstreamNetworks) -> HttpLogShipper {
        HttpLogShipper::new(networks, Duration::from_secs(5)).unwrap()
    }

    fn observed() -> RequestObservation {
        RequestObservation {
            correlation_id: CorrelationId::new(),
            tenant_id: Fact::Known(TenantId::new()),
            route: RouteMatch::NoRoute,
            method: UntrustedText::record("GET"),
            path: ObservedPath::record("/reports"),
            client: IpAddr::from([203, 0, 113, 1]),
            principal: ObservedPrincipal::Anonymous,
            outcome: RequestOutcome::Allowed {
                upstream_status: 200,
            },
            trace: Traced::NotTraced,
            latency: time::Duration::milliseconds(5),
            classification: Vec::new(),
            policy: Default::default(),
            occurred_at: time::OffsetDateTime::now_utc(),
        }
    }

    fn batch<'a>(
        records: &'a [RequestObservation],
        credential: Option<&'a Secret>,
        format: LogFormat,
    ) -> Batch<'a> {
        Batch {
            credential,
            format,
            records,
        }
    }

    async fn answering(verb: &str, response: ResponseTemplate) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method(verb))
            .respond_with(response)
            .mount(&server)
            .await;
        server
    }

    /// A collector receives the batch as JSON lines, with the credential
    /// as the whole `Authorization` header.
    #[tokio::test]
    async fn a_collector_receives_json_lines_with_the_credential() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(header("authorization", "Splunk abc"))
            .and(header("content-type", "application/x-ndjson"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;
        let records = [observed(), observed()];
        let credential = Secret::new("Splunk abc");

        let result = shipper(loopback())
            .to_collector(
                by_name(&server, "/ingest"),
                &batch(&records, Some(&credential), LogFormat::JsonLines),
            )
            .await;

        assert!(result.is_ok());
        let received = server.received_requests().await.unwrap();
        let body = String::from_utf8(received.first().unwrap().body.clone()).unwrap();
        assert_eq!(body.lines().count(), 2);
    }

    /// A collector's 401 response produces an infrastructure error naming
    /// the status and excluding the token echoed in its body.
    #[tokio::test]
    async fn a_refusal_names_the_status_and_not_the_answer() {
        let server = answering(
            "POST",
            ResponseTemplate::new(401).set_body_string("bad token Splunk abc"),
        )
        .await;
        let records = [observed()];
        let credential = Secret::new("Splunk abc");

        let error = shipper(loopback())
            .to_collector(
                by_name(&server, "/ingest"),
                &batch(&records, Some(&credential), LogFormat::JsonLines),
            )
            .await
            .unwrap_err();

        assert!(matches!(error, DomainError::Infrastructure(_)));
        let printed = format!("{error:?} {}", ianua_domain::shared::errors::causes(&error));
        assert!(printed.contains("401"));
        assert!(!printed.contains("abc"), "{printed}");
    }

    /// A collector resolving to disallowed loopback addresses returns a
    /// validation error without receiving a batch.
    #[tokio::test]
    async fn a_collector_resolving_inside_is_refused() {
        let server = answering("POST", ResponseTemplate::new(200)).await;
        let records = [observed()];

        let result = shipper(UpstreamNetworks::public_only())
            .to_collector(
                by_name(&server, "/ingest"),
                &batch(&records, None, LogFormat::JsonLines),
            )
            .await;

        assert!(matches!(result, Err(DomainError::Validation(_))));
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    /// A collector redirect to the metadata address fails the batch send
    /// with an infrastructure error.
    #[tokio::test]
    async fn a_redirect_is_a_failure() {
        let server = answering(
            "POST",
            ResponseTemplate::new(302).insert_header("location", "http://169.254.169.254/"),
        )
        .await;
        let records = [observed()];

        let result = shipper(loopback())
            .to_collector(
                by_name(&server, "/ingest"),
                &batch(&records, None, LogFormat::JsonLines),
            )
            .await;

        assert!(matches!(result, Err(DomainError::Infrastructure(_))));
    }

    /// A collector response delayed beyond the shipper timeout returns an
    /// infrastructure error.
    #[tokio::test]
    async fn a_hung_collector_is_given_up() {
        let server = answering(
            "POST",
            ResponseTemplate::new(200).set_delay(Duration::from_secs(3)),
        )
        .await;
        let records = [observed()];
        let shipper = HttpLogShipper::new(loopback(), Duration::from_millis(200)).unwrap();

        let result = shipper
            .to_collector(
                by_name(&server, "/ingest"),
                &batch(&records, None, LogFormat::OpenTelemetry),
            )
            .await;

        assert!(matches!(result, Err(DomainError::Infrastructure(_))));
    }

    /// A bucket receives one signed object under the day's key.
    #[tokio::test]
    async fn a_bucket_receives_one_signed_object() {
        let server = MockServer::start().await;
        mount_bucket(&server).await;
        let records = [observed()];
        let credential = Secret::new("AKIDEXAMPLE:secret");
        let endpoint = by_name(&server, "/");
        let bucket = Bucket {
            endpoint: &endpoint,
            region: &BucketRegion::new("eu-central-1").unwrap(),
            name: &BucketName::new("acme-logs").unwrap(),
        };

        let result = shipper(loopback())
            .to_bucket(
                &bucket,
                &batch(&records, Some(&credential), LogFormat::JsonLines),
            )
            .await;

        assert!(result.is_ok());
        let received = server.received_requests().await.unwrap();
        let signed = received[0]
            .headers
            .get("authorization")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(signed.contains("/eu-central-1/s3/aws4_request"));
        assert!(signed.contains("SignedHeaders=content-type;host;"));
    }

    /// Accepts one object under the dated log key with both signing headers present.
    async fn mount_bucket(server: &MockServer) {
        Mock::given(method("PUT"))
            .and(path_regex(
                r"^/acme-logs/ianua/\d{4}/\d{2}/\d{2}/[0-9a-f]{32}\.jsonl$",
            ))
            .and(header_exists("x-amz-content-sha256"))
            .and(header_exists("authorization"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(server)
            .await;
    }

    /// Datadog receives a JSON array with the API key in its header.
    #[tokio::test]
    async fn datadog_receives_an_array_with_its_key() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(header("dd-api-key", "dd-key"))
            .respond_with(ResponseTemplate::new(202))
            .expect(1)
            .mount(&server)
            .await;
        let records = [observed()];
        let credential = Secret::new("dd-key");

        let result = shipper(loopback())
            .to_datadog(
                &format!("{}/api/v2/logs", server.uri()),
                &batch(&records, Some(&credential), LogFormat::JsonLines),
            )
            .await;

        assert!(result.is_ok());
        let received = server.received_requests().await.unwrap();
        let sent: serde_json::Value =
            serde_json::from_slice(&received.first().unwrap().body).unwrap();
        assert_eq!(sent[0]["ddsource"], serde_json::json!("ianua"));
    }

    /// Datadog's intake is the site's own host, never one the tenant typed.
    #[test]
    fn datadog_is_reached_at_the_sites_intake() {
        assert_eq!(
            datadog_intake(DatadogSite::Eu1),
            "https://http-intake.logs.datadoghq.eu/api/v2/logs"
        );
    }
}
