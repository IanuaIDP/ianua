//! Sending one audit record along one of a tenant's streams: to a Splunk
//! event collector, a Datadog account's log intake, a syslog collector over
//! TLS, or any HTTPS endpoint.
//!
//! A collector, an endpoint and a syslog host are addresses the tenant
//! chose, so each is checked before the call and screened as its name
//! resolves; Datadog's intake is the site's own host, so it goes through the
//! fixed client. Every credential is opened from its sealed copy for this
//! send alone and goes into one header, marked sensitive, never into a log
//! line or an error. The record's body and the destination's answer are
//! never logged or read back.

mod datadog;
mod event;
mod splunk;
mod syslog;

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use ianua_app::ports::audit::AuditStreamSender;
use ianua_app::ports::authentication::{SealedFor, SecretEncryptor};
use ianua_domain::domains::audit::record::AuditRecord;
use ianua_domain::domains::audit::streaming::{HttpAuthorization, SplunkTarget, StreamDestination};
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::shared::security::ssrf::UpstreamNetworks;
use ianua_domain::types::SealedSecret;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderName, HeaderValue};

use crate::http::calls::{reachable, succeeded};
use crate::http::client::{DeliveryReach, fixed};
use crate::http::logs::streams::syslog::SyslogSender;

/// The header Datadog reads the API key from.
const DATADOG_KEY: &str = "dd-api-key";

/// One header a send carries, its value marked sensitive.
type Credential = Option<(HeaderName, HeaderValue)>;

/// Sends audit records to the destinations a tenant streams them to.
pub struct HttpAuditStreamSender {
    screened: reqwest::Client,
    fixed: reqwest::Client,
    networks: UpstreamNetworks,
    syslog: SyslogSender,
    encryptor: Arc<dyn SecretEncryptor>,
}

impl fmt::Debug for HttpAuditStreamSender {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpAuditStreamSender")
            .field("networks", &self.networks)
            .field("syslog", &self.syslog)
            .finish_non_exhaustive()
    }
}

impl HttpAuditStreamSender {
    /// A sender whose every send gives up after `timeout`, reaching a
    /// tenant's address only when it is public or in `networks`, by the
    /// path `reach` says, and opening sealed credentials with `encryptor`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a client or TLS cannot be
    /// set up.
    pub fn new(
        networks: UpstreamNetworks,
        timeout: Duration,
        encryptor: Arc<dyn SecretEncryptor>,
        reach: &DeliveryReach,
    ) -> Result<Self, DomainError> {
        Ok(Self {
            screened: reach.client(timeout, networks.clone())?,
            fixed: fixed(timeout)?,
            syslog: SyslogSender::new(networks.clone(), timeout, reach)?,
            networks,
            encryptor,
        })
    }

    /// `sealed`, kept at `place`, opened for one send.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when it cannot be opened
    /// there or is not text. The error never holds the value.
    async fn opened(
        &self,
        sealed: &SealedSecret,
        place: &SealedFor,
    ) -> Result<Secret, DomainError> {
        let bytes = self.encryptor.decrypt(sealed, place).await?;
        String::from_utf8(bytes)
            .map(Secret::new)
            .map_err(|_| DomainError::infra_msg("a stream's credential is not text"))
    }

    /// The header `authorization` asks for, its value opened from `place`.
    async fn endpoint_header(
        &self,
        authorization: &HttpAuthorization,
        place: &SealedFor,
    ) -> Result<Credential, DomainError> {
        let HttpAuthorization::Header { name, value } = authorization else {
            return Ok(None);
        };
        let name = HeaderName::from_bytes(name.as_str().as_bytes()).map_err(|_| {
            DomainError::invalid(message!(
                "infra-the-stream-s-header-name-cannot",
                "the stream's header name cannot be sent"
            ))
        })?;
        Ok(Some((name, sensitive(&self.opened(value, place).await?)?)))
    }

    /// Sends a record to the screened collector with its opened Splunk token.
    async fn send_splunk(
        &self,
        target: &SplunkTarget,
        credentials: &SealedFor,
        record: &AuditRecord,
    ) -> Result<(), DomainError> {
        let url = reachable(target.endpoint().as_str(), &self.networks)?;
        let token = splunk::authorization(&self.opened(target.token(), credentials).await?);
        let header = Some((AUTHORIZATION, sensitive(&token)?));
        post(
            &self.screened,
            url,
            splunk::event(record, target.index())?,
            header,
        )
        .await
    }
}

#[async_trait]
impl AuditStreamSender for HttpAuditStreamSender {
    async fn send(
        &self,
        destination: &StreamDestination,
        credentials: &SealedFor,
        record: &AuditRecord,
    ) -> Result<(), DomainError> {
        match destination {
            StreamDestination::Splunk(target) => {
                self.send_splunk(target, credentials, record).await
            }
            StreamDestination::Datadog(target) => {
                let key = self.opened(target.api_key(), credentials).await?;
                let header = Some((HeaderName::from_static(DATADOG_KEY), sensitive(&key)?));
                let url =
                    url::Url::parse(&datadog::intake(target.site())).map_err(DomainError::infra)?;
                post(&self.fixed, url, datadog::entries(record)?, header).await
            }
            StreamDestination::Syslog(target) => {
                self.syslog
                    .send(target.host().as_str(), target.port().get(), record)
                    .await
            }
            StreamDestination::Http(target) => {
                let url = reachable(target.endpoint().as_str(), &self.networks)?;
                let header = self
                    .endpoint_header(target.authorization(), credentials)
                    .await?;
                post(&self.screened, url, event::json(record)?, header).await
            }
        }
    }
}

/// Posts `body`, as JSON, to `url` through `client`, with `header` when
/// there is one. Only the status of the answer is read.
///
/// # Errors
///
/// - `DomainError::Validation` when the address resolves only inside the
///   deployment.
/// - `DomainError::Infrastructure` when it cannot be reached in time or
///   does not answer with success.
async fn post(
    client: &reqwest::Client,
    url: url::Url,
    body: Vec<u8>,
    header: Credential,
) -> Result<(), DomainError> {
    let mut request = client
        .post(url)
        .header(CONTENT_TYPE, "application/json")
        .body(body);
    if let Some((name, value)) = header {
        request = request.header(name, value);
    }
    succeeded(request.send().await).map(drop)
}

/// `secret` as a header value marked sensitive, so the client never prints
/// it.
///
/// # Errors
///
/// Returns `DomainError::Validation` when it cannot be a header value. The
/// refusal never repeats it.
fn sensitive(secret: &Secret) -> Result<HeaderValue, DomainError> {
    let mut value = HeaderValue::from_str(secret.expose()).map_err(|_| {
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
    use ianua_app::ports::authentication::{SealOwner, SealedField};
    use ianua_domain::domains::audit::streaming::{SplunkIndex, StreamHeaderName};
    use ianua_domain::types::TenantId;
    use wiremock::matchers::{header, method};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::crypto::{AesGcmSecretEncryptor, SealingKey};
    use crate::http::calls::tests::{by_name, loopback};
    use crate::http::client::screened;
    use crate::http::logs::streams::event::tests::record;

    fn client(networks: UpstreamNetworks) -> reqwest::Client {
        screened(Duration::from_secs(5), networks).unwrap()
    }

    /// The collector token as a sensitive authorization header.
    fn token() -> (HeaderName, HeaderValue) {
        (
            AUTHORIZATION,
            sensitive(&Secret::new("Splunk hec-token")).unwrap(),
        )
    }

    async fn answering(response: ResponseTemplate) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(response)
            .mount(&server)
            .await;
        server
    }

    /// A Splunk collector receives the record with its token in the
    /// `Splunk` authorization.
    #[tokio::test]
    async fn a_splunk_collector_receives_the_record_with_its_token() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(header("authorization", "Splunk hec-token"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;
        let body = splunk::event(&record(), &SplunkIndex::TokenDefault).unwrap();

        let result = post(
            &client(loopback()),
            by_name(&server, "/services/collector"),
            body,
            Some(token()),
        )
        .await;

        assert!(result.is_ok());
    }

    /// An endpoint is sent the header the stream names, with its opened
    /// value.
    #[tokio::test]
    async fn an_endpoint_is_sent_the_header_it_asks_for() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(header("x-siem-key", "opened"))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(&server)
            .await;
        let sender = sender();
        let place = stream_place(TenantId::new());
        let sealed = sender.encryptor.encrypt(b"opened", &place).await.unwrap();
        let header = sender
            .endpoint_header(&endpoint_authorization(sealed), &place)
            .await
            .unwrap();

        let result = post(
            &client(loopback()),
            by_name(&server, "/in"),
            event::json(&record()).unwrap(),
            header,
        )
        .await;

        assert!(result.is_ok());
    }

    /// The sealed credential under the endpoint's chosen SIEM header.
    fn endpoint_authorization(value: SealedSecret) -> HttpAuthorization {
        HttpAuthorization::Header {
            name: StreamHeaderName::new(
                ianua_domain::types::HeaderName::new("x-siem-key").unwrap(),
            )
            .unwrap(),
            value,
        }
    }

    /// A collector's 403 response produces an infrastructure error naming
    /// the status and excluding the token echoed in its body.
    #[tokio::test]
    async fn a_refusal_names_the_status_and_not_the_answer() {
        let server =
            answering(ResponseTemplate::new(403).set_body_string("invalid token hec-token")).await;
        let body = event::json(&record()).unwrap();

        let error = post(
            &client(loopback()),
            by_name(&server, "/in"),
            body,
            Some(token()),
        )
        .await
        .unwrap_err();

        assert!(matches!(error, DomainError::Infrastructure(_)));
        let printed = format!("{error:?} {}", ianua_domain::shared::errors::causes(&error));
        assert!(printed.contains("403"), "{printed}");
        assert!(!printed.contains("hec-token"), "{printed}");
    }

    /// A collector resolving to disallowed loopback addresses returns a
    /// validation error without receiving a request.
    #[tokio::test]
    async fn a_destination_resolving_inside_is_refused() {
        let server = answering(ResponseTemplate::new(200)).await;

        let result = post(
            &client(UpstreamNetworks::public_only()),
            by_name(&server, "/in"),
            event::json(&record()).unwrap(),
            None,
        )
        .await;

        assert!(matches!(result, Err(DomainError::Validation(_))));
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    /// A collector redirect to the metadata address returns an infrastructure
    /// error.
    #[tokio::test]
    async fn a_redirect_is_a_failure() {
        let server = answering(
            ResponseTemplate::new(302).insert_header("location", "http://169.254.169.254/"),
        )
        .await;

        let result = post(
            &client(loopback()),
            by_name(&server, "/in"),
            event::json(&record()).unwrap(),
            None,
        )
        .await;

        assert!(matches!(result, Err(DomainError::Infrastructure(_))));
    }

    /// A collector response delayed beyond the client timeout returns an
    /// infrastructure error.
    #[tokio::test]
    async fn a_hung_destination_is_given_up() {
        let server = answering(ResponseTemplate::new(200).set_delay(Duration::from_secs(3))).await;
        let client = screened(Duration::from_millis(200), loopback()).unwrap();

        let result = post(
            &client,
            by_name(&server, "/in"),
            event::json(&record()).unwrap(),
            None,
        )
        .await;

        assert!(matches!(result, Err(DomainError::Infrastructure(_))));
    }

    /// Opening a credential sealed with an unknown key returns an
    /// infrastructure error.
    #[tokio::test]
    async fn a_credential_that_does_not_open_is_refused() {
        let sender = sender();
        let place = stream_place(TenantId::new());
        let foreign =
            AesGcmSecretEncryptor::new(SealingKey::new("k2", [9; 32]).unwrap(), Vec::new())
                .encrypt(b"other", &place)
                .await
                .unwrap();

        let result = sender.opened(&foreign, &place).await;

        assert!(matches!(result, Err(DomainError::Infrastructure(_))));
    }

    /// Opening Globex's sealed collector token in Acme's stream context
    /// returns an infrastructure error.
    #[tokio::test]
    async fn a_credential_sealed_for_another_tenant_does_not_open() {
        let sender = sender();
        let globex = stream_place(TenantId::new());
        let acme = stream_place(TenantId::new());
        let copied = sender
            .encryptor
            .encrypt(b"globex-token", &globex)
            .await
            .unwrap();

        let result = sender.opened(&copied, &acme).await;

        assert!(matches!(result, Err(DomainError::Infrastructure(_))));
    }

    /// Where `tenant`'s one stream keeps its credentials.
    fn stream_place(tenant: TenantId) -> SealedFor {
        SealedFor::new(
            SealOwner::Tenant(tenant),
            SealedField::AuditStreamCredential,
            uuid::Uuid::nil(),
        )
    }

    fn sender() -> HttpAuditStreamSender {
        let encryptor =
            AesGcmSecretEncryptor::new(SealingKey::new("k1", [7; 32]).unwrap(), Vec::new());
        HttpAuditStreamSender::new(
            loopback(),
            Duration::from_secs(5),
            Arc::new(encryptor),
            &DeliveryReach::default(),
        )
        .unwrap()
    }
}
