//! The post of one try at a webhook message: signed as Standard Webhooks
//! lays it out, screened when its host resolves, never redirected, and
//! given up once the subscription's retry policy says.
//!
//! The answer's body is never read: a delivery is judged by its status
//! alone, and what an endpoint says back is not the platform's to keep.

use std::time::{Duration, Instant};

use async_trait::async_trait;
use ianua_app::ports::webhooks::{OutboundDelivery, WebhookDeliverer, WebhookDeliveryOutcome};
use ianua_domain::domains::webhooks::signing::SignedDelivery;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::ssrf::UpstreamNetworks;

use crate::http::calls::{bounded, millis_since, outcome_of, reachable};
use crate::http::client::DeliveryReach;
use crate::http::signing::signatures;

/// Sends webhook deliveries to the endpoints tenants registered.
#[derive(Debug, Clone)]
pub struct HttpWebhookDeliverer {
    client: reqwest::Client,
    networks: UpstreamNetworks,
    longest: Duration,
}

impl HttpWebhookDeliverer {
    /// A deliverer reaching public addresses and those in `networks`, the
    /// deployment's own, by the path `reach` says, every try given up
    /// after `longest` at most, or sooner when the subscription's policy
    /// says, and never past the longest any call may take.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the client cannot be
    /// built.
    pub fn new(
        networks: UpstreamNetworks,
        longest: Duration,
        reach: &DeliveryReach,
    ) -> Result<Self, DomainError> {
        let longest = bounded(longest);
        Ok(Self {
            client: reach.client(longest, networks.clone())?,
            networks,
            longest,
        })
    }

    /// Posts `delivery` to `url`, the address it names once screened,
    /// signed with each of its secrets and given up after its timeout.
    async fn post(
        &self,
        url: url::Url,
        delivery: &OutboundDelivery<'_>,
    ) -> Result<WebhookDeliveryOutcome, DomainError> {
        let signed = delivery.signed;
        let signature = signatures(&signed.signed_content(delivery.payload), delivery.secrets)?;
        let request = self
            .client
            .post(url)
            .timeout(delivery.timeout.std_duration().min(self.longest))
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header(SignedDelivery::ID_HEADER, signed.id_header())
            .header(SignedDelivery::TIMESTAMP_HEADER, signed.timestamp_header())
            .header(SignedDelivery::SIGNATURE_HEADER, signature)
            .body(delivery.payload.to_vec());
        let started = Instant::now();
        let outcome = outcome_of(request.send().await)?;
        Ok(WebhookDeliveryOutcome {
            outcome,
            duration_ms: millis_since(started),
        })
    }
}

#[async_trait]
impl WebhookDeliverer for HttpWebhookDeliverer {
    async fn deliver(
        &self,
        delivery: OutboundDelivery<'_>,
    ) -> Result<WebhookDeliveryOutcome, DomainError> {
        let url = reachable(delivery.url.as_str(), &self.networks)?;
        self.post(url, &delivery).await
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::shared::security::secret::Secret;
    use ianua_domain::types::{DeliveryOutcome, PublicHttpsUrl, Seconds, WebhookMessageId};
    use wiremock::matchers::{body_bytes, header, header_exists, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::http::calls::tests::{by_name, loopback};

    const BODY: &[u8] = br#"{"type":"identity.user_registered"}"#;

    fn deliverer(networks: UpstreamNetworks) -> HttpWebhookDeliverer {
        HttpWebhookDeliverer::new(networks, Duration::from_secs(10), &DeliveryReach::default())
            .unwrap()
    }

    /// The address a subscription names; the tests post to the mock
    /// instead, which the domain's public URL cannot name.
    fn registered() -> PublicHttpsUrl {
        PublicHttpsUrl::new("https://hooks.example.com/in").unwrap()
    }

    fn secrets() -> [Secret; 2] {
        [
            Secret::new("whsec_Y3VycmVudA=="),
            Secret::new("whsec_cHJldmlvdXM="),
        ]
    }

    async fn endpoint(response: ResponseTemplate) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/hook"))
            .respond_with(response)
            .mount(&server)
            .await;
        server
    }

    async fn sent_to(
        server: &MockServer,
        deliverer: &HttpWebhookDeliverer,
        timeout: Seconds,
    ) -> Result<WebhookDeliveryOutcome, DomainError> {
        let url = registered();
        let secrets = secrets();
        let delivery = OutboundDelivery {
            url: &url,
            signed: SignedDelivery::now(WebhookMessageId::new()),
            payload: BODY,
            secrets: &secrets,
            timeout,
        };
        deliverer.post(by_name(server, "/hook"), &delivery).await
    }

    /// A delivery carries the body, the message id, the send time and one
    /// signature per secret, and a 204 reads as answered with 204.
    #[tokio::test]
    async fn a_delivery_is_signed_with_every_secret_and_reports_its_code() {
        let server = MockServer::start().await;
        mount_signed_delivery(&server).await;
        let url = registered();
        let secrets = secrets();
        let signed = SignedDelivery::now(WebhookMessageId::new());
        let delivery = OutboundDelivery {
            url: &url,
            signed,
            payload: BODY,
            secrets: &secrets,
            timeout: Seconds::new(5),
        };

        let outcome = deliverer(loopback())
            .post(by_name(&server, "/hook"), &delivery)
            .await
            .unwrap();

        assert_eq!(outcome.outcome, DeliveryOutcome::Answered { code: 204 });
        let received = server.received_requests().await.unwrap();
        let sent = received[0]
            .headers
            .get(SignedDelivery::SIGNATURE_HEADER)
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        assert_eq!(
            sent,
            signatures(&signed.signed_content(BODY), &secrets).unwrap()
        );
        assert_eq!(sent.split(' ').count(), 2);
    }

    /// Accepts only the expected JSON body with the delivery's ID and timestamp headers.
    async fn mount_signed_delivery(server: &MockServer) {
        Mock::given(method("POST"))
            .and(path("/hook"))
            .and(body_bytes(BODY))
            .and(header("content-type", "application/json"))
            .and(header_exists(SignedDelivery::ID_HEADER))
            .and(header_exists(SignedDelivery::TIMESTAMP_HEADER))
            .respond_with(ResponseTemplate::new(204))
            .mount(server)
            .await;
    }

    /// An endpoint answering 500 is a failed delivery with its code, not an
    /// error, so the retry policy can count it.
    #[tokio::test]
    async fn an_error_answer_is_reported_with_its_code() {
        let server = endpoint(ResponseTemplate::new(500).set_body_string("boom")).await;

        let outcome = sent_to(&server, &deliverer(loopback()), Seconds::new(5))
            .await
            .unwrap();

        assert_eq!(outcome.outcome, DeliveryOutcome::Answered { code: 500 });
    }

    /// A webhook redirect to the metadata address is reported as HTTP 307,
    /// with one request recorded at the endpoint.
    #[tokio::test]
    async fn a_redirect_is_a_failed_delivery_and_never_followed() {
        let server = endpoint(
            ResponseTemplate::new(307).insert_header("location", "http://169.254.169.254/"),
        )
        .await;

        let outcome = sent_to(&server, &deliverer(loopback()), Seconds::new(5))
            .await
            .unwrap();

        assert_eq!(outcome.outcome, DeliveryOutcome::Answered { code: 307 });
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }

    /// A response delayed beyond the subscription policy's timeout produces
    /// a timed-out delivery outcome.
    #[tokio::test]
    async fn a_hung_endpoint_times_out_at_the_policy_limit() {
        let server = endpoint(ResponseTemplate::new(200).set_delay(Duration::from_secs(5))).await;

        let outcome = sent_to(&server, &deliverer(loopback()), Seconds::new(1))
            .await
            .unwrap();

        assert_eq!(outcome.outcome, DeliveryOutcome::TimedOut);
    }

    /// A response exceeding the deployment timeout produces a timed-out
    /// outcome even when the subscription policy allows a longer wait.
    #[tokio::test]
    async fn a_try_ends_at_the_deployments_timeout_before_a_longer_policy() {
        let server = endpoint(ResponseTemplate::new(200).set_delay(Duration::from_secs(5))).await;
        let held = HttpWebhookDeliverer::new(
            loopback(),
            Duration::from_secs(1),
            &DeliveryReach::default(),
        )
        .unwrap();

        let outcome = sent_to(&server, &held, Seconds::new(20)).await.unwrap();

        assert_eq!(outcome.outcome, DeliveryOutcome::TimedOut);
    }

    /// A webhook host resolving to disallowed loopback addresses returns a
    /// validation error without receiving a request.
    #[tokio::test]
    async fn a_host_resolving_inside_the_deployment_is_refused() {
        let server = endpoint(ResponseTemplate::new(200)).await;

        let result = sent_to(
            &server,
            &deliverer(UpstreamNetworks::public_only()),
            Seconds::new(5),
        )
        .await;

        assert!(matches!(result, Err(DomainError::Validation(_))));
        assert!(server.received_requests().await.unwrap().is_empty());
    }
}
