//! The post of one message to a push subscription's endpoint.
//!
//! The body has the shape a pulled message has, so a service reads both
//! alike: the payload in base64, the headers and the message type. It is
//! signed as Standard Webhooks lays it out, under a fresh id and the send
//! time, with every secret that still signs. The endpoint is screened when
//! its host resolves, a redirect is never followed, and the post is given
//! up at the subscription's acknowledgement deadline. Only the status of
//! the answer is read.

use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ianua_app::ports::messaging::{OutgoingPush, PushDeliverer, PushOutcome, ReceivedMessage};
use ianua_domain::domains::messaging::message_type::MessageType;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::ssrf::UpstreamNetworks;
use serde::Serialize;

use crate::http::calls::{Sent, bounded, reachable, sent};
use crate::http::client::{DeliveryReach, LONGEST_CALL};
use crate::http::signing::SignedHeaders;

/// Posts messages to the endpoints push subscriptions name.
#[derive(Debug, Clone)]
pub struct HttpPushDeliverer {
    client: reqwest::Client,
    networks: UpstreamNetworks,
}

/// A message as a push carries it.
#[derive(Serialize)]
struct PushBody<'a> {
    payload: String,
    headers: Vec<HeaderPair<'a>>,
    message_type: Option<&'a str>,
}

/// One header of the message.
#[derive(Serialize)]
struct HeaderPair<'a> {
    key: &'a str,
    value: &'a str,
}

impl HttpPushDeliverer {
    /// A deliverer reaching public addresses and those in `networks`, the
    /// deployment's own, by the path `reach` says.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the client cannot be
    /// built.
    pub fn new(networks: UpstreamNetworks, reach: &DeliveryReach) -> Result<Self, DomainError> {
        Ok(Self {
            client: reach.client(LONGEST_CALL, networks.clone())?,
            networks,
        })
    }

    /// Posts `push`'s message to `url`, the address it names once screened.
    async fn post(
        &self,
        url: url::Url,
        push: OutgoingPush<'_>,
    ) -> Result<PushOutcome, DomainError> {
        let body = serde_json::to_vec(&body_of(push.message)).map_err(DomainError::infra)?;
        let signed = SignedHeaders::of(
            format!("msg_{}", push.message.key.as_str()),
            ianua_domain::shared::clock::now(),
            &body,
            push.secrets,
        )?;
        let request = self
            .client
            .post(url)
            .timeout(bounded(push.timeout.std_duration()))
            .header(reqwest::header::CONTENT_TYPE, "application/json");
        let outcome = sent(signed.applied(request).body(body).send().await)?;
        Ok(taken(&outcome))
    }
}

#[async_trait]
impl PushDeliverer for HttpPushDeliverer {
    async fn push(&self, push: OutgoingPush<'_>) -> Result<PushOutcome, DomainError> {
        let url = reachable(push.url.as_str(), &self.networks)?;
        self.post(url, push).await
    }
}

/// `message` in the shape a pulled message has.
fn body_of(message: &ReceivedMessage) -> PushBody<'_> {
    PushBody {
        payload: STANDARD.encode(&message.payload),
        headers: message
            .headers
            .iter()
            .map(|(key, value)| HeaderPair { key, value })
            .collect(),
        message_type: message.message_type.as_ref().map(MessageType::as_str),
    }
}

/// Whether `sent` took the message: only a success code does.
fn taken(sent: &Sent) -> PushOutcome {
    match sent {
        Sent::Answered(response) if response.status().is_success() => PushOutcome::Accepted,
        Sent::Answered(_) | Sent::TimedOut | Sent::Unreachable(_) => PushOutcome::Failed,
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use ianua_app::ports::messaging::MessageKey;
    use ianua_domain::shared::security::secret::Secret;
    use ianua_domain::types::{PublicHttpsUrl, Seconds};
    use wiremock::matchers::{header, header_exists, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::http::calls::tests::{by_name, loopback};
    use crate::http::signing::signatures;

    fn deliverer(networks: UpstreamNetworks) -> HttpPushDeliverer {
        HttpPushDeliverer::new(networks, &DeliveryReach::default()).unwrap()
    }

    fn message() -> ReceivedMessage {
        ReceivedMessage {
            key: MessageKey::new("orders-42"),
            payload: b"order 42 shipped".to_vec(),
            headers: vec![("trace".to_owned(), "abc".to_owned())],
            message_type: None,
            published_at: time::OffsetDateTime::now_utc(),
        }
    }

    async fn endpoint(response: ResponseTemplate) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/push"))
            .respond_with(response)
            .mount(&server)
            .await;
        server
    }

    async fn pushed(
        server: &MockServer,
        deliverer: &HttpPushDeliverer,
        timeout: Seconds,
    ) -> Result<PushOutcome, DomainError> {
        let url = PublicHttpsUrl::new("https://orders.example.com/push").unwrap();
        let message = message();
        let secrets = [Secret::new("psec_Y3VycmVudA==")];
        let push = OutgoingPush {
            url: &url,
            message: &message,
            secrets: &secrets,
            timeout,
        };
        deliverer.post(by_name(server, "/push"), push).await
    }

    /// A push carries the message as a pulled one reads, signed over its
    /// id, its time and its body, and a 200 means it was taken.
    #[tokio::test]
    async fn a_push_is_signed_and_taken_on_success() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/push"))
            .and(header("content-type", "application/json"))
            .and(header_exists("webhook-id"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let outcome = pushed(&server, &deliverer(loopback()), Seconds::new(5))
            .await
            .unwrap();

        assert_eq!(outcome, PushOutcome::Accepted);
        let requests = server.received_requests().await.unwrap();
        let received = &requests[0];
        assert_push_signature(received);
        let body: serde_json::Value = serde_json::from_slice(&received.body).unwrap();
        assert_eq!(body["payload"], STANDARD.encode(b"order 42 shipped"));
        assert_eq!(body["headers"][0]["key"], "trace");
    }

    /// Checks that the received push's ID and signature bind its timestamp and exact body.
    fn assert_push_signature(received: &wiremock::Request) {
        let read = |name: &str| {
            received
                .headers
                .get(name)
                .unwrap()
                .to_str()
                .unwrap()
                .to_owned()
        };
        assert_eq!(read("webhook-id"), "msg_orders-42");
        let content = format!("{}.{}.", read("webhook-id"), read("webhook-timestamp"));
        let signed = [content.as_bytes(), received.body.as_slice()].concat();
        assert_eq!(
            read("webhook-signature"),
            signatures(&signed, &[Secret::new("psec_Y3VycmVudA==")]).unwrap()
        );
    }

    /// An endpoint answering 503 did not take the message.
    #[tokio::test]
    async fn an_error_answer_fails_the_push() {
        let server = endpoint(ResponseTemplate::new(503)).await;

        let outcome = pushed(&server, &deliverer(loopback()), Seconds::new(5))
            .await
            .unwrap();

        assert_eq!(outcome, PushOutcome::Failed);
    }

    /// An endpoint redirect to a private address produces a failed push
    /// outcome.
    #[tokio::test]
    async fn a_redirect_fails_the_push_and_is_never_followed() {
        let server =
            endpoint(ResponseTemplate::new(301).insert_header("location", "http://10.0.0.1/"))
                .await;

        let outcome = pushed(&server, &deliverer(loopback()), Seconds::new(5))
            .await
            .unwrap();

        assert_eq!(outcome, PushOutcome::Failed);
    }

    /// A response delayed beyond the subscription deadline produces a
    /// failed push outcome.
    #[tokio::test]
    async fn a_hung_endpoint_fails_at_the_deadline() {
        let server = endpoint(ResponseTemplate::new(200).set_delay(Duration::from_secs(5))).await;

        let outcome = pushed(&server, &deliverer(loopback()), Seconds::new(1))
            .await
            .unwrap();

        assert_eq!(outcome, PushOutcome::Failed);
    }

    /// A push endpoint resolving to disallowed loopback addresses returns
    /// a validation error without receiving a request.
    #[tokio::test]
    async fn an_endpoint_inside_the_deployment_is_refused() {
        let server = endpoint(ResponseTemplate::new(200)).await;

        let result = pushed(
            &server,
            &deliverer(UpstreamNetworks::public_only()),
            Seconds::new(5),
        )
        .await;

        assert!(matches!(result, Err(DomainError::Validation(_))));
        assert!(server.received_requests().await.unwrap().is_empty());
    }
}
