//! The push of a Security Event Token to a receiver's endpoint (RFC 8935).
//!
//! The token carries its own signature, made by the tenant's signing key
//! before it gets here, so the post only adds the receiver's own
//! `Authorization` header when it asked for one. The endpoint is screened
//! when its host resolves, a redirect is never followed, and the push is
//! given up after a fixed time, so a receiver that hangs holds no
//! dispatch. Only the status of the answer is read.

use std::time::{Duration, Instant};

use async_trait::async_trait;
use ianua_app::ports::signals::{
    ReceiverCredential, SetPush, SignalDeliverer, SignalDeliveryOutcome,
};
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::ssrf::UpstreamNetworks;

use crate::http::calls::{millis_since, outcome_of, reachable};
use crate::http::client::DeliveryReach;

/// How long a receiver has to answer one push.
const PUSH_TIMEOUT: Duration = Duration::from_secs(10);

/// The media type of a Security Event Token sent as the body.
const SECEVENT: &str = "application/secevent+jwt";

/// Pushes signed Security Event Tokens to the receivers streams name.
#[derive(Debug, Clone)]
pub struct HttpSignalDeliverer {
    client: reqwest::Client,
    networks: UpstreamNetworks,
}

impl HttpSignalDeliverer {
    /// A deliverer reaching public addresses and those in `networks`, the
    /// deployment's own, by the path `reach` says.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the client cannot be
    /// built.
    pub fn new(networks: UpstreamNetworks, reach: &DeliveryReach) -> Result<Self, DomainError> {
        Self::within(networks, PUSH_TIMEOUT, reach)
    }

    /// A deliverer whose pushes give up after `timeout`.
    fn within(
        networks: UpstreamNetworks,
        timeout: Duration,
        reach: &DeliveryReach,
    ) -> Result<Self, DomainError> {
        Ok(Self {
            client: reach.client(timeout, networks.clone())?,
            networks,
        })
    }

    /// Posts `push`'s token to `url`, the address it names once screened.
    async fn post(
        &self,
        url: url::Url,
        push: SetPush<'_>,
    ) -> Result<SignalDeliveryOutcome, DomainError> {
        let request = self
            .client
            .post(url)
            .header(reqwest::header::CONTENT_TYPE, SECEVENT)
            .header(reqwest::header::ACCEPT, "application/json")
            .body(push.token.as_str().to_owned());
        let request = with_credential(request, push.credential)?;
        let started = Instant::now();
        let outcome = outcome_of(request.send().await)?;
        Ok(SignalDeliveryOutcome {
            outcome,
            duration_ms: millis_since(started),
        })
    }
}

#[async_trait]
impl SignalDeliverer for HttpSignalDeliverer {
    async fn deliver(&self, push: SetPush<'_>) -> Result<SignalDeliveryOutcome, DomainError> {
        let url = reachable(push.endpoint.as_str(), &self.networks)?;
        self.post(url, push).await
    }
}

/// `request` with the receiver's `Authorization` header, when it asked for
/// one. The header is marked sensitive, so no debug print shows it.
///
/// # Errors
///
/// Returns `DomainError::Validation` when the value cannot be sent as a
/// header, rather than pushing without the header the receiver asked for.
fn with_credential(
    request: reqwest::RequestBuilder,
    credential: &ReceiverCredential,
) -> Result<reqwest::RequestBuilder, DomainError> {
    let ReceiverCredential::Header(value) = credential else {
        return Ok(request);
    };
    let mut header = reqwest::header::HeaderValue::from_str(value.expose()).map_err(|_| {
        DomainError::invalid(message!(
            "infra-the-receiver-s-header-cannot-be",
            "the receiver's header cannot be sent as one"
        ))
    })?;
    header.set_sensitive(true);
    Ok(request.header(reqwest::header::AUTHORIZATION, header))
}

#[cfg(test)]
mod tests {
    use ianua_app::ports::signals::SecurityEventToken;
    use ianua_domain::shared::security::secret::Secret;
    use ianua_domain::types::{DeliveryOutcome, PublicHttpsUrl};
    use wiremock::matchers::{body_string, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::http::calls::tests::{by_name, loopback};

    const TOKEN: &str = "eyJhbGciOiJSUzI1NiJ9.eyJqdGkiOiIxIn0.c2ln";

    fn deliverer(networks: UpstreamNetworks) -> HttpSignalDeliverer {
        HttpSignalDeliverer::new(networks, &DeliveryReach::default()).unwrap()
    }

    async fn receiver(response: ResponseTemplate) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/events"))
            .respond_with(response)
            .mount(&server)
            .await;
        server
    }

    async fn pushed(
        server: &MockServer,
        deliverer: &HttpSignalDeliverer,
        credential: &ReceiverCredential,
    ) -> Result<SignalDeliveryOutcome, DomainError> {
        let endpoint = PublicHttpsUrl::new("https://receiver.example.com/events").unwrap();
        let token = SecurityEventToken::new(TOKEN.to_owned());
        let push = SetPush {
            endpoint: &endpoint,
            token: &token,
            credential,
        };
        deliverer.post(by_name(server, "/events"), push).await
    }

    /// The token goes as the body under its own media type, with the
    /// receiver's header, and a 202 reads as answered with 202.
    #[tokio::test]
    async fn a_token_is_pushed_with_the_receivers_header() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/events"))
            .and(header("content-type", SECEVENT))
            .and(header("authorization", "Bearer rcv-token"))
            .and(body_string(TOKEN))
            .respond_with(ResponseTemplate::new(202))
            .mount(&server)
            .await;
        let credential = ReceiverCredential::Header(Secret::new("Bearer rcv-token"));

        let outcome = pushed(&server, &deliverer(loopback()), &credential)
            .await
            .unwrap();

        assert_eq!(outcome.outcome, DeliveryOutcome::Answered { code: 202 });
    }

    /// A receiver that asked for no header gets none.
    #[tokio::test]
    async fn no_header_is_sent_when_none_was_asked_for() {
        let server = receiver(ResponseTemplate::new(202)).await;

        pushed(
            &server,
            &deliverer(loopback()),
            &ReceiverCredential::Omitted,
        )
        .await
        .unwrap();

        let received = server.received_requests().await.unwrap();
        assert!(received[0].headers.get("authorization").is_none());
    }

    /// A receiver refusing the token with 400 is a failed push with its
    /// code, not an error.
    #[tokio::test]
    async fn a_refusal_is_reported_with_its_code() {
        let server =
            receiver(ResponseTemplate::new(400).set_body_string(r#"{"err":"invalid_key"}"#)).await;

        let outcome = pushed(
            &server,
            &deliverer(loopback()),
            &ReceiverCredential::Omitted,
        )
        .await
        .unwrap();

        assert_eq!(outcome.outcome, DeliveryOutcome::Answered { code: 400 });
    }

    /// A receiver redirect to a private address is reported as HTTP 302.
    #[tokio::test]
    async fn a_redirect_is_never_followed() {
        let server =
            receiver(ResponseTemplate::new(302).insert_header("location", "http://10.0.0.1/"))
                .await;

        let outcome = pushed(
            &server,
            &deliverer(loopback()),
            &ReceiverCredential::Omitted,
        )
        .await
        .unwrap();

        assert_eq!(outcome.outcome, DeliveryOutcome::Answered { code: 302 });
    }

    /// A receiver response delayed beyond the push timeout produces a
    /// timed-out delivery outcome.
    #[tokio::test]
    async fn a_hung_receiver_times_out() {
        let server = receiver(ResponseTemplate::new(202).set_delay(Duration::from_secs(3))).await;
        let deliverer = HttpSignalDeliverer::within(
            loopback(),
            Duration::from_millis(300),
            &DeliveryReach::default(),
        )
        .unwrap();

        let outcome = pushed(&server, &deliverer, &ReceiverCredential::Omitted)
            .await
            .unwrap();

        assert_eq!(outcome.outcome, DeliveryOutcome::TimedOut);
    }

    /// A credential containing a line break and injected header returns a
    /// validation error without sending a push.
    #[tokio::test]
    async fn a_header_that_cannot_be_sent_is_refused() {
        let server = receiver(ResponseTemplate::new(202)).await;
        let credential = ReceiverCredential::Header(Secret::new("Bearer a\r\nX-Evil: 1"));

        let result = pushed(&server, &deliverer(loopback()), &credential).await;

        assert!(matches!(result, Err(DomainError::Validation(_))));
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    /// A receiver resolving to disallowed loopback addresses returns a
    /// validation error without receiving a push.
    #[tokio::test]
    async fn a_receiver_inside_the_deployment_is_refused() {
        let server = receiver(ResponseTemplate::new(202)).await;

        let result = pushed(
            &server,
            &deliverer(UpstreamNetworks::public_only()),
            &ReceiverCredential::Omitted,
        )
        .await;

        assert!(matches!(result, Err(DomainError::Validation(_))));
        assert!(server.received_requests().await.unwrap().is_empty());
    }
}
