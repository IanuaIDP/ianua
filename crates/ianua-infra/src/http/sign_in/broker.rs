//! Relaying the sign-ins the gateway answers on an app's host to the API's
//! internal listener, sealed with the key the two derive for app sign-in
//! alone.
//!
//! The API answers with a typed outcome, refusals included, sealed for the
//! request it answers. Anything else (a bare `401` for a request it did not
//! take, a status that is not a success, an answer not sealed for this
//! request, one that does not read or is too large, no answer in time) is
//! an error, and the gateway refuses the sign-in on it.

use std::time::Duration;

use async_trait::async_trait;
use ianua_app::ports::authentication::{AppSignInBroker, RELAY_PATH, WireOutcome, WireRequest};
use ianua_domain::shared::errors::DomainError;

use crate::crypto::{HmacRequestSeal, RootSecret};
use crate::http::client::InternalLink;
use crate::http::relay::{RelayEndpoint, RelayLimits, SealedRelay};

/// How many sign-ins one gateway relays at once. A burst beyond it is
/// refused at once rather than queued behind the password hashing it would
/// only add to.
const IN_FLIGHT: usize = 64;

/// The largest answer read back. An outcome is a few hundred bytes; a page
/// is a few kilobytes plus the workspace's CSS, up to 64 KiB of it, which
/// JSON may escape to several times its size.
const ANSWER_BYTES: usize = 512 * 1024;

/// Relays app sign-ins to the API over HTTP, sealed.
pub struct HttpAppSignInBroker {
    relay: SealedRelay,
}

impl HttpAppSignInBroker {
    /// A broker relaying to the API's internal listener at `base_url`, each
    /// sign-in held to `timeout`, sealing under the key `root` derives for
    /// app sign-in requests.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the address does not join
    /// or the client cannot be built.
    pub fn new(
        base_url: &url::Url,
        timeout: Duration,
        root: &RootSecret,
        link: &InternalLink,
    ) -> Result<Self, DomainError> {
        let limits = RelayLimits {
            timeout,
            in_flight: IN_FLIGHT,
            answer_bytes: ANSWER_BYTES,
        };
        let seal = HmacRequestSeal::new(root);
        Ok(Self {
            relay: SealedRelay::new(
                RelayEndpoint {
                    base_url,
                    path: RELAY_PATH,
                },
                seal,
                limits,
                link,
            )?,
        })
    }
}

#[async_trait]
impl AppSignInBroker for HttpAppSignInBroker {
    async fn submit(&self, request: WireRequest) -> Result<WireOutcome, DomainError> {
        self.relay.ask(&request.ctx.nonce, &request).await
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::ports::authentication::{
        RequestSeal, SEAL_HEADER, WIRE_VERSION, WireCommand, WireContext,
    };
    use ianua_domain::shared::clock;
    use ianua_domain::types::{DomainName, Nonce, ServiceId, TenantId};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

    use super::*;
    use crate::crypto::keys::tests::test_root;
    use crate::http::relay::tests::SealingApi;

    fn sign_out() -> WireRequest {
        WireRequest {
            v: WIRE_VERSION,
            ctx: WireContext {
                tenant_id: TenantId::new(),
                service_id: ServiceId::new(),
                host: DomainName::new("shop.example.com").unwrap(),
                client_ip: Some("203.0.113.7".to_owned()),
                user_agent: None,
                accept_language: None,
                ts: clock::now().unix_timestamp(),
                nonce: Nonce::new("a-nonce-used-only-once").unwrap(),
            },
            command: WireCommand::LogOut { session: None },
        }
    }

    async fn api(response: impl Respond + 'static) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(RELAY_PATH))
            .respond_with(response)
            .mount(&server)
            .await;
        server
    }

    /// The API answering `answer`, sealed for the request it answers.
    fn answering(answer: serde_json::Value) -> SealingApi {
        SealingApi::new(HmacRequestSeal::new(&test_root()), "/ctx/nonce", answer)
    }

    fn broker_for(server: &MockServer) -> HttpAppSignInBroker {
        let base = url::Url::parse(&server.uri()).unwrap();
        HttpAppSignInBroker::new(
            &base,
            Duration::from_secs(1),
            &test_root(),
            &InternalLink::PlainInDevelopment,
        )
        .unwrap()
    }

    /// The sign-out goes to the relay path sealed under the sign-in key,
    /// and the API's outcome, sealed for it, reads back.
    #[tokio::test]
    async fn a_sign_in_is_relayed_sealed_and_its_outcome_reads_back() {
        let server = api(answering(serde_json::json!({"result": "signed_out"}))).await;

        let outcome = broker_for(&server).submit(sign_out()).await.unwrap();

        assert!(matches!(outcome, WireOutcome::SignedOut));
        let sent: Vec<Request> = server.received_requests().await.unwrap();
        let seal = sent[0].headers.get(SEAL_HEADER).unwrap().to_str().unwrap();
        assert!(HmacRequestSeal::new(&test_root()).verifies(&sent[0].body, seal));
        assert!(!HmacRequestSeal::approvals(&test_root()).verifies(&sent[0].body, seal));
    }

    /// An empty HTTP 401 response to a sign-out request returns an
    /// infrastructure error.
    #[tokio::test]
    async fn an_unsealed_answer_is_an_error() {
        let server = api(ResponseTemplate::new(401)).await;

        let outcome = broker_for(&server).submit(sign_out()).await;

        assert!(matches!(outcome, Err(DomainError::Infrastructure(_))));
    }

    /// A sealed answer containing an unknown outcome returns an infrastructure
    /// error.
    #[tokio::test]
    async fn an_answer_that_is_no_outcome_is_an_error() {
        let server = api(answering(serde_json::json!({"result": "welcome"}))).await;

        let outcome = broker_for(&server).submit(sign_out()).await;

        assert!(matches!(outcome, Err(DomainError::Infrastructure(_))));
    }

    /// A well-formed signed-out result without the API's seal returns an
    /// infrastructure error.
    #[tokio::test]
    async fn an_outcome_without_the_apis_seal_is_refused() {
        let server =
            api(ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"result": "signed_out"})))
            .await;

        let outcome = broker_for(&server).submit(sign_out()).await;

        assert!(matches!(outcome, Err(DomainError::Infrastructure(_))));
    }

    /// A sealed outcome delayed beyond the broker timeout returns an
    /// infrastructure error.
    #[tokio::test]
    async fn a_late_outcome_is_given_up_on() {
        let server =
            api(answering(serde_json::json!({"result": "signed_out"}))
                .delayed(Duration::from_secs(3)))
            .await;

        let outcome = broker_for(&server).submit(sign_out()).await;

        assert!(matches!(outcome, Err(DomainError::Infrastructure(_))));
    }
}
