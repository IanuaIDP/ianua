//! Asking the API about agent approvals from the gateway, which never
//! writes one itself.
//!
//! Each question goes to the API's internal listener sealed under the key
//! the two derive for approvals alone, never the sign-in key, with the
//! time it was sent and a nonce used once. Deny by default: a refusal, an
//! answer to another question, one not sealed by the API for this
//! question, one that does not read or is too large, a status that is not a
//! success, or no answer in time, each is an error, and the gateway
//! refuses the action on it.

use std::time::Duration;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::agents::{
    APPROVAL_RELAY_PATH, APPROVAL_WIRE_VERSION, ApprovalBroker, ApprovalWireAnswer,
    ApprovalWireQuestion, ApprovalWireRequest, GatedAction, Held, Spending,
};
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;

use crate::crypto::{HmacRequestSeal, RootSecret};
use crate::http::client::InternalLink;
use crate::http::relay::{RelayEndpoint, RelayLimits, SealedRelay, fresh_nonce};

/// How many questions one gateway asks at once. A burst beyond it is
/// refused at once, and the actions behind it with it, rather than queued.
const IN_FLIGHT: usize = 64;

/// The largest answer read back. An answer is a few dozen bytes.
const ANSWER_BYTES: usize = 4 * 1024;

/// Relays the gateway's questions about approvals to the API over HTTP,
/// sealed.
pub struct HttpApprovalBroker {
    relay: SealedRelay,
}

impl HttpApprovalBroker {
    /// A broker asking the API's internal listener at `base_url`, each
    /// question held to `timeout`, sealing under the key `root` derives for
    /// approval questions.
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
        let seal = HmacRequestSeal::approvals(root);
        Ok(Self {
            relay: SealedRelay::new(
                RelayEndpoint {
                    base_url,
                    path: APPROVAL_RELAY_PATH,
                },
                seal,
                limits,
                link,
            )?,
        })
    }

    /// The API's answer to `question`, asked in `tenant_id`.
    async fn ask(
        &self,
        tenant_id: &ScopedTenant,
        question: ApprovalWireQuestion,
    ) -> Result<ApprovalWireAnswer, DomainError> {
        let request = ApprovalWireRequest {
            v: APPROVAL_WIRE_VERSION,
            tenant_id: **tenant_id,
            ts: clock::now().unix_timestamp(),
            nonce: fresh_nonce()?,
            question,
        };
        self.relay.ask(&request.nonce, &request).await
    }
}

impl TenantScoped for HttpApprovalBroker {}

#[async_trait]
impl ApprovalBroker for HttpApprovalBroker {
    async fn hold(
        &self,
        tenant_id: &ScopedTenant,
        action: &GatedAction,
    ) -> Result<Held, DomainError> {
        self.ask(tenant_id, ApprovalWireQuestion::Hold(action.into()))
            .await?
            .into_held()
    }

    async fn spend(
        &self,
        tenant_id: &ScopedTenant,
        action: &GatedAction,
    ) -> Result<Spending, DomainError> {
        self.ask(tenant_id, ApprovalWireQuestion::Spend(action.into()))
            .await?
            .into_spending()
    }
}

/// The approval broker of a gateway that was given no address of the API:
/// every question is an error, so an action waiting for a person's
/// approval is refused, never let through for want of anyone to ask.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoApprovalBroker;

impl TenantScoped for NoApprovalBroker {}

#[async_trait]
impl ApprovalBroker for NoApprovalBroker {
    async fn hold(
        &self,
        _tenant_id: &ScopedTenant,
        _action: &GatedAction,
    ) -> Result<Held, DomainError> {
        Err(unreachable_api())
    }

    async fn spend(
        &self,
        _tenant_id: &ScopedTenant,
        _action: &GatedAction,
    ) -> Result<Spending, DomainError> {
        Err(unreachable_api())
    }
}

/// Why a gateway with no address of the API answers no approval.
fn unreachable_api() -> DomainError {
    DomainError::infra_msg("the gateway was given no address of the API to ask approvals of")
}

#[cfg(test)]
mod tests {
    use ianua_app::ports::agents::RequestOpened;
    use ianua_app::ports::authentication::{RequestSeal, SEAL_HEADER};
    use ianua_domain::types::{
        AgentId, ApprovalId, DeclaredAction, DelegationId, HttpMethod, TenantId,
    };
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

    use super::*;
    use crate::crypto::keys::tests::test_root;
    use crate::http::relay::tests::SealingApi;

    fn payment() -> GatedAction {
        GatedAction {
            agent_id: AgentId::new(),
            delegation_id: DelegationId::new(),
            method: HttpMethod::Post,
            target: "/payments?amount=10".to_owned(),
            declared: DeclaredAction::Undeclared,
        }
    }

    fn acme() -> ScopedTenant {
        ScopedTenant::for_test(TenantId::new())
    }

    /// Without an API broker, both holding and spending an approval for a
    /// payment return errors.
    #[tokio::test]
    async fn with_no_api_every_approval_question_is_an_error() {
        let held = NoApprovalBroker.hold(&acme(), &payment()).await;
        let spent = NoApprovalBroker.spend(&acme(), &payment()).await;

        assert!(held.is_err());
        assert!(spent.is_err());
    }

    async fn api(response: impl Respond + 'static) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(APPROVAL_RELAY_PATH))
            .respond_with(response)
            .mount(&server)
            .await;
        server
    }

    /// The API answering `answer`, sealed for the question it answers.
    fn answering(answer: &serde_json::Value) -> SealingApi {
        SealingApi::new(
            HmacRequestSeal::approvals(&test_root()),
            "/nonce",
            answer.clone(),
        )
    }

    fn broker_for(server: &MockServer) -> HttpApprovalBroker {
        let base = url::Url::parse(&server.uri()).unwrap();
        HttpApprovalBroker::new(
            &base,
            Duration::from_secs(1),
            &test_root(),
            &InternalLink::PlainInDevelopment,
        )
        .unwrap()
    }

    /// The question the gateway sent, as the API received it.
    async fn received(server: &MockServer) -> (Request, ApprovalWireRequest) {
        let sent = server.received_requests().await.unwrap().remove(0);
        let request = serde_json::from_slice(&sent.body).unwrap();
        (sent, request)
    }

    /// The gateway asks to hold Ann's agent's payment. The question goes
    /// sealed under the approvals key, for Acme, recent and with a nonce,
    /// and the API's request reads back as newly opened.
    #[tokio::test]
    async fn a_hold_goes_sealed_and_reads_back_as_the_request() {
        let approval_id = ApprovalId::new();
        let server = api(answering(&serde_json::json!({
            "result": "awaiting_decision",
            "approval_id": approval_id,
            "opened": "now",
        })))
        .await;
        let tenant = acme();

        let held = broker_for(&server).hold(&tenant, &payment()).await.unwrap();

        assert_eq!(
            held,
            Held::AwaitingDecision {
                approval_id,
                opened: RequestOpened::Now
            }
        );
        let (sent, request) = received(&server).await;
        let seal = sent.headers.get(SEAL_HEADER).unwrap().to_str().unwrap();
        assert!(HmacRequestSeal::approvals(&test_root()).verifies(&sent.body, seal));
        assert_eq!(request.tenant_id, *tenant);
        assert!((clock::now().unix_timestamp() - request.ts).abs() <= 5);
        assert!(matches!(request.question, ApprovalWireQuestion::Hold(_)));
    }

    /// A successfully answered approval question carries a seal that does
    /// not verify under the sign-in key.
    #[tokio::test]
    async fn a_question_is_never_sealed_under_the_sign_in_key() {
        let server = api(answering(&serde_json::json!({"result": "spent"}))).await;

        broker_for(&server)
            .spend(&acme(), &payment())
            .await
            .unwrap();

        let (sent, _) = received(&server).await;
        let seal = sent.headers.get(SEAL_HEADER).unwrap().to_str().unwrap();
        assert!(!HmacRequestSeal::new(&test_root()).verifies(&sent.body, seal));
    }

    /// Two approval questions sent through one broker carry distinct nonces.
    #[tokio::test]
    async fn each_question_carries_its_own_nonce() {
        let server = api(answering(&serde_json::json!({"result": "none_granted"}))).await;
        let broker = broker_for(&server);

        broker.spend(&acme(), &payment()).await.unwrap();
        broker.spend(&acme(), &payment()).await.unwrap();

        let sent = server.received_requests().await.unwrap();
        let first: ApprovalWireRequest = serde_json::from_slice(&sent[0].body).unwrap();
        let second: ApprovalWireRequest = serde_json::from_slice(&sent[1].body).unwrap();
        assert_ne!(first.nonce, second.nonce);
    }

    /// The API's sealed refusal to spend an approval returns a forbidden
    /// error.
    #[tokio::test]
    async fn a_refusal_is_forbidden() {
        let server = api(answering(&serde_json::json!({"result": "refused"}))).await;

        let spending = broker_for(&server).spend(&acme(), &payment()).await;

        assert!(matches!(spending, Err(DomainError::Forbidden(_))));
    }

    /// An unknown approval result and a spend result answering a hold each
    /// return an infrastructure error, even with valid seals.
    #[tokio::test]
    async fn a_forged_answer_is_refused() {
        let made_up = api(answering(&serde_json::json!({"result": "approved"}))).await;
        let crossed = api(answering(&serde_json::json!({"result": "spent"}))).await;

        let spending = broker_for(&made_up).spend(&acme(), &payment()).await;
        let held = broker_for(&crossed).hold(&acme(), &payment()).await;

        assert!(matches!(spending, Err(DomainError::Infrastructure(_))));
        assert!(matches!(held, Err(DomainError::Infrastructure(_))));
    }

    /// An empty HTTP 401 response to a spend request returns an
    /// infrastructure error.
    #[tokio::test]
    async fn a_status_that_is_not_a_success_is_an_error() {
        let server = api(ResponseTemplate::new(401)).await;

        let spending = broker_for(&server).spend(&acme(), &payment()).await;

        assert!(matches!(spending, Err(DomainError::Infrastructure(_))));
    }

    /// A sealed spend result delayed beyond the broker timeout returns an
    /// infrastructure error.
    #[tokio::test]
    async fn a_late_answer_is_refused() {
        let server =
            api(answering(&serde_json::json!({"result": "spent"})).delayed(Duration::from_secs(3)))
                .await;

        let spending = broker_for(&server).spend(&acme(), &payment()).await;

        assert!(matches!(spending, Err(DomainError::Infrastructure(_))));
    }

    /// A well-formed spend result without the API's seal returns an
    /// infrastructure error.
    #[tokio::test]
    async fn an_answer_without_the_apis_seal_is_refused() {
        let server =
            api(ResponseTemplate::new(200).set_body_json(serde_json::json!({"result": "spent"})))
                .await;

        let spending = broker_for(&server).spend(&acme(), &payment()).await;

        assert!(matches!(spending, Err(DomainError::Infrastructure(_))));
    }

    /// A spend result sealed with the sign-in key returns an infrastructure
    /// error on the approvals channel.
    #[tokio::test]
    async fn an_answer_sealed_under_the_sign_in_key_is_refused() {
        let server = api(SealingApi::new(
            HmacRequestSeal::new(&test_root()),
            "/nonce",
            serde_json::json!({"result": "spent"}),
        ))
        .await;

        let spending = broker_for(&server).spend(&acme(), &payment()).await;

        assert!(matches!(spending, Err(DomainError::Infrastructure(_))));
    }
}
