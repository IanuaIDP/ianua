//! Stripe as a workflow integration, installed under `stripe`: a step
//! finds, reads, adds and changes customers, reads payments, refunds one,
//! lists and sends invoices, and lists and cancels subscriptions, through
//! an account the tenant connected.
//!
//! The crate is a description handed to the SDK's
//! [`RestService`](ianua_integration::rest::service::RestService). A
//! Stripe account holds a secret or restricted key, sent as a bearer token
//! only to the API, every call pinned to the API version the steps were
//! checked against. A key is proven by listing one customer, which a
//! restricted key reading customers may do.
//!
//! Refunds, sending invoices and cancelling subscriptions move money or
//! change billing, so they are financial and need an approval before them.
//! Stripe chooses each webhook's signing secret itself and shows it once,
//! which registrations cannot keep yet, so no workflow starts on Stripe's
//! events.

#![cfg_attr(not(test), warn(clippy::too_many_lines))]

mod operations;

use std::time::Duration;

use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::shared::errors::DomainError;
use ianua_integration::ServiceEndpoint;
use ianua_integration::describe::ProfileText;
use ianua_integration::rest::access::Access;
use ianua_integration::rest::operation::Verb;
use ianua_integration::rest::service::{Answers, Probe, RestService, RestServiceParams};

/// Stripe's public API.
pub const PUBLIC_API: &str = "https://api.stripe.com/v1/";

/// The API version every call is pinned to: the one the steps were checked
/// against.
const VERSION: &str = "2026-09-30.endive";

/// How the integration presents itself.
const PROFILE: ProfileText<'static> = ProfileText {
    title: "Stripe",
    description: "Finds and keeps a team's Stripe customers, reads payments, refunds them, sends invoices and cancels subscriptions, through a key the tenant connects.",
    icon: "stripe",
    picture: include_str!("../assets/icon.svg"),
    brand: "635bff",
};

/// How the Stripe integration is set up for this deployment.
#[derive(Debug, Clone)]
pub struct StripeSettings {
    /// Where Stripe's API answers: [`PUBLIC_API`], or a stand-in's.
    pub endpoint: ServiceEndpoint,
    /// How long one call may take.
    pub timeout: Duration,
    /// The most sensitive data a step may send, and so the most sensitive
    /// an answer is counted as.
    pub ceiling: DataClassLevel,
}

/// The Stripe integration, set up by `settings`.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when the client cannot be built,
/// and `DomainError::Validation` when the description breaks a rule.
pub fn integration(settings: StripeSettings) -> Result<RestService, DomainError> {
    RestService::new(RestServiceParams {
        key: "stripe",
        profile: PROFILE,
        operations: operations::all().collect(),
        previews: &[],
        access: Access::Bearer {
            endpoint: settings.endpoint,
        },
        headers: &[("stripe-version", VERSION)],
        probe: Probe {
            verb: Verb::Get,
            path: &["customers"],
            query: &[("limit", "1")],
        },
        answers: Answers::ByStatus,
        timeout: settings.timeout,
        ceiling: settings.ceiling,
        sign_in: None,
        events: None,
    })
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::workflows::data::{FieldName, FlowData};
    use ianua_domain::domains::workflows::execution::ActionCall;
    use ianua_domain::domains::workflows::execution::step::ActionOutcome;
    use ianua_domain::domains::workflows::integration::account_check::AccountCheck;
    use ianua_domain::domains::workflows::integration::{
        ActionAccount, IntegrationKey, OperationKey,
    };
    use ianua_domain::shared::events::chain::EventOrigin;
    use ianua_domain::shared::security::secret::Secret;
    use ianua_domain::types::{ActionCallId, DeclaredAction, IntegrationAccountId};
    use ianua_integration::Integration;
    use ianua_integration::rest::openapi::Description;
    use serde_json::json;
    use wiremock::matchers::{body_string, header, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::operations::all;

    /// Stripe's own description of its API, which every operation is
    /// checked against. Stripe publishes it at
    /// `stripe/openapi/openapi/spec3.json`; what the operations use of it is
    /// kept in `api-description.json`. To refresh it, download the file and
    /// run the tests with `IANUA_STRIPE_API_DESCRIPTION=/path/to/spec3.json`,
    /// then pin [`VERSION`] to its `info.version`.
    fn description() -> Description {
        Description {
            kept: std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("api-description.json"),
            setting: "IANUA_STRIPE_API_DESCRIPTION",
            lead: &["v1"],
        }
    }

    /// Every operation calls an endpoint Stripe describes, with only the
    /// parameters and form fields it knows, always sending those it
    /// requires, and promising only outputs its answer carries; and the
    /// extract holds exactly those endpoints.
    #[test]
    fn every_operation_fits_stripes_api_description() {
        let description = description();
        let extract = description.extract(all()).unwrap();

        let wrong = description.misfits(all(), &extract);

        assert!(wrong.is_empty(), "{}", wrong.join("\n"));
        assert_eq!(
            Description::kept_endpoints(&extract),
            Description::called_endpoints(all()),
            "refresh the extract with IANUA_STRIPE_API_DESCRIPTION"
        );
    }

    /// A key as a test writes it: not shaped like a real one.
    const KEY: &str = "acme stripe key for workflows";

    fn stripe(server: &MockServer) -> RestService {
        integration(StripeSettings {
            endpoint: ServiceEndpoint::at(&format!("{}/v1/", server.uri())).unwrap(),
            timeout: Duration::from_secs(2),
            ceiling: DataClassLevel::Internal,
        })
        .unwrap()
    }

    fn key() -> Secret {
        Secret::new(KEY.to_owned())
    }

    fn step(operation: &str, entries: Vec<(&str, FlowData)>) -> ActionCall {
        let arguments = FlowData::map(
            entries
                .into_iter()
                .map(|(name, value)| (FieldName::new(name).unwrap(), value))
                .collect(),
        )
        .unwrap();
        ActionCall {
            call_id: ActionCallId::new(),
            integration: IntegrationKey::new("stripe").unwrap(),
            operation: OperationKey::new(operation).unwrap(),
            account: ActionAccount::Account(IntegrationAccountId::new()),
            arguments,
            effect: DeclaredAction::Undeclared,
            exposure: DataClassLevel::Internal,
            origin: EventOrigin::Outside,
        }
    }

    /// Tess's approved workflow refunds a payment: the key signs it, the
    /// API version is pinned, and the payment goes as a form.
    #[tokio::test]
    async fn a_refund_is_sent_with_the_key_and_the_pinned_version() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/refunds"))
            .and(header("authorization", format!("Bearer {KEY}").as_str()))
            .and(header("stripe-version", VERSION))
            .and(header("content-type", "application/x-www-form-urlencoded"))
            .and(body_string("payment_intent=pi_123"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({ "id": "re_1", "status": "succeeded" })),
            )
            .expect(1)
            .mount(&server)
            .await;
        let refund = step(
            "refund-payment",
            vec![("payment", FlowData::text("pi_123").unwrap())],
        );

        let outcome = stripe(&server).call(&refund, Some(&key())).await.outcome;

        assert!(
            matches!(outcome, ActionOutcome::Succeeded { .. }),
            "{outcome:?}"
        );
    }

    /// Stripe's HTTP refusal fails the refund step, while rate limiting
    /// turns it away for a later attempt.
    #[tokio::test]
    async fn a_refusal_fails_and_a_rate_limit_turns_away() {
        let refusing = MockServer::start().await;
        Mock::given(path("/v1/refunds"))
            .respond_with(ResponseTemplate::new(400))
            .mount(&refusing)
            .await;
        let busy = MockServer::start().await;
        Mock::given(path("/v1/refunds"))
            .respond_with(ResponseTemplate::new(429))
            .mount(&busy)
            .await;
        let refund = step(
            "refund-payment",
            vec![("payment", FlowData::text("pi_123").unwrap())],
        );

        let refused = stripe(&refusing).call(&refund, Some(&key())).await.outcome;
        let limited = stripe(&busy).call(&refund, Some(&key())).await.outcome;

        assert!(matches!(refused, ActionOutcome::Failed(_)));
        assert!(matches!(limited, ActionOutcome::TurnedAway(_)));
    }

    /// Stripe listing one customer for a key, answering `status`.
    async fn checked(status: u16) -> AccountCheck {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/customers"))
            .and(query_param("limit", "1"))
            .and(header("authorization", format!("Bearer {KEY}").as_str()))
            .respond_with(ResponseTemplate::new(status).set_body_json(json!({ "data": [] })))
            .mount(&server)
            .await;
        stripe(&server).check_account(&key()).await
    }

    /// Tess connects the key: Stripe lists a customer, so it is taken; a
    /// key Stripe does not know is refused, and Stripe being down says
    /// nothing of it.
    #[tokio::test]
    async fn a_known_key_is_accepted_and_an_unknown_one_refused() {
        assert_eq!(checked(200).await, AccountCheck::Accepted);
        assert!(matches!(checked(401).await, AccountCheck::Refused(_)));
        assert_eq!(checked(503).await, AccountCheck::Unreachable);
    }

    /// Stripe presents itself with a title, icon and brand colour, explains
    /// every operation and starts no workflow.
    #[tokio::test]
    async fn stripe_presents_itself_and_explains_its_operations() {
        let server = MockServer::start().await;
        let stripe = stripe(&server);

        assert_eq!(stripe.profile().icon().as_str(), "stripe");
        assert_eq!(stripe.profile().brand().as_str(), "635bff");
        assert_eq!(stripe.guides().len(), stripe.operations().len());
        assert!(stripe.events().is_empty());
    }
}
