//! Airtable as a workflow integration, installed under `airtable`: a step
//! lists the bases and tables a token reaches, and finds, reads, adds,
//! changes and deletes records, through an account the tenant connected.
//!
//! The crate is a description handed to the SDK's
//! [`RestService`](ianua_integration::rest::service::RestService). An
//! Airtable account holds a personal access token, sent as a bearer token
//! only to the API, reaching only the bases it was granted. A token is
//! proven by asking Airtable whose it is.
//!
//! Airtable publishes no OpenAPI description of its API, so the steps
//! follow its API reference and are held to the SDK's rules alone. Its
//! webhooks announce changes without their contents, which must be read
//! through another call, so no workflow starts on them here.

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

/// Airtable's public API.
pub const PUBLIC_API: &str = "https://api.airtable.com/v0/";

/// How the integration presents itself.
const PROFILE: ProfileText<'static> = ProfileText {
    title: "Airtable",
    description: "Finds, adds, changes and deletes records in a team's Airtable bases, through a token the tenant connects.",
    icon: "airtable",
    picture: include_str!("../assets/icon.svg"),
    brand: "166ee1",
};

/// How the Airtable integration is set up for this deployment.
#[derive(Debug, Clone)]
pub struct AirtableSettings {
    /// Where Airtable's API answers: [`PUBLIC_API`], or a stand-in's.
    pub endpoint: ServiceEndpoint,
    /// How long one call may take.
    pub timeout: Duration,
    /// The most sensitive data a step may send, and so the most sensitive
    /// an answer is counted as.
    pub ceiling: DataClassLevel,
}

/// The Airtable integration, set up by `settings`.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when the client cannot be built,
/// and `DomainError::Validation` when the description breaks a rule.
pub fn integration(settings: AirtableSettings) -> Result<RestService, DomainError> {
    RestService::new(RestServiceParams {
        key: "airtable",
        profile: PROFILE,
        operations: operations::all().collect(),
        previews: &[],
        access: Access::Bearer {
            endpoint: settings.endpoint,
        },
        headers: &[],
        probe: Probe {
            verb: Verb::Get,
            path: &["meta", "whoami"],
            query: &[],
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
    use serde_json::json;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    /// A token as a test writes it: not shaped like a real one.
    const TOKEN: &str = "acme airtable token for workflows";

    fn airtable(server: &MockServer) -> RestService {
        integration(AirtableSettings {
            endpoint: ServiceEndpoint::at(&format!("{}/v0/", server.uri())).unwrap(),
            timeout: Duration::from_secs(2),
            ceiling: DataClassLevel::Internal,
        })
        .unwrap()
    }

    fn token() -> Secret {
        Secret::new(TOKEN.to_owned())
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
            integration: IntegrationKey::new("airtable").unwrap(),
            operation: OperationKey::new(operation).unwrap(),
            account: ActionAccount::Account(IntegrationAccountId::new()),
            arguments,
            effect: DeclaredAction::Undeclared,
            exposure: DataClassLevel::Internal,
            origin: EventOrigin::Outside,
        }
    }

    /// Ann's workflow reads a record: the token signs it, and Airtable's
    /// answer is the step's output.
    #[tokio::test]
    async fn a_record_is_read_with_the_token() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v0/appOrders/tblPeople/recAnn"))
            .and(header("authorization", format!("Bearer {TOKEN}").as_str()))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": "recAnn", "fields": { "Name": "Ann" }
            })))
            .expect(1)
            .mount(&server)
            .await;
        let read = step(
            "get-record",
            vec![
                ("base", FlowData::text("appOrders").unwrap()),
                ("table", FlowData::text("tblPeople").unwrap()),
                ("record", FlowData::text("recAnn").unwrap()),
            ],
        );

        let outcome = airtable(&server).call(&read, Some(&token())).await.outcome;

        assert!(
            matches!(outcome, ActionOutcome::Succeeded { .. }),
            "{outcome:?}"
        );
    }

    /// Airtable saying whose a token is, answering `status`.
    async fn checked(status: u16) -> AccountCheck {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v0/meta/whoami"))
            .and(header("authorization", format!("Bearer {TOKEN}").as_str()))
            .respond_with(ResponseTemplate::new(status).set_body_json(json!({ "id": "usrAnn" })))
            .mount(&server)
            .await;
        airtable(&server).check_account(&token()).await
    }

    /// Tess connects the token: Airtable knows whose it is, so it is taken;
    /// a token it does not know is refused, and Airtable being down says
    /// nothing of it.
    #[tokio::test]
    async fn a_known_token_is_accepted_and_an_unknown_one_refused() {
        assert_eq!(checked(200).await, AccountCheck::Accepted);
        assert!(matches!(checked(401).await, AccountCheck::Refused(_)));
        assert_eq!(checked(503).await, AccountCheck::Unreachable);
    }

    /// Airtable presents itself with a title, icon and brand colour,
    /// explains every operation and starts no workflow.
    #[tokio::test]
    async fn airtable_presents_itself_and_explains_its_operations() {
        let server = MockServer::start().await;
        let airtable = airtable(&server);

        assert_eq!(airtable.profile().icon().as_str(), "airtable");
        assert_eq!(airtable.profile().brand().as_str(), "166ee1");
        assert_eq!(airtable.guides().len(), airtable.operations().len());
        assert!(airtable.events().is_empty());
    }
}
