//! HubSpot as a workflow integration, installed under `hubspot`: a step
//! finds, reads, adds and changes contacts, companies and deals in
//! HubSpot's CRM, and lists the people records can be handed to, through
//! an account the tenant connected.
//!
//! The crate is a description handed to the SDK's
//! [`RestService`](ianua_integration::rest::service::RestService). A
//! HubSpot account holds a private app's access token, sent as a bearer
//! token only to the API, reaching only what the app was granted. A token
//! is proven by listing one contact, which every step's app may read.
//!
//! HubSpot publishes its API's descriptions only inside its developer
//! site, not at an address a test can fetch, so the steps follow its API
//! reference for CRM v3 and are held to the SDK's rules alone. Its
//! webhooks are set up in a public app's settings, not through the API, so
//! no workflow starts on them here.

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

/// HubSpot's public API.
pub const PUBLIC_API: &str = "https://api.hubapi.com/";

/// How the integration presents itself.
const PROFILE: ProfileText<'static> = ProfileText {
    title: "HubSpot",
    description: "Finds, adds and changes a team's HubSpot contacts, companies and deals, and hands deals to their owners, through an app token the tenant connects.",
    icon: "hubspot",
    picture: include_str!("../assets/icon.svg"),
    brand: "c1410d",
};

/// How the HubSpot integration is set up for this deployment.
#[derive(Debug, Clone)]
pub struct HubSpotSettings {
    /// Where HubSpot's API answers: [`PUBLIC_API`], or a stand-in's.
    pub endpoint: ServiceEndpoint,
    /// How long one call may take.
    pub timeout: Duration,
    /// The most sensitive data a step may send, and so the most sensitive
    /// an answer is counted as.
    pub ceiling: DataClassLevel,
}

/// The HubSpot integration, set up by `settings`.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when the client cannot be built,
/// and `DomainError::Validation` when the description breaks a rule.
pub fn integration(settings: HubSpotSettings) -> Result<RestService, DomainError> {
    RestService::new(RestServiceParams {
        key: "hubspot",
        profile: PROFILE,
        operations: operations::all().collect(),
        previews: &[],
        access: Access::Bearer {
            endpoint: settings.endpoint,
        },
        headers: &[],
        probe: Probe {
            verb: Verb::Get,
            path: &["crm", "v3", "objects", "contacts"],
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
    use ianua_integration::answer::flow_of;
    use serde_json::json;
    use wiremock::matchers::{body_json, header, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    /// A token as a test writes it: not shaped like a real one.
    const TOKEN: &str = "acme hubspot app token";

    fn hubspot(server: &MockServer) -> RestService {
        integration(HubSpotSettings {
            endpoint: ServiceEndpoint::at(&format!("{}/", server.uri())).unwrap(),
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
            integration: IntegrationKey::new("hubspot").unwrap(),
            operation: OperationKey::new(operation).unwrap(),
            account: ActionAccount::Account(IntegrationAccountId::new()),
            arguments,
            effect: DeclaredAction::Undeclared,
            exposure: DataClassLevel::Internal,
            origin: EventOrigin::Outside,
        }
    }

    /// Ann's workflow adds a contact: the token signs it, and the
    /// properties go as they were given.
    #[tokio::test]
    async fn a_contact_is_added_with_the_token() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/crm/v3/objects/contacts"))
            .and(header("authorization", format!("Bearer {TOKEN}").as_str()))
            .and(body_json(
                json!({ "properties": { "email": "ann@acme.test" } }),
            ))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({ "id": "51" })))
            .expect(1)
            .mount(&server)
            .await;
        let add = step(
            "create-contact",
            vec![(
                "properties",
                flow_of(&json!({ "email": "ann@acme.test" })).unwrap(),
            )],
        );

        let outcome = hubspot(&server).call(&add, Some(&token())).await.outcome;

        assert!(
            matches!(outcome, ActionOutcome::Succeeded { .. }),
            "{outcome:?}"
        );
    }

    /// HubSpot listing one contact for a token, answering `status`.
    async fn checked(status: u16) -> AccountCheck {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/crm/v3/objects/contacts"))
            .and(query_param("limit", "1"))
            .and(header("authorization", format!("Bearer {TOKEN}").as_str()))
            .respond_with(ResponseTemplate::new(status).set_body_json(json!({ "results": [] })))
            .mount(&server)
            .await;
        hubspot(&server).check_account(&token()).await
    }

    /// Tess connects the token: HubSpot lists a contact, so it is taken; a
    /// token it does not know, or one without the contacts scope, is
    /// refused, and HubSpot being down says nothing of it.
    #[tokio::test]
    async fn a_known_token_is_accepted_and_others_refused() {
        assert_eq!(checked(200).await, AccountCheck::Accepted);
        assert!(matches!(checked(401).await, AccountCheck::Refused(_)));
        assert!(matches!(checked(403).await, AccountCheck::Refused(_)));
        assert_eq!(checked(503).await, AccountCheck::Unreachable);
    }

    /// HubSpot presents itself with a title, icon and brand colour,
    /// explains every operation and starts no workflow.
    #[tokio::test]
    async fn hubspot_presents_itself_and_explains_its_operations() {
        let server = MockServer::start().await;
        let hubspot = hubspot(&server);

        assert_eq!(hubspot.profile().icon().as_str(), "hubspot");
        assert_eq!(hubspot.profile().brand().as_str(), "c1410d");
        assert_eq!(hubspot.guides().len(), hubspot.operations().len());
        assert!(hubspot.events().is_empty());
    }
}
