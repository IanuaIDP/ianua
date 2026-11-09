//! Salesforce as a workflow integration, installed under `salesforce`: a
//! step finds records with SOQL, reads, adds, changes and deletes records
//! of any kind of object, and adds leads, tasks and cases, through an
//! account the tenant connected.
//!
//! The crate is a description handed to the SDK's
//! [`RestService`](ianua_integration::rest::service::RestService). A
//! Salesforce account holds `{"site", "client_id", "client_secret",
//! "refresh_token"}`: the company's own domain, such as
//! `https://acme.my.salesforce.com`, and a connected app's grant. Before
//! each call the grant is exchanged at the deployment's token address for
//! a short-lived token, which alone goes to the domain's REST API, version
//! 62.0. The domain must be one the deployment allows, every
//! `*.my.salesforce.com` by default, so a token never reaches an address
//! an account made up. A grant is proven by listing the org's kinds of
//! object.
//!
//! Salesforce publishes no OpenAPI description of its REST API outside an
//! org, so the steps follow its reference and are held to the SDK's rules
//! alone. Its outbound messages are set up inside the org, not through the
//! API, so no workflow starts on them here.

#![cfg_attr(not(test), warn(clippy::too_many_lines))]

mod operations;

use std::time::Duration;

use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::shared::errors::DomainError;
use ianua_integration::ServiceEndpoint;
use ianua_integration::describe::ProfileText;
use ianua_integration::rest::access::{Access, AllowedSites};
use ianua_integration::rest::operation::Verb;
use ianua_integration::rest::service::{Answers, Probe, RestService, RestServiceParams};

/// Salesforce's token address, where a grant is exchanged for a token.
pub const PUBLIC_TOKEN: &str = "https://login.salesforce.com/services/oauth2/token";

/// The REST API's path under a domain.
const API: &[&str] = &["services", "data", "v62.0"];

/// How the integration presents itself.
const PROFILE: ProfileText<'static> = ProfileText {
    title: "Salesforce",
    description: "Finds, adds and changes records in a company's Salesforce org, and adds leads, tasks and cases, through a connected app's grant the tenant connects.",
    icon: "salesforce",
    picture: include_str!("../assets/icon.svg"),
    brand: "0b5cab",
};

/// How the Salesforce integration is set up for this deployment.
#[derive(Debug, Clone)]
pub struct SalesforceSettings {
    /// The domains an account may name.
    pub sites: AllowedSites,
    /// Where a grant is exchanged for a token: [`PUBLIC_TOKEN`], or a
    /// stand-in's.
    pub token: ServiceEndpoint,
    /// How long one call may take.
    pub timeout: Duration,
    /// The most sensitive data a step may send, and so the most sensitive
    /// an answer is counted as.
    pub ceiling: DataClassLevel,
}

/// The Salesforce integration, set up by `settings`.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when the client cannot be built,
/// and `DomainError::Validation` when the description breaks a rule.
pub fn integration(settings: SalesforceSettings) -> Result<RestService, DomainError> {
    RestService::new(RestServiceParams {
        key: "salesforce",
        profile: PROFILE,
        operations: operations::all().collect(),
        previews: &[],
        access: Access::SiteGrant {
            sites: settings.sites,
            api: API,
            token: settings.token,
        },
        headers: &[],
        probe: Probe {
            verb: Verb::Get,
            path: &["sobjects"],
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
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    /// The domains the test deployment allows a connected account to name.
    const PUBLIC_SITES: &str = ".my.salesforce.com";

    fn salesforce(token: &MockServer) -> RestService {
        integration(SalesforceSettings {
            sites: AllowedSites::new([PUBLIC_SITES]),
            token: ServiceEndpoint::at(&format!("{}/token", token.uri())).unwrap(),
            timeout: Duration::from_secs(2),
            ceiling: DataClassLevel::Internal,
        })
        .unwrap()
    }

    /// A grant as a test writes it, for a domain named `site`: not shaped
    /// like a real one.
    fn grant(site: &str) -> Secret {
        Secret::new(
            json!({
                "site": site,
                "client_id": "acme app",
                "client_secret": "app words",
                "refresh_token": "lasting grant"
            })
            .to_string(),
        )
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
            integration: IntegrationKey::new("salesforce").unwrap(),
            operation: OperationKey::new(operation).unwrap(),
            account: ActionAccount::Account(IntegrationAccountId::new()),
            arguments,
            effect: DeclaredAction::Undeclared,
            exposure: DataClassLevel::Internal,
            origin: EventOrigin::Outside,
        }
    }

    /// An account naming a disallowed Salesforce domain fails the step
    /// without contacting the token endpoint.
    #[tokio::test]
    async fn an_account_naming_another_domain_sends_nothing() {
        let token = MockServer::start().await;
        let lead = step(
            "create-lead",
            vec![
                ("last_name", FlowData::text("Lovelace").unwrap()),
                ("company", FlowData::text("Acme").unwrap()),
            ],
        );

        let outcome = salesforce(&token)
            .call(&lead, Some(&grant("https://crm.evil.test")))
            .await
            .outcome;

        assert!(matches!(outcome, ActionOutcome::Failed(_)));
        assert_eq!(token.received_requests().await.unwrap().len(), 0);
    }

    /// A rejected Salesforce grant fails the account check, while a busy
    /// token endpoint reports the account as unreachable.
    #[tokio::test]
    async fn a_revoked_grant_is_refused_and_a_down_token_address_says_nothing() {
        let revoked = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(400))
            .mount(&revoked)
            .await;
        let down = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&down)
            .await;
        let acme = grant("https://acme.my.salesforce.com");

        let refused = salesforce(&revoked).check_account(&acme).await;
        let unknown = salesforce(&down).check_account(&acme).await;

        assert!(matches!(refused, AccountCheck::Refused(_)));
        assert_eq!(unknown, AccountCheck::Unreachable);
    }

    /// Salesforce presents itself with a title, icon and brand colour,
    /// explains every operation and starts no workflow.
    #[tokio::test]
    async fn salesforce_presents_itself_and_explains_its_operations() {
        let token = MockServer::start().await;
        let salesforce = salesforce(&token);

        assert_eq!(salesforce.profile().icon().as_str(), "salesforce");
        assert_eq!(salesforce.profile().brand().as_str(), "0b5cab");
        assert_eq!(salesforce.guides().len(), salesforce.operations().len());
        assert!(salesforce.events().is_empty());
    }
}
