//! Azure DevOps as a workflow integration, installed under `azure-devops`:
//! a step creates, reads, edits, deletes, comments on and finds work items,
//! starts and reads pipeline runs, and opens and reads pull requests,
//! through an account the tenant connected.
//!
//! The crate is a description handed to the SDK's
//! [`RestService`](ianua_integration::rest::service::RestService). An
//! account holds `{"organization", "token"}`: the organization's name, as
//! in `dev.azure.com/acme`, and a personal access token. Calls go only to
//! the Azure DevOps address the deployment names, with the organization's
//! name after it, and every part of a step's path is checked and escaped.
//! Azure DevOps answers a token it does not know with a sign-in page and
//! a `203`, which the SDK never counts as success.
//!
//! Microsoft no longer publishes a machine-readable description of the
//! API, so the steps follow its REST reference for version 7.1 and are
//! held to it by tests against a stand-in and the optional live scenario.
//!
//! With the deployment's app in Microsoft Entra set, a person connects an
//! account by signing in with their work account instead, naming the
//! organization; the account keeps it beside a grant exchanged for a token
//! before each call, keeping the refresh token Microsoft replaces. A
//! workflow may also start when a work item is created in a project
//! (`events`), through a service hook added with the account.

#![cfg_attr(not(test), warn(clippy::too_many_lines))]

mod events;
mod operations;

use std::time::Duration;

use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::domains::workflows::integration::form::{PreviewKind, PreviewPart};
use ianua_domain::shared::errors::DomainError;
use ianua_integration::ServiceEndpoint;
use ianua_integration::connect::SignIn;
use ianua_integration::describe::ProfileText;
use ianua_integration::form::PreviewText;
use ianua_integration::rest::access::Access;
use ianua_integration::rest::event::ServiceEvents;
use ianua_integration::rest::grant::GrantAt;
use ianua_integration::rest::operation::Verb;
use ianua_integration::rest::service::{Answers, Probe, RestService, RestServiceParams};
use ianua_integration::rest::sign_in::{
    Keeps, OAuthSignIn, OAuthSignInParams, SignInSettings, TokenBody,
};
use ianua_integration::rest::watch::WatchCalls;

use crate::events::ServiceHooks;

/// Azure DevOps' public address, before an organization's name.
pub const PUBLIC_API: &str = "https://dev.azure.com/";

/// How the integration presents itself.
const PROFILE: ProfileText<'static> = ProfileText {
    title: "Azure DevOps",
    description: "Creates and updates work items, starts pipelines and opens pull requests in a team's Azure DevOps organization, through a personal access token the tenant connects.",
    icon: "azure-devops",
    picture: include_str!("../assets/icon.svg"),
    brand: "0078d4",
};

/// How creating a work item is previewed: as Azure Boards shows one.
const PREVIEWS: &[PreviewText] = &[PreviewText {
    operation: "create-work-item",
    kind: PreviewKind::Issue,
    parts: &[
        (PreviewPart::Place, "project"),
        (PreviewPart::Title, "title"),
        (PreviewPart::Body, "description"),
        (PreviewPart::Labels, "tags"),
    ],
}];

/// How the Azure DevOps integration is set up for this deployment.
#[derive(Debug, Clone)]
pub struct AzureDevOpsSettings {
    /// Where Azure DevOps answers, before an organization's name:
    /// [`PUBLIC_API`], or a stand-in's.
    pub endpoint: ServiceEndpoint,
    /// How long one call may take.
    pub timeout: Duration,
    /// The most sensitive data a step may send, and so the most sensitive
    /// an answer or an event is counted as.
    pub ceiling: DataClassLevel,
    /// The deployment's app in Microsoft Entra, at [`PUBLIC_AUTHORIZE`] and
    /// [`PUBLIC_TOKEN`] or a stand-in's, when one is registered; without
    /// it, accounts are connected with a personal access token pasted in.
    pub sign_in: Option<SignInSettings>,
}

/// Where Microsoft Entra signs people of any work or school directory in.
pub const PUBLIC_AUTHORIZE: &str =
    "https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize";

/// Where Microsoft Entra swaps codes and exchanges grants.
pub const PUBLIC_TOKEN: &str = "https://login.microsoftonline.com/organizations/oauth2/v2.0/token";

/// Azure DevOps' resource in Microsoft Entra, with every permission the
/// signed-in person holds there.
const RESOURCE_SCOPE: &str = "499b84ac-1321-427f-aa17-267ca6975798/.default";

/// The scopes a signed-in account asks for: Azure DevOps, and a grant
/// that lasts.
const SCOPES: &[&str] = &[RESOURCE_SCOPE, "offline_access"];

/// The scope Microsoft asks to be named again when a code is swapped and
/// a grant exchanged.
const SWAP_SCOPE: &str = "499b84ac-1321-427f-aa17-267ca6975798/.default offline_access";

/// The headers every call carries.
const HEADERS: &[(&str, &str)] = &[("accept", "application/json")];

/// The Azure DevOps integration, set up by `settings`.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when the client cannot be built,
/// and `DomainError::Validation` when the description breaks a rule.
pub fn integration(settings: AzureDevOpsSettings) -> Result<RestService, DomainError> {
    let access = Access::Organization {
        base: settings.endpoint,
        signed_in: settings.sign_in.as_ref().map(|at| GrantAt {
            token: at.token.clone(),
            body: TokenBody::Form,
            scope: Some(SWAP_SCOPE),
        }),
    };
    let events = service_events(&access, settings.timeout, settings.ceiling)?;
    RestService::new(RestServiceParams {
        key: "azure-devops",
        profile: PROFILE,
        operations: operations::all().collect(),
        previews: PREVIEWS,
        access,
        headers: HEADERS,
        probe: Probe {
            verb: Verb::Get,
            path: &["_apis", "projects"],
            query: &[("api-version", "7.1"), ("$top", "1")],
        },
        answers: Answers::ByStatus,
        timeout: settings.timeout,
        ceiling: settings.ceiling,
        sign_in: settings
            .sign_in
            .map(|at| sign_in(at, settings.timeout))
            .transpose()?,
        events: Some(events),
    })
}

/// Describes service-hook events and builds their client with the same account access.
fn service_events(
    access: &Access,
    timeout: Duration,
    ceiling: DataClassLevel,
) -> Result<ServiceEvents, DomainError> {
    let hooks = ServiceHooks::new(WatchCalls::new(access.clone(), HEADERS, timeout)?, ceiling);
    Ok(ServiceEvents {
        described: events::all(),
        watcher: Box::new(hooks),
    })
}

/// Signing in through Microsoft Entra with the deployment's app `at`; the
/// person names the organization, which the account keeps beside its
/// grant.
fn sign_in(at: SignInSettings, timeout: Duration) -> Result<Box<dyn SignIn>, DomainError> {
    let oauth = OAuthSignIn::new(OAuthSignInParams {
        at,
        scopes: SCOPES,
        scope_separator: " ",
        extra: &[],
        swap_extra: &[("scope", SWAP_SCOPE)],
        token_body: TokenBody::Form,
        keeps: Keeps::RefreshGrant,
        place: Some("organization"),
        timeout,
    })?;
    Ok(Box::new(oauth))
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
    use wiremock::matchers::{header, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    /// The account as a test writes it: not shaped like a real token.
    const ACCOUNT: &str = r#"{"organization": "acme", "token": "test token for acme"}"#;

    fn azure(server: &MockServer) -> RestService {
        integration(AzureDevOpsSettings {
            endpoint: ServiceEndpoint::at(&format!("{}/", server.uri())).unwrap(),
            timeout: Duration::from_secs(2),
            ceiling: DataClassLevel::Internal,
            sign_in: None,
        })
        .unwrap()
    }

    fn account() -> Secret {
        Secret::new(ACCOUNT.to_owned())
    }

    fn new_bug() -> ActionCall {
        let arguments = FlowData::map(
            [
                ("project", "Web"),
                ("type", "Bug"),
                ("title", "Login fails"),
            ]
            .into_iter()
            .map(|(name, value)| {
                (
                    FieldName::new(name).unwrap(),
                    FlowData::text(value).unwrap(),
                )
            })
            .collect(),
        )
        .unwrap();
        ActionCall {
            call_id: ActionCallId::new(),
            integration: IntegrationKey::new("azure-devops").unwrap(),
            operation: OperationKey::new("create-work-item").unwrap(),
            account: ActionAccount::Account(IntegrationAccountId::new()),
            arguments,
            effect: DeclaredAction::Undeclared,
            exposure: DataClassLevel::Internal,
            origin: EventOrigin::Outside,
        }
    }

    /// Ann's workflow files a bug in the Web project: Azure DevOps is asked
    /// at the organization, with the token as a password and the fields as
    /// a JSON Patch.
    #[tokio::test]
    async fn a_bug_is_filed_in_the_organization() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/acme/Web/_apis/wit/workitems/$Bug"))
            .and(query_param("api-version", "7.1"))
            .and(header("content-type", "application/json-patch+json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "id": 42 })))
            .expect(1)
            .mount(&server)
            .await;

        let outcome = azure(&server)
            .call(&new_bug(), Some(&account()))
            .await
            .outcome;

        assert!(
            matches!(outcome, ActionOutcome::Succeeded { .. }),
            "{outcome:?}"
        );
        let sent = &server.received_requests().await.unwrap()[0];
        let authorization = sent.headers.get("authorization").unwrap().to_str().unwrap();
        assert!(authorization.starts_with("Basic "), "{authorization}");
    }

    /// A sign-in page returned with HTTP 203 refuses the account check and
    /// fails the work-item step.
    #[tokio::test]
    async fn a_sign_in_page_is_never_success() {
        let server = MockServer::start().await;
        Mock::given(path("/acme/_apis/projects"))
            .respond_with(ResponseTemplate::new(203).set_body_string("<html>Sign in</html>"))
            .mount(&server)
            .await;
        Mock::given(path("/acme/Web/_apis/wit/workitems/$Bug"))
            .respond_with(ResponseTemplate::new(203).set_body_string("<html>Sign in</html>"))
            .mount(&server)
            .await;
        let azure = azure(&server);

        let check = azure.check_account(&account()).await;
        let outcome = azure.call(&new_bug(), Some(&account())).await.outcome;

        assert!(matches!(check, AccountCheck::Refused(_)), "{check:?}");
        assert!(matches!(outcome, ActionOutcome::Failed(_)), "{outcome:?}");
    }

    /// A token Azure DevOps knows is taken: listing one project works.
    #[tokio::test]
    async fn a_token_azure_devops_knows_is_accepted() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/acme/_apis/projects"))
            .and(query_param("$top", "1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "count": 1 })))
            .mount(&server)
            .await;

        let check = azure(&server).check_account(&account()).await;

        assert_eq!(check, AccountCheck::Accepted);
    }

    /// Azure DevOps presents itself with a title and icon, and explains
    /// every operation.
    #[tokio::test]
    async fn azure_devops_presents_itself_and_explains_its_operations() {
        let server = MockServer::start().await;
        let azure = azure(&server);

        assert_eq!(azure.profile().title().as_str(), "Azure DevOps");
        assert_eq!(azure.guides().len(), azure.operations().len());
    }
}
