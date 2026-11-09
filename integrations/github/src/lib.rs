//! GitHub as a workflow integration, installed under `github`, and the
//! reference other integrations are modelled on: a step reads, opens and
//! changes issues and pull requests, comments, labels, assigns, reads a
//! file, publishes a release, deletes a branch or starts a GitHub Actions
//! workflow, through the token of an account the tenant connected.
//!
//! The crate is a description handed to the SDK's
//! [`RestService`](ianua_integration::rest::service::RestService): its
//! profile, its operations, each described once in `operations/`, how an
//! account reaches GitHub, the headers GitHub asks for, and the request
//! that proves a token. Requests, refusals, answers and token checks are
//! the SDK's.
//!
//! The account holds the token alone, such as a fine-grained personal
//! access token. It is asked about at GitHub before it is kept, and sent
//! only to the GitHub API this deployment names, never to an address a
//! step chooses: a step names the repository and the path inside it, and
//! the address is built from them with every part checked and escaped. No
//! redirect is followed.
//!
//! With the deployment's OAuth app set, a person connects an account by
//! signing in at GitHub instead, and the token GitHub issues is kept the
//! same way. A workflow may also start on an issue or pull request opened
//! or a push in one repository (`events`), through a webhook registered
//! with the account's token and proven by its own secret.

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
use ianua_integration::rest::operation::Verb;
use ianua_integration::rest::service::{Answers, Probe, RestService, RestServiceParams};
use ianua_integration::rest::sign_in::{
    Keeps, OAuthSignIn, OAuthSignInParams, SignInSettings, TokenBody,
};
use ianua_integration::rest::watch::WatchCalls;

use crate::events::Hooks;

/// GitHub's public API.
pub const PUBLIC_API: &str = "https://api.github.com/";

/// The version of GitHub's REST API the calls are written for.
const API_VERSION: &str = "2022-11-28";

/// How the integration presents itself.
const PROFILE: ProfileText<'static> = ProfileText {
    title: "GitHub",
    description: "Reads and changes issues and pull requests, reads files, publishes releases and starts Actions workflows in a team's GitHub repositories, through a token the tenant connects.",
    icon: "github",
    picture: include_str!("../assets/icon.svg"),
    brand: "24292f",
};

/// How opening an issue or a pull request is previewed: as GitHub shows
/// one.
const PREVIEWS: &[PreviewText] = &[
    PreviewText {
        operation: "create-issue",
        kind: PreviewKind::Issue,
        parts: &[
            (PreviewPart::Place, "repository"),
            (PreviewPart::Title, "title"),
            (PreviewPart::Body, "body"),
            (PreviewPart::Labels, "labels"),
        ],
    },
    PreviewText {
        operation: "create-pull-request",
        kind: PreviewKind::Issue,
        parts: &[
            (PreviewPart::Place, "repository"),
            (PreviewPart::Title, "title"),
            (PreviewPart::Body, "body"),
        ],
    },
];

/// The headers GitHub asks every call to carry.
const HEADERS: &[(&str, &str)] = &[
    ("accept", "application/vnd.github+json"),
    ("user-agent", "ianua-workflows"),
    ("x-github-api-version", API_VERSION),
];

/// Where GitHub signs people in for an OAuth app.
pub const PUBLIC_AUTHORIZE: &str = "https://github.com/login/oauth/authorize";

/// Where GitHub swaps an OAuth app's code for a token.
pub const PUBLIC_TOKEN: &str = "https://github.com/login/oauth/access_token";

/// The scopes a signed-in account needs: its repositories, and their
/// webhooks, which publishing a workflow on GitHub's events registers and
/// archiving removes.
const SCOPES: &[&str] = &["repo", "admin:repo_hook"];

/// How the GitHub integration is set up for this deployment.
#[derive(Debug, Clone)]
pub struct GitHubSettings {
    /// Where GitHub's API answers: [`PUBLIC_API`], a GitHub Enterprise
    /// server's, or a stand-in's.
    pub endpoint: ServiceEndpoint,
    /// How long one call may take.
    pub timeout: Duration,
    /// The most sensitive data a step may send to GitHub, and so the most
    /// sensitive an answer or an event is counted as.
    pub ceiling: DataClassLevel,
    /// The deployment's OAuth app at GitHub, at [`PUBLIC_AUTHORIZE`] and
    /// [`PUBLIC_TOKEN`] or a stand-in's, when one is registered; without
    /// it, accounts are connected with a token pasted in.
    pub sign_in: Option<SignInSettings>,
}

/// The GitHub integration, set up by `settings`.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when a client cannot be built,
/// and `DomainError::Validation` when the description breaks a rule.
pub fn integration(settings: GitHubSettings) -> Result<RestService, DomainError> {
    let access = Access::Bearer {
        endpoint: settings.endpoint,
    };
    let events = service_events(&access, settings.timeout, settings.ceiling)?;
    RestService::new(RestServiceParams {
        key: "github",
        profile: PROFILE,
        operations: operations::all().collect(),
        previews: PREVIEWS,
        access,
        headers: HEADERS,
        probe: Probe {
            verb: Verb::Get,
            path: &["user"],
            query: &[],
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

/// Describes repository events and builds their webhook client using the account access.
fn service_events(
    access: &Access,
    timeout: Duration,
    ceiling: DataClassLevel,
) -> Result<ServiceEvents, DomainError> {
    let hooks = Hooks::new(WatchCalls::new(access.clone(), HEADERS, timeout)?, ceiling);
    Ok(ServiceEvents {
        described: events::all(),
        watcher: Box::new(hooks),
    })
}

/// Signing in at GitHub through the deployment's app `at`.
fn sign_in(at: SignInSettings, timeout: Duration) -> Result<Box<dyn SignIn>, DomainError> {
    let oauth = OAuthSignIn::new(OAuthSignInParams {
        at,
        scopes: SCOPES,
        scope_separator: " ",
        extra: &[],
        swap_extra: &[],
        token_body: TokenBody::Form,
        keeps: Keeps::AccessToken,
        place: None,
        timeout,
    })?;
    Ok(Box::new(oauth))
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::workflows::data::{FieldName, FlowData, FlowValue};
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
    use wiremock::matchers::{body_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::operations::all;

    /// GitHub's own description of its REST API, which every operation is
    /// checked against. GitHub publishes it at
    /// `github/rest-api-description/descriptions/api.github.com/api.github.com.json`;
    /// what the operations use of it is kept in `api-description.json`. To
    /// refresh it, download the file and run the tests with
    /// `IANUA_GITHUB_API_DESCRIPTION=/path/to/api.github.com.json`.
    fn description() -> Description {
        Description {
            kept: std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("api-description.json"),
            setting: "IANUA_GITHUB_API_DESCRIPTION",
            lead: &[],
        }
    }

    /// Every operation calls an endpoint GitHub describes, with only the
    /// query parameters and body properties it knows, always sending those
    /// it requires, and promising only outputs and statuses its answer
    /// carries; and the extract holds exactly those endpoints.
    #[test]
    fn every_operation_fits_githubs_api_description() {
        let description = description();
        let extract = description.extract(all()).unwrap();

        let wrong = description.misfits(all(), &extract);

        assert!(wrong.is_empty(), "{}", wrong.join("\n"));
        assert_eq!(
            Description::kept_endpoints(&extract),
            Description::called_endpoints(all()),
            "refresh the extract with IANUA_GITHUB_API_DESCRIPTION"
        );
    }

    /// A token as a test writes it: not shaped like a real one.
    const TOKEN: &str = "test token for ann";

    fn github(server: &MockServer) -> RestService {
        integration(GitHubSettings {
            endpoint: ServiceEndpoint::at(&server.uri()).unwrap(),
            timeout: Duration::from_secs(2),
            ceiling: DataClassLevel::Internal,
            sign_in: None,
        })
        .unwrap()
    }

    fn arguments(entries: Vec<(&str, FlowData)>) -> FlowData {
        FlowData::map(
            entries
                .into_iter()
                .map(|(name, value)| (FieldName::new(name).unwrap(), value))
                .collect(),
        )
        .unwrap()
    }

    fn text(value: &str) -> FlowData {
        FlowData::text(value).unwrap()
    }

    fn call(operation: &str, arguments: FlowData) -> ActionCall {
        ActionCall {
            call_id: ActionCallId::new(),
            integration: IntegrationKey::new("github").unwrap(),
            operation: OperationKey::new(operation).unwrap(),
            account: ActionAccount::Account(IntegrationAccountId::new()),
            arguments,
            effect: DeclaredAction::Undeclared,
            exposure: DataClassLevel::Internal,
            origin: EventOrigin::Outside,
        }
    }

    fn new_issue(repository: &str) -> ActionCall {
        call(
            "create-issue",
            arguments(vec![
                ("repository", text(repository)),
                ("title", text("Nightly build failed")),
                ("body", text("See the run log.")),
                (
                    "labels",
                    FlowData::list(vec![text("ci"), text("urgent")]).unwrap(),
                ),
            ]),
        )
    }

    async fn requests_made(server: &MockServer) -> usize {
        server.received_requests().await.unwrap().len()
    }

    /// Ann's workflow opens an issue in acme/web: GitHub is asked with her
    /// token, GitHub's headers and the title, body and labels, and the new
    /// issue's number comes back in the step's output.
    #[tokio::test]
    async fn an_issue_is_opened_with_the_accounts_token() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/repos/acme/web/issues"))
            .and(header("authorization", format!("Bearer {TOKEN}").as_str()))
            .and(header("x-github-api-version", API_VERSION))
            .and(header("accept", "application/vnd.github+json"))
            .and(body_json(json!({
                "title": "Nightly build failed",
                "body": "See the run log.",
                "labels": ["ci", "urgent"]
            })))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({ "number": 42 })))
            .expect(1)
            .mount(&server)
            .await;

        let outcome = github(&server)
            .call(&new_issue("acme/web"), Some(&Secret::new(TOKEN.to_owned())))
            .await
            .outcome;

        let ActionOutcome::Succeeded { output, .. } = outcome else {
            panic!("the issue was not opened: {outcome:?}");
        };
        let number = output
            .field(&FieldName::new("json").unwrap())
            .and_then(|json| json.field(&FieldName::new("number").unwrap()))
            .map(FlowData::value);
        assert_eq!(number, Some(FlowValue::Number(42.0)));
    }

    /// A comment goes to the issue the step numbers.
    #[tokio::test]
    async fn a_comment_goes_to_the_numbered_issue() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/repos/acme/web/issues/7/comments"))
            .and(body_json(json!({ "body": "Fixed in the next release." })))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({ "id": 1 })))
            .expect(1)
            .mount(&server)
            .await;
        let comment = call(
            "comment-on-issue",
            arguments(vec![
                ("repository", text("acme/web")),
                ("issue", FlowData::number(7.0).unwrap()),
                ("body", text("Fixed in the next release.")),
            ]),
        );

        let outcome = github(&server)
            .call(&comment, Some(&Secret::new(TOKEN.to_owned())))
            .await
            .outcome;

        assert!(
            matches!(outcome, ActionOutcome::Succeeded { .. }),
            "{outcome:?}"
        );
    }

    /// Missing or blank tokens and a repository containing a parent path
    /// each fail the issue step without sending a request to GitHub.
    #[tokio::test]
    async fn no_token_or_a_crooked_repository_sends_nothing() {
        let server = MockServer::start().await;
        let github = github(&server);

        let without = github.call(&new_issue("acme/web"), None).await.outcome;
        let blank = github
            .call(&new_issue("acme/web"), Some(&Secret::new("  ".to_owned())))
            .await
            .outcome;
        let crooked = github
            .call(
                &new_issue("acme/../admin"),
                Some(&Secret::new(TOKEN.to_owned())),
            )
            .await
            .outcome;

        for outcome in [without, blank, crooked] {
            assert!(matches!(outcome, ActionOutcome::Failed(_)), "{outcome:?}");
        }
        assert_eq!(requests_made(&server).await, 0);
    }

    /// GitHub refusing the token fails the step; GitHub saying it is busy
    /// turns it away, to be tried again.
    #[tokio::test]
    async fn a_refusal_fails_and_a_busy_github_turns_away() {
        let server = MockServer::start().await;
        Mock::given(path("/repos/acme/locked/issues"))
            .respond_with(ResponseTemplate::new(403))
            .mount(&server)
            .await;
        Mock::given(path("/repos/acme/busy/issues"))
            .respond_with(ResponseTemplate::new(429))
            .mount(&server)
            .await;
        let github = github(&server);
        let token = Secret::new(TOKEN.to_owned());

        let refused = github
            .call(&new_issue("acme/locked"), Some(&token))
            .await
            .outcome;
        let busy = github
            .call(&new_issue("acme/busy"), Some(&token))
            .await
            .outcome;

        assert!(matches!(refused, ActionOutcome::Failed(_)));
        assert!(matches!(busy, ActionOutcome::TurnedAway(_)));
    }

    /// GitHub's redirect fails the issue step, and the destination host
    /// receives no request.
    #[tokio::test]
    async fn a_redirect_is_not_followed() {
        let elsewhere = MockServer::start().await;
        let server = MockServer::start().await;
        Mock::given(path("/repos/acme/web/issues"))
            .respond_with(
                ResponseTemplate::new(307)
                    .insert_header("location", format!("{}/steal", elsewhere.uri()).as_str()),
            )
            .mount(&server)
            .await;

        let outcome = github(&server)
            .call(&new_issue("acme/web"), Some(&Secret::new(TOKEN.to_owned())))
            .await
            .outcome;

        assert!(matches!(outcome, ActionOutcome::Failed(_)));
        assert_eq!(requests_made(&elsewhere).await, 0);
    }

    /// GitHub answering who a token belongs to `status`.
    async fn checked(status: u16, token: &str) -> AccountCheck {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/user"))
            .and(header("authorization", format!("Bearer {TOKEN}").as_str()))
            .respond_with(ResponseTemplate::new(status))
            .mount(&server)
            .await;
        Mock::given(path("/user"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&server)
            .await;
        github(&server)
            .check_account(&Secret::new(token.to_owned()))
            .await
    }

    /// Tess connects the team's token: GitHub knows whose it is, so it is
    /// taken.
    #[tokio::test]
    async fn a_token_github_knows_is_accepted() {
        assert_eq!(checked(200, TOKEN).await, AccountCheck::Accepted);
    }

    /// GitHub's 401 response to a mistyped token refuses the account check.
    #[tokio::test]
    async fn a_token_github_does_not_know_is_refused() {
        let answer = checked(200, "a mistyped token").await;

        assert!(matches!(answer, AccountCheck::Refused(_)));
    }

    /// GitHub limiting the rate or failing says nothing of the token, so the
    /// check is unreachable, never accepted.
    #[tokio::test]
    async fn a_busy_or_failing_github_says_nothing_of_the_token() {
        for status in [429, 500, 503] {
            assert_eq!(checked(status, TOKEN).await, AccountCheck::Unreachable);
        }
    }

    /// GitHub presents itself with a title and icon, and explains every one
    /// of its operations.
    #[tokio::test]
    async fn github_presents_itself_and_explains_its_operations() {
        let server = MockServer::start().await;
        let github = github(&server);

        assert_eq!(github.profile().title().as_str(), "GitHub");
        assert_eq!(github.profile().icon().as_str(), "github");
        assert_eq!(github.guides().len(), github.operations().len());
    }
}
