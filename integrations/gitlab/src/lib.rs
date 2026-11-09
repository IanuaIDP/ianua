//! GitLab as a workflow integration, installed under `gitlab`: a step
//! lists, reads, opens, edits, closes, reopens, comments on and labels
//! issues, lists, reads, opens and merges merge requests, starts a CI/CD
//! pipeline or deletes a branch, through the token of an account the
//! tenant connected.
//!
//! The crate is a description handed to the SDK's
//! [`RestService`](ianua_integration::rest::service::RestService): its
//! profile, its operations, each described once in `operations/`, how an
//! account reaches GitLab, and the request that proves a token. Requests,
//! refusals, answers and token checks are the SDK's.
//!
//! The account holds the token alone: a personal, group or project access
//! token; or, when the deployment registered an app at GitLab and the
//! person signed in, the app's grant, exchanged for a token that lasts two
//! hours and kept until a minute before it runs out. Either is asked about
//! at GitLab before it is kept, and sent only to
//! the GitLab API this deployment names, gitlab.com's or a self-managed
//! one's, never to an address a step chooses: a step names the project
//! and what is inside it, and the address is built from them with every
//! part checked and escaped. No redirect is followed.
//!
//! A workflow may also start on an issue or merge request opened, a merge
//! request merged or a pipeline finished in one project (`events`),
//! through a project webhook registered with the account's token and
//! proven by its own secret token.

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

use crate::events::Hooks;

/// gitlab.com's API.
pub const PUBLIC_API: &str = "https://gitlab.com/api/v4/";

/// How the integration presents itself.
const PROFILE: ProfileText<'static> = ProfileText {
    title: "GitLab",
    description: "Reads and changes issues and merge requests, merges them, deletes branches and starts CI/CD pipelines in a team's GitLab projects, through a token the tenant connects.",
    icon: "gitlab",
    picture: include_str!("../assets/icon.svg"),
    brand: "e24329",
};

/// How opening an issue or a merge request is previewed: as GitLab shows
/// one.
const PREVIEWS: &[PreviewText] = &[
    PreviewText {
        operation: "create-issue",
        kind: PreviewKind::Issue,
        parts: &[
            (PreviewPart::Place, "project"),
            (PreviewPart::Title, "title"),
            (PreviewPart::Body, "description"),
            (PreviewPart::Labels, "labels"),
        ],
    },
    PreviewText {
        operation: "create-merge-request",
        kind: PreviewKind::Issue,
        parts: &[
            (PreviewPart::Place, "project"),
            (PreviewPart::Title, "title"),
            (PreviewPart::Body, "description"),
            (PreviewPart::Labels, "labels"),
        ],
    },
];

/// The scope a signed-in account asks for: the API, which its steps and
/// its webhooks need.
const SCOPES: &[&str] = &["api"];

/// The headers every call carries.
const HEADERS: &[(&str, &str)] = &[
    ("accept", "application/json"),
    ("user-agent", "ianua-workflows"),
];

/// How the GitLab integration is set up for this deployment.
#[derive(Debug, Clone)]
pub struct GitLabSettings {
    /// Where GitLab's API answers: [`PUBLIC_API`], a self-managed GitLab's
    /// `/api/v4/`, or a stand-in's.
    pub endpoint: ServiceEndpoint,
    /// How long one call may take.
    pub timeout: Duration,
    /// The most sensitive data a step may send to GitLab, and so the most
    /// sensitive an answer or an event is counted as.
    pub ceiling: DataClassLevel,
    /// The deployment's app at GitLab, when one is registered, so people
    /// may sign in instead of pasting a token.
    pub sign_in: Option<SignInSettings>,
}

/// The GitLab integration, set up by `settings`.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when a client cannot be built,
/// and `DomainError::Validation` when the description breaks a rule.
pub fn integration(settings: GitLabSettings) -> Result<RestService, DomainError> {
    let access = access(settings.endpoint, settings.sign_in.as_ref());
    let hooks = Hooks::new(
        WatchCalls::new(access.clone(), HEADERS, settings.timeout)?,
        settings.ceiling,
    );
    RestService::new(RestServiceParams {
        key: "gitlab",
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
        events: Some(ServiceEvents {
            described: events::all(),
            watcher: Box::new(hooks),
        }),
    })
}

/// How an account reaches GitLab at `endpoint`: by its pasted token, or,
/// when the deployment registered an app `signed_in`, by that too, the
/// grant exchanged at the app's token address.
fn access(endpoint: ServiceEndpoint, signed_in: Option<&SignInSettings>) -> Access {
    match signed_in {
        Some(at) => Access::BearerOrGrant {
            endpoint,
            signed_in: GrantAt {
                token: at.token.clone(),
                body: TokenBody::Form,
                scope: None,
            },
        },
        None => Access::Bearer { endpoint },
    }
}

/// Signing in at GitLab with the deployment's app `at`; the account keeps
/// the app's grant.
fn sign_in(at: SignInSettings, timeout: Duration) -> Result<Box<dyn SignIn>, DomainError> {
    let oauth = OAuthSignIn::new(OAuthSignInParams {
        at,
        scopes: SCOPES,
        scope_separator: " ",
        extra: &[],
        swap_extra: &[],
        token_body: TokenBody::Form,
        keeps: Keeps::RefreshGrant,
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

    /// GitLab's own description of its REST API, which every operation is
    /// checked against. GitLab publishes it at
    /// `gitlab-org/gitlab/doc/api/openapi/openapi_v3.yaml`, written in
    /// YAML; what the operations use of it is kept in
    /// `api-description.json`. To refresh it, download the file, convert it
    /// to JSON, and run the tests with
    /// `IANUA_GITLAB_API_DESCRIPTION=/path/to/openapi_v3.json`.
    fn description() -> Description {
        Description {
            kept: std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("api-description.json"),
            setting: "IANUA_GITLAB_API_DESCRIPTION",
            lead: &["api", "v4"],
        }
    }

    /// The steps on repository files, whose endpoints GitLab's generated
    /// description gets wrong: it gives a file read no answer, and a write
    /// only a multipart `file`, though GitLab's own reference for the
    /// repository files API takes JSON with `branch`, `content`,
    /// `commit_message` and `encoding`, and answers a read with `content`,
    /// `commit_id` and `size`. Their endpoints are still checked to exist.
    const MISDESCRIBED_BY_GITLAB: &[&str] = &["get-file:", "create-file:", "update-file:"];

    /// Every operation calls an endpoint GitLab describes, with only the
    /// query parameters and body properties it knows, always sending those
    /// it requires, and promising only outputs and statuses its answer
    /// carries, but for the file steps GitLab misdescribes; and the extract
    /// holds exactly those endpoints.
    #[test]
    fn every_operation_fits_gitlabs_api_description() {
        let description = description();
        let extract = description.extract(all()).unwrap();

        let wrong: Vec<String> = description
            .misfits(all(), &extract)
            .into_iter()
            .filter(|misfit| {
                !MISDESCRIBED_BY_GITLAB
                    .iter()
                    .any(|step| misfit.starts_with(step))
            })
            .collect();

        assert!(wrong.is_empty(), "{}", wrong.join("\n"));
        assert_eq!(
            Description::kept_endpoints(&extract),
            Description::called_endpoints(all()),
            "refresh the extract with IANUA_GITLAB_API_DESCRIPTION"
        );
    }

    /// A token as a test writes it: not shaped like a real one.
    const TOKEN: &str = "acme gitlab token for workflows";

    fn gitlab(server: &MockServer) -> RestService {
        integration(GitLabSettings {
            endpoint: ServiceEndpoint::at(&format!("{}/api/v4/", server.uri())).unwrap(),
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
            integration: IntegrationKey::new("gitlab").unwrap(),
            operation: OperationKey::new(operation).unwrap(),
            account: ActionAccount::Account(IntegrationAccountId::new()),
            arguments,
            effect: DeclaredAction::Undeclared,
            exposure: DataClassLevel::Internal,
            origin: EventOrigin::Outside,
        }
    }

    fn new_issue(project: &str) -> ActionCall {
        call(
            "create-issue",
            arguments(vec![
                ("project", text(project)),
                ("title", text("Nightly build failed")),
                ("description", text("See the run log.")),
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

    /// Ann's workflow opens an issue in acme/web: GitLab is asked with her
    /// token at the project's escaped path with the title, text and labels,
    /// and the new issue's number comes back in the step's output.
    #[tokio::test]
    async fn an_issue_is_opened_with_the_accounts_token() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v4/projects/acme%2Fweb/issues"))
            .and(header("authorization", format!("Bearer {TOKEN}").as_str()))
            .and(body_json(json!({
                "title": "Nightly build failed",
                "description": "See the run log.",
                "labels": ["ci", "urgent"]
            })))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({ "iid": 42 })))
            .expect(1)
            .mount(&server)
            .await;

        let outcome = gitlab(&server)
            .call(&new_issue("acme/web"), Some(&Secret::new(TOKEN.to_owned())))
            .await
            .outcome;

        let ActionOutcome::Succeeded { output, .. } = outcome else {
            panic!("the issue was not opened: {outcome:?}");
        };
        let number = output
            .field(&FieldName::new("json").unwrap())
            .and_then(|json| json.field(&FieldName::new("iid").unwrap()))
            .map(FlowData::value);
        assert_eq!(number, Some(FlowValue::Number(42.0)));
    }

    /// A comment goes to the notes of the issue the step numbers.
    #[tokio::test]
    async fn a_comment_goes_to_the_numbered_issue() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v4/projects/acme%2Fweb/issues/7/notes"))
            .and(body_json(json!({ "body": "Fixed in the next release." })))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({ "id": 1 })))
            .expect(1)
            .mount(&server)
            .await;
        let comment = call(
            "comment-on-issue",
            arguments(vec![
                ("project", text("acme/web")),
                ("issue", FlowData::number(7.0).unwrap()),
                ("body", text("Fixed in the next release.")),
            ]),
        );

        let outcome = gitlab(&server)
            .call(&comment, Some(&Secret::new(TOKEN.to_owned())))
            .await
            .outcome;

        assert!(
            matches!(outcome, ActionOutcome::Succeeded { .. }),
            "{outcome:?}"
        );
    }

    /// Missing or blank tokens and a project named `..` each fail the issue
    /// step without sending a request to GitLab.
    #[tokio::test]
    async fn no_token_or_a_crooked_project_sends_nothing() {
        let server = MockServer::start().await;
        let gitlab = gitlab(&server);

        let without = gitlab.call(&new_issue("acme/web"), None).await.outcome;
        let blank = gitlab
            .call(&new_issue("acme/web"), Some(&Secret::new("  ".to_owned())))
            .await
            .outcome;
        let crooked = gitlab
            .call(&new_issue(".."), Some(&Secret::new(TOKEN.to_owned())))
            .await
            .outcome;

        for outcome in [without, blank, crooked] {
            assert!(matches!(outcome, ActionOutcome::Failed(_)), "{outcome:?}");
        }
        assert_eq!(requests_made(&server).await, 0);
    }

    /// GitLab refusing the token fails the step; GitLab saying it is busy
    /// turns it away, to be tried again.
    #[tokio::test]
    async fn a_refusal_fails_and_a_busy_gitlab_turns_away() {
        let server = MockServer::start().await;
        Mock::given(path("/api/v4/projects/acme%2Flocked/issues"))
            .respond_with(ResponseTemplate::new(403))
            .mount(&server)
            .await;
        Mock::given(path("/api/v4/projects/acme%2Fbusy/issues"))
            .respond_with(ResponseTemplate::new(429))
            .mount(&server)
            .await;
        let gitlab = gitlab(&server);
        let token = Secret::new(TOKEN.to_owned());

        let refused = gitlab
            .call(&new_issue("acme/locked"), Some(&token))
            .await
            .outcome;
        let busy = gitlab
            .call(&new_issue("acme/busy"), Some(&token))
            .await
            .outcome;

        assert!(matches!(refused, ActionOutcome::Failed(_)));
        assert!(matches!(busy, ActionOutcome::TurnedAway(_)));
    }

    /// GitLab's redirect fails the issue step, and the destination host
    /// receives no request.
    #[tokio::test]
    async fn a_redirect_is_not_followed() {
        let elsewhere = MockServer::start().await;
        let server = MockServer::start().await;
        Mock::given(path("/api/v4/projects/acme%2Fweb/issues"))
            .respond_with(
                ResponseTemplate::new(307)
                    .insert_header("location", format!("{}/steal", elsewhere.uri()).as_str()),
            )
            .mount(&server)
            .await;

        let outcome = gitlab(&server)
            .call(&new_issue("acme/web"), Some(&Secret::new(TOKEN.to_owned())))
            .await
            .outcome;

        assert!(matches!(outcome, ActionOutcome::Failed(_)));
        assert_eq!(requests_made(&elsewhere).await, 0);
    }

    /// GitLab answering who a token belongs to `status`.
    async fn checked(status: u16, token: &str) -> AccountCheck {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v4/user"))
            .and(header("authorization", format!("Bearer {TOKEN}").as_str()))
            .respond_with(ResponseTemplate::new(status))
            .mount(&server)
            .await;
        Mock::given(path("/api/v4/user"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&server)
            .await;
        gitlab(&server)
            .check_account(&Secret::new(token.to_owned()))
            .await
    }

    /// Tess connects the team's project token: GitLab knows whose it is, so
    /// it is taken.
    #[tokio::test]
    async fn a_token_gitlab_knows_is_accepted() {
        assert_eq!(checked(200, TOKEN).await, AccountCheck::Accepted);
    }

    /// GitLab's 401 response to a mistyped token refuses the account check.
    #[tokio::test]
    async fn a_token_gitlab_does_not_know_is_refused() {
        let answer = checked(200, "a mistyped token").await;

        assert!(matches!(answer, AccountCheck::Refused(_)));
    }

    /// GitLab limiting the rate or failing says nothing of the token, so
    /// the check is unreachable, never accepted.
    #[tokio::test]
    async fn a_busy_or_failing_gitlab_says_nothing_of_the_token() {
        for status in [429, 500, 503] {
            assert_eq!(checked(status, TOKEN).await, AccountCheck::Unreachable);
        }
    }

    /// GitLab presents itself with a title and icon, and explains every one
    /// of its operations.
    #[tokio::test]
    async fn gitlab_presents_itself_and_explains_its_operations() {
        let server = MockServer::start().await;
        let gitlab = gitlab(&server);

        assert_eq!(gitlab.profile().title().as_str(), "GitLab");
        assert_eq!(gitlab.profile().icon().as_str(), "gitlab");
        assert_eq!(gitlab.guides().len(), gitlab.operations().len());
    }
}
