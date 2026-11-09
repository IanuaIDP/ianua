//! Gmail as a workflow integration, installed under `gmail`: a step
//! searches and reads the account's mail, sends an email as the account,
//! changes a message's labels, moves one to the trash and makes a label,
//! through an account the tenant connected.
//!
//! The crate is a description handed to the SDK's
//! [`RestService`](ianua_integration::rest::service::RestService). A Google
//! account holds `{"client_id", "client_secret", "refresh_token"}`: the
//! tenant's own OAuth client and a grant to Gmail's scopes. Before each
//! call the grant is exchanged at Google's token address for a token
//! lasting an hour, which signs the call; the grant itself never leaves
//! for the Gmail API. A grant is proven by reading the mailbox's profile.
//!
//! Gmail takes an email as one whole message, which the SDK's mail body
//! writes, refusing a header that holds a line break, so a subject or an
//! address can never add a recipient of its own.
//!
//! With the deployment's OAuth client set, a person connects an account by
//! signing in at Google instead, and the account keeps the client and the
//! grant Google issues in the same shape.
//!
//! Gmail tells of new mail through Google Cloud Pub/Sub, not by calling an
//! address, so no workflow starts on it.

#![cfg_attr(not(test), warn(clippy::too_many_lines))]

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
use ianua_integration::rest::operation::Verb;
use ianua_integration::rest::service::{Answers, Probe, RestService, RestServiceParams};
use ianua_integration::rest::sign_in::{OAuthSignIn, SignInSettings};

/// Gmail's public API.
pub const PUBLIC_API: &str = "https://gmail.googleapis.com/gmail/v1/";

/// Google's token address, where a grant is exchanged for a token.
pub const PUBLIC_TOKEN: &str = "https://oauth2.googleapis.com/token";

/// How the integration presents itself.
const PROFILE: ProfileText<'static> = ProfileText {
    title: "Gmail",
    description: "Searches and reads a team's Gmail, sends email as the account, and labels or trashes messages, through an OAuth grant the tenant connects.",
    icon: "gmail",
    picture: include_str!("../assets/icon.svg"),
    brand: "c5221f",
};

/// The scopes a signed-in account is granted: reading and labelling mail,
/// and sending it, which the steps need and nothing more.
const SCOPES: &[&str] = &[
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/gmail.send",
];

/// How a sent email is previewed.
const PREVIEWS: &[PreviewText] = &[PreviewText {
    operation: "send-message",
    kind: PreviewKind::Email,
    parts: &[
        (PreviewPart::Place, "to"),
        (PreviewPart::Title, "subject"),
        (PreviewPart::Body, "text"),
    ],
}];

/// How the Gmail integration is set up for this deployment.
#[derive(Debug, Clone)]
pub struct GmailSettings {
    /// Where Gmail's API answers: [`PUBLIC_API`], or a stand-in's.
    pub endpoint: ServiceEndpoint,
    /// Where a grant is exchanged for a token: [`PUBLIC_TOKEN`], or a
    /// stand-in's.
    pub token: ServiceEndpoint,
    /// How long one call may take.
    pub timeout: Duration,
    /// The most sensitive data a step may send, and so the most sensitive
    /// an answer is counted as.
    pub ceiling: DataClassLevel,
    /// The deployment's OAuth client at Google, when one is registered;
    /// without it, accounts are connected with a client and grant pasted
    /// in.
    pub sign_in: Option<SignInSettings>,
}

/// The Gmail integration, set up by `settings`.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when the client cannot be built,
/// and `DomainError::Validation` when the description breaks a rule.
pub fn integration(settings: GmailSettings) -> Result<RestService, DomainError> {
    RestService::new(RestServiceParams {
        key: "gmail",
        profile: PROFILE,
        operations: operations::all().collect(),
        previews: PREVIEWS,
        access: Access::Refreshed {
            endpoint: settings.endpoint,
            token: settings.token,
        },
        headers: &[],
        probe: Probe {
            verb: Verb::Get,
            path: &["users", "me", "profile"],
            query: &[],
        },
        answers: Answers::ByStatus,
        timeout: settings.timeout,
        ceiling: settings.ceiling,
        sign_in: settings
            .sign_in
            .map(|at| sign_in(at, settings.timeout))
            .transpose()?,
        events: None,
    })
}

/// Signing in at Google through the deployment's OAuth client `at`, for
/// the scopes Gmail's steps need.
fn sign_in(at: SignInSettings, timeout: Duration) -> Result<Box<dyn SignIn>, DomainError> {
    Ok(Box::new(OAuthSignIn::google(at, SCOPES, timeout)?))
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
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::operations::all;

    /// Gmail's API described as OpenAPI 3, which every operation is
    /// checked against. Google publishes it as a discovery document;
    /// APIs.guru converts that to
    /// `https://api.apis.guru/v2/specs/googleapis.com/gmail/v1/openapi.json`,
    /// whose paths start with `/gmail/v1`, and what the operations use of
    /// it is kept in `api-description.json`. To refresh it, download the
    /// file and run the tests with
    /// `IANUA_GMAIL_API_DESCRIPTION=/path/to/openapi.json`.
    fn description() -> Description {
        Description {
            kept: std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("api-description.json"),
            setting: "IANUA_GMAIL_API_DESCRIPTION",
            lead: &["gmail", "v1"],
        }
    }

    /// Every operation calls an endpoint Google describes, with only the
    /// parameters and body properties it knows, always sending those it
    /// requires, and promising only outputs its answer carries; and the
    /// extract holds exactly those endpoints.
    #[test]
    fn every_operation_fits_googles_api_description() {
        let description = description();
        let extract = description.extract(all()).unwrap();

        let wrong = description.misfits(all(), &extract);

        assert!(wrong.is_empty(), "{}", wrong.join("\n"));
        assert_eq!(
            Description::kept_endpoints(&extract),
            Description::called_endpoints(all()),
            "refresh the extract with IANUA_GMAIL_API_DESCRIPTION"
        );
    }

    /// A grant as a test writes it: not shaped like a real one.
    const GRANT: &str = r#"{"client_id": "acme app", "client_secret": "app words", "refresh_token": "lasting grant"}"#;

    /// Google's stand-in: its token address issuing `short token` for the
    /// grant, and its Gmail API under `/gmail/v1`.
    async fn google() -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({ "access_token": "short token", "expires_in": 3599 })),
            )
            .mount(&server)
            .await;
        server
    }

    fn gmail(server: &MockServer) -> RestService {
        integration(GmailSettings {
            endpoint: ServiceEndpoint::at(&format!("{}/gmail/v1/", server.uri())).unwrap(),
            token: ServiceEndpoint::at(&format!("{}/token", server.uri())).unwrap(),
            timeout: Duration::from_secs(2),
            ceiling: DataClassLevel::Internal,
            sign_in: None,
        })
        .unwrap()
    }

    fn grant() -> Secret {
        Secret::new(GRANT.to_owned())
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
            integration: IntegrationKey::new("gmail").unwrap(),
            operation: OperationKey::new(operation).unwrap(),
            account: ActionAccount::Account(IntegrationAccountId::new()),
            arguments,
            effect: DeclaredAction::Undeclared,
            exposure: DataClassLevel::Internal,
            origin: EventOrigin::Outside,
        }
    }

    fn mail() -> ActionCall {
        step(
            "send-message",
            vec![
                (
                    "to",
                    FlowData::list(vec![FlowData::text("bob@acme.test").unwrap()]).unwrap(),
                ),
                ("subject", FlowData::text("Build passed").unwrap()),
                ("text", FlowData::text("All green.").unwrap()),
            ],
        )
    }

    /// Ann's workflow mails Bob: the grant is exchanged for a token, which
    /// signs the message sent from the account's own mailbox.
    #[tokio::test]
    async fn a_mail_is_sent_with_a_token_the_grant_was_exchanged_for() {
        let server = google().await;
        Mock::given(method("POST"))
            .and(path("/gmail/v1/users/me/messages/send"))
            .and(header("authorization", "Bearer short token"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({ "id": "18c2", "threadId": "t-1" })),
            )
            .expect(1)
            .mount(&server)
            .await;

        let outcome = gmail(&server).call(&mail(), Some(&grant())).await.outcome;

        assert!(
            matches!(outcome, ActionOutcome::Succeeded { .. }),
            "{outcome:?}"
        );
    }

    /// Google's invalid-grant response fails the mail step; all requests
    /// stay at the token endpoint.
    #[tokio::test]
    async fn a_revoked_grant_fails_without_calling_gmail() {
        let server = MockServer::start().await;
        Mock::given(path("/token"))
            .respond_with(
                ResponseTemplate::new(400).set_body_json(json!({ "error": "invalid_grant" })),
            )
            .mount(&server)
            .await;

        let outcome = gmail(&server).call(&mail(), Some(&grant())).await.outcome;

        assert!(matches!(outcome, ActionOutcome::Failed(_)));
        let calls = server.received_requests().await.unwrap();
        assert!(calls.iter().all(|call| call.url.path() == "/token"));
    }

    /// Google reading the mailbox's profile for a grant, answering
    /// `status`.
    async fn checked(server: &MockServer, status: u16) -> AccountCheck {
        Mock::given(method("GET"))
            .and(path("/gmail/v1/users/me/profile"))
            .and(header("authorization", "Bearer short token"))
            .respond_with(
                ResponseTemplate::new(status)
                    .set_body_json(json!({ "emailAddress": "team@acme.test" })),
            )
            .mount(server)
            .await;
        gmail(server).check_account(&grant()).await
    }

    /// Tess connects the grant: Google issues a token and reads the
    /// mailbox's profile, so it is taken; a token without Gmail's scopes
    /// is refused.
    #[tokio::test]
    async fn a_live_grant_is_accepted_and_one_without_the_scope_refused() {
        assert_eq!(checked(&google().await, 200).await, AccountCheck::Accepted);
        assert!(matches!(
            checked(&google().await, 403).await,
            AccountCheck::Refused(_)
        ));
    }

    /// Gmail presents itself with a title, icon and brand colour, explains
    /// every operation and starts no workflow.
    #[tokio::test]
    async fn gmail_presents_itself_and_explains_its_operations() {
        let server = MockServer::start().await;
        let gmail = gmail(&server);

        assert_eq!(gmail.profile().icon().as_str(), "gmail");
        assert_eq!(gmail.profile().brand().as_str(), "c5221f");
        assert_eq!(gmail.guides().len(), gmail.operations().len());
        assert!(gmail.events().is_empty());
    }
}
