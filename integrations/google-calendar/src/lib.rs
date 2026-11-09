//! Google Calendar as a workflow integration, installed under
//! `google-calendar`: a step lists and creates calendars, finds busy
//! times, and lists, reads, creates, changes, moves and deletes events,
//! through an account the tenant connected.
//!
//! The crate is a description handed to the SDK's
//! [`RestService`](ianua_integration::rest::service::RestService). A Google
//! account holds `{"client_id", "client_secret", "refresh_token"}`: the
//! tenant's own OAuth client and a grant to the calendar scope. Before
//! each call the grant is exchanged at Google's token address for a token
//! lasting an hour, which signs the call; the grant itself never leaves
//! for the calendar API. Listing the account's calendars proves a grant.
//!
//! With the deployment's OAuth client set, a person connects an account by
//! signing in at Google instead, and the account keeps the client and the
//! grant Google issues in the same shape. A workflow may also start when a
//! calendar changes (`events`), through a watch channel opened with the
//! account's grant.

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
use ianua_integration::rest::sign_in::{OAuthSignIn, SignInSettings};
use ianua_integration::rest::watch::WatchCalls;

use crate::events::Channels;

/// Google Calendar's public API.
pub const PUBLIC_API: &str = "https://www.googleapis.com/calendar/v3/";

/// Google's token address, where a grant is exchanged for a token.
pub const PUBLIC_TOKEN: &str = "https://oauth2.googleapis.com/token";

/// How the integration presents itself.
const PROFILE: ProfileText<'static> = ProfileText {
    title: "Google Calendar",
    description: "Reads and books time in a team's Google calendars, invites people and finds when they are free, through an OAuth grant the tenant connects.",
    icon: "google-calendar",
    picture: include_str!("../assets/icon.svg"),
    brand: "1a73e8",
};

/// How booking an event is previewed: as the event in a calendar.
const PREVIEWS: &[PreviewText] = &[PreviewText {
    operation: "create-event",
    kind: PreviewKind::CalendarEvent,
    parts: &[
        (PreviewPart::Title, "summary"),
        (PreviewPart::Start, "start"),
        (PreviewPart::End, "end"),
        (PreviewPart::Place, "location"),
        (PreviewPart::Body, "description"),
    ],
}];

/// How the Google Calendar integration is set up for this deployment.
#[derive(Debug, Clone)]
pub struct GoogleCalendarSettings {
    /// Where Google Calendar's API answers: [`PUBLIC_API`], or a
    /// stand-in's.
    pub endpoint: ServiceEndpoint,
    /// Where a grant is exchanged for a token: [`PUBLIC_TOKEN`], or a
    /// stand-in's.
    pub token: ServiceEndpoint,
    /// How long one call may take.
    pub timeout: Duration,
    /// The most sensitive data a step may send, and so the most sensitive
    /// an answer or a notification is counted as.
    pub ceiling: DataClassLevel,
    /// The deployment's OAuth client at Google, at [`PUBLIC_AUTHORIZE`] and
    /// [`PUBLIC_TOKEN`] or a stand-in's, when one is registered; without
    /// it, accounts are connected with a client and grant pasted in.
    pub sign_in: Option<SignInSettings>,
}

/// Where Google signs people in.
pub const PUBLIC_AUTHORIZE: &str = "https://accounts.google.com/o/oauth2/v2/auth";

/// The scope a signed-in account is granted: the calendars, which every
/// step and the watch channels need.
const SCOPES: &[&str] = &["https://www.googleapis.com/auth/calendar"];

/// The Google Calendar integration, set up by `settings`.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when the client cannot be built,
/// and `DomainError::Validation` when the description breaks a rule.
pub fn integration(settings: GoogleCalendarSettings) -> Result<RestService, DomainError> {
    let access = Access::Refreshed {
        endpoint: settings.endpoint,
        token: settings.token,
    };
    let events = service_events(&access, settings.timeout, settings.ceiling)?;
    RestService::new(RestServiceParams {
        key: "google-calendar",
        profile: PROFILE,
        operations: operations::all().collect(),
        previews: PREVIEWS,
        access,
        headers: &[],
        probe: Probe {
            verb: Verb::Get,
            path: &["users", "me", "calendarList"],
            query: &[("maxResults", "1")],
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

/// Describes calendar events and builds their watch channels using the same grant access.
fn service_events(
    access: &Access,
    timeout: Duration,
    ceiling: DataClassLevel,
) -> Result<ServiceEvents, DomainError> {
    let channels = Channels::new(WatchCalls::new(access.clone(), &[], timeout)?, ceiling);
    Ok(ServiceEvents {
        described: events::all(),
        watcher: Box::new(channels),
    })
}

/// Signing in at Google through the deployment's OAuth client `at`, for
/// the scope the calendar steps need.
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
    use wiremock::matchers::{body_json, header, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::operations::all;

    /// Google Calendar's API described as OpenAPI 3, which every operation
    /// is checked against. Google publishes it as a discovery document;
    /// APIs.guru converts that to
    /// `https://api.apis.guru/v2/specs/googleapis.com/calendar/v3/openapi.json`,
    /// and what the operations use of it is kept in `api-description.json`.
    /// To refresh it, download the file and run the tests with
    /// `IANUA_GOOGLE_CALENDAR_API_DESCRIPTION=/path/to/openapi.json`.
    fn description() -> Description {
        Description {
            kept: std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("api-description.json"),
            setting: "IANUA_GOOGLE_CALENDAR_API_DESCRIPTION",
            lead: &[],
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
            "refresh the extract with IANUA_GOOGLE_CALENDAR_API_DESCRIPTION"
        );
    }

    /// A grant as a test writes it: not shaped like a real one.
    const GRANT: &str = r#"{"client_id": "acme app", "client_secret": "app words", "refresh_token": "lasting grant"}"#;

    /// Google's stand-in: its token address issuing `short token` for the
    /// grant, and its calendar API under `/calendar/v3`.
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

    fn calendar(server: &MockServer) -> RestService {
        integration(GoogleCalendarSettings {
            endpoint: ServiceEndpoint::at(&format!("{}/calendar/v3/", server.uri())).unwrap(),
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

    fn text(value: &str) -> FlowData {
        FlowData::text(value).unwrap()
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
            integration: IntegrationKey::new("google-calendar").unwrap(),
            operation: OperationKey::new(operation).unwrap(),
            account: ActionAccount::Account(IntegrationAccountId::new()),
            arguments,
            effect: DeclaredAction::Undeclared,
            exposure: DataClassLevel::Internal,
            origin: EventOrigin::Outside,
        }
    }

    fn review() -> ActionCall {
        step(
            "create-event",
            vec![
                ("calendar", text("primary")),
                ("summary", text("Incident review")),
                ("start", text("2026-11-03T09:00:00+01:00")),
                ("end", text("2026-11-03T09:30:00+01:00")),
            ],
        )
    }

    /// Ann's workflow books the incident review: the grant is exchanged
    /// for a token, which signs the event sent to her calendar.
    #[tokio::test]
    async fn an_event_is_booked_with_a_token_the_grant_was_exchanged_for() {
        let server = google().await;
        Mock::given(method("POST"))
            .and(path("/calendar/v3/calendars/primary/events"))
            .and(header("authorization", "Bearer short token"))
            .and(body_json(json!({
                "summary": "Incident review",
                "start": { "dateTime": "2026-11-03T09:00:00+01:00" },
                "end": { "dateTime": "2026-11-03T09:30:00+01:00" }
            })))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({ "id": "e1", "status": "confirmed" })),
            )
            .expect(1)
            .mount(&server)
            .await;

        let outcome = calendar(&server)
            .call(&review(), Some(&grant()))
            .await
            .outcome;

        assert!(
            matches!(outcome, ActionOutcome::Succeeded { .. }),
            "{outcome:?}"
        );
    }

    /// Creating an event without its start fails without sending any
    /// request to Google, including a token exchange.
    #[tokio::test]
    async fn a_step_that_cannot_be_sent_never_exchanges_the_grant() {
        let server = MockServer::start().await;
        let untimed = step(
            "create-event",
            vec![("calendar", text("primary")), ("summary", text("Review"))],
        );

        let outcome = calendar(&server)
            .call(&untimed, Some(&grant()))
            .await
            .outcome;

        assert!(matches!(outcome, ActionOutcome::Failed(_)));
        assert_eq!(server.received_requests().await.unwrap().len(), 0);
    }

    /// Google's invalid-grant response fails the event step; all requests
    /// stay at the token endpoint.
    #[tokio::test]
    async fn a_revoked_grant_fails_without_calling_the_calendar() {
        let server = MockServer::start().await;
        Mock::given(path("/token"))
            .respond_with(
                ResponseTemplate::new(400).set_body_json(json!({ "error": "invalid_grant" })),
            )
            .mount(&server)
            .await;

        let outcome = calendar(&server)
            .call(&review(), Some(&grant()))
            .await
            .outcome;

        assert!(matches!(outcome, ActionOutcome::Failed(_)));
        let calls = server.received_requests().await.unwrap();
        assert!(calls.iter().all(|call| call.url.path() == "/token"));
    }

    /// Google listing the account's calendars for a grant answering
    /// `status`.
    async fn checked(server: &MockServer, status: u16) -> AccountCheck {
        Mock::given(method("GET"))
            .and(path("/calendar/v3/users/me/calendarList"))
            .and(query_param("maxResults", "1"))
            .and(header("authorization", "Bearer short token"))
            .respond_with(ResponseTemplate::new(status).set_body_json(json!({ "items": [] })))
            .mount(server)
            .await;
        calendar(server).check_account(&grant()).await
    }

    /// Tess connects the grant: Google issues a token and lists the
    /// calendars, so it is taken; a token without the calendar scope is
    /// refused.
    #[tokio::test]
    async fn a_live_grant_is_accepted_and_one_without_the_scope_refused() {
        assert_eq!(checked(&google().await, 200).await, AccountCheck::Accepted);
        assert!(matches!(
            checked(&google().await, 403).await,
            AccountCheck::Refused(_)
        ));
    }

    /// A rejected grant fails the account check, while a 503 response from
    /// Google's token endpoint reports the account as unreachable.
    #[tokio::test]
    async fn a_revoked_grant_is_refused_and_a_down_token_address_says_nothing() {
        let revoked = MockServer::start().await;
        Mock::given(path("/token"))
            .respond_with(ResponseTemplate::new(400))
            .mount(&revoked)
            .await;
        let down = MockServer::start().await;
        Mock::given(path("/token"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&down)
            .await;

        let refused = calendar(&revoked).check_account(&grant()).await;
        let unknown = calendar(&down).check_account(&grant()).await;

        assert!(matches!(refused, AccountCheck::Refused(_)));
        assert_eq!(unknown, AccountCheck::Unreachable);
    }

    /// Google Calendar presents itself with a title and icon, and explains
    /// every operation.
    #[tokio::test]
    async fn google_calendar_presents_itself_and_explains_its_operations() {
        let server = MockServer::start().await;
        let calendar = calendar(&server);

        assert_eq!(calendar.profile().icon().as_str(), "google-calendar");
        assert_eq!(calendar.guides().len(), calendar.operations().len());
    }
}
