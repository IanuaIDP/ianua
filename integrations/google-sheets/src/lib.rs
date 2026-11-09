//! Google Sheets as a workflow integration, installed under
//! `google-sheets`: a step lists a spreadsheet's tabs, creates a
//! spreadsheet, reads cells, adds rows, writes over cells and clears them,
//! through an account the tenant connected.
//!
//! The crate is a description handed to the SDK's
//! [`RestService`](ianua_integration::rest::service::RestService). A Google
//! account holds `{"client_id", "client_secret", "refresh_token"}`: the
//! tenant's own OAuth client and a grant to the spreadsheets scope. Before
//! each call the grant is exchanged at Google's token address for a token
//! lasting an hour, which signs the call; the grant itself never leaves
//! for the Sheets API.
//!
//! Google Sheets has no address that answers for an account alone, as
//! Calendar's own calendar list does: every read names a spreadsheet. A
//! grant is proven by reading the id of Google's own public sample
//! spreadsheet, which any token with the spreadsheets scope may read and
//! which holds nothing of the tenant's. A revoked grant is refused at the
//! token address before that, and a token without the scope is refused by
//! the read.
//!
//! With the deployment's OAuth client set, a person connects an account by
//! signing in at Google instead, and the account keeps the client and the
//! grant Google issues in the same shape.
//!
//! Google Sheets sends no notifications of its own (a changed file is told
//! through Drive's API, a different service), so no workflow starts on it.

#![cfg_attr(not(test), warn(clippy::too_many_lines))]

mod operations;

use std::time::Duration;

use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::shared::errors::DomainError;
use ianua_integration::ServiceEndpoint;
use ianua_integration::connect::SignIn;
use ianua_integration::describe::ProfileText;
use ianua_integration::rest::access::Access;
use ianua_integration::rest::operation::Verb;
use ianua_integration::rest::service::{Answers, Probe, RestService, RestServiceParams};
use ianua_integration::rest::sign_in::{OAuthSignIn, SignInSettings};

/// Google Sheets' public API.
pub const PUBLIC_API: &str = "https://sheets.googleapis.com/v4/";

/// Google's token address, where a grant is exchanged for a token.
pub const PUBLIC_TOKEN: &str = "https://oauth2.googleapis.com/token";

/// Where Google signs people in.
pub const PUBLIC_AUTHORIZE: &str = "https://accounts.google.com/o/oauth2/v2/auth";

/// Google's public sample spreadsheet, from its Sheets quickstarts, which
/// the probe reads to prove a grant.
const SAMPLE_SPREADSHEET: &str = "1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs74OgvE2upms";

/// How the integration presents itself.
const PROFILE: ProfileText<'static> = ProfileText {
    title: "Google Sheets",
    description: "Reads and writes a team's Google spreadsheets: adds rows, reads and writes cells and clears them, through an OAuth grant the tenant connects.",
    icon: "google-sheets",
    picture: include_str!("../assets/icon.svg"),
    brand: "188038",
};

/// The scope a signed-in account is granted: the spreadsheets, which every
/// step needs.
const SCOPES: &[&str] = &["https://www.googleapis.com/auth/spreadsheets"];

/// How the Google Sheets integration is set up for this deployment.
#[derive(Debug, Clone)]
pub struct GoogleSheetsSettings {
    /// Where Google Sheets' API answers: [`PUBLIC_API`], or a stand-in's.
    pub endpoint: ServiceEndpoint,
    /// Where a grant is exchanged for a token: [`PUBLIC_TOKEN`], or a
    /// stand-in's.
    pub token: ServiceEndpoint,
    /// How long one call may take.
    pub timeout: Duration,
    /// The most sensitive data a step may send, and so the most sensitive
    /// an answer is counted as.
    pub ceiling: DataClassLevel,
    /// The deployment's OAuth client at Google, at [`PUBLIC_AUTHORIZE`] and
    /// [`PUBLIC_TOKEN`] or a stand-in's, when one is registered; without
    /// it, accounts are connected with a client and grant pasted in.
    pub sign_in: Option<SignInSettings>,
}

/// The Google Sheets integration, set up by `settings`.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when the client cannot be built,
/// and `DomainError::Validation` when the description breaks a rule.
pub fn integration(settings: GoogleSheetsSettings) -> Result<RestService, DomainError> {
    RestService::new(RestServiceParams {
        key: "google-sheets",
        profile: PROFILE,
        operations: operations::all().collect(),
        previews: &[],
        access: Access::Refreshed {
            endpoint: settings.endpoint,
            token: settings.token,
        },
        headers: &[],
        probe: Probe {
            verb: Verb::Get,
            path: &["spreadsheets", SAMPLE_SPREADSHEET],
            query: &[("fields", "spreadsheetId")],
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
/// the scope the spreadsheet steps need.
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

    /// Google Sheets' API described as OpenAPI 3, which every operation is
    /// checked against. Google publishes it as a discovery document;
    /// APIs.guru converts that to
    /// `https://api.apis.guru/v2/specs/googleapis.com/sheets/v4/openapi.json`,
    /// whose paths start with `/v4`, and what the operations use of it is
    /// kept in `api-description.json`. To refresh it, download the file and
    /// run the tests with
    /// `IANUA_GOOGLE_SHEETS_API_DESCRIPTION=/path/to/openapi.json`.
    fn description() -> Description {
        Description {
            kept: std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("api-description.json"),
            setting: "IANUA_GOOGLE_SHEETS_API_DESCRIPTION",
            lead: &["v4"],
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
            "refresh the extract with IANUA_GOOGLE_SHEETS_API_DESCRIPTION"
        );
    }

    /// A grant as a test writes it: not shaped like a real one.
    const GRANT: &str = r#"{"client_id": "acme app", "client_secret": "app words", "refresh_token": "lasting grant"}"#;

    /// Google's stand-in: its token address issuing `short token` for the
    /// grant, and its Sheets API under `/v4`.
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

    fn sheets(server: &MockServer) -> RestService {
        integration(GoogleSheetsSettings {
            endpoint: ServiceEndpoint::at(&format!("{}/v4/", server.uri())).unwrap(),
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
            integration: IntegrationKey::new("google-sheets").unwrap(),
            operation: OperationKey::new(operation).unwrap(),
            account: ActionAccount::Account(IntegrationAccountId::new()),
            arguments,
            effect: DeclaredAction::Undeclared,
            exposure: DataClassLevel::Internal,
            origin: EventOrigin::Outside,
        }
    }

    fn order() -> ActionCall {
        step(
            "append-rows",
            vec![
                ("spreadsheet", text("sheet-of-orders")),
                ("sheet", text("Orders")),
                (
                    "rows",
                    FlowData::list(vec![FlowData::list(vec![text("Ann"), text("3")]).unwrap()])
                        .unwrap(),
                ),
                ("input", text("RAW")),
            ],
        )
    }

    /// Ann's workflow adds an order: the grant is exchanged for a token,
    /// which signs the row sent under the Orders tab.
    #[tokio::test]
    async fn a_row_is_added_with_a_token_the_grant_was_exchanged_for() {
        let server = google().await;
        Mock::given(method("POST"))
            .and(path(
                "/v4/spreadsheets/sheet-of-orders/values/Orders:append",
            ))
            .and(query_param("valueInputOption", "RAW"))
            .and(header("authorization", "Bearer short token"))
            .and(body_json(json!({ "values": [["Ann", "3"]] })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "spreadsheetId": "sheet-of-orders",
                "updates": { "updatedRange": "Orders!A2:B2", "updatedRows": 1 }
            })))
            .expect(1)
            .mount(&server)
            .await;

        let outcome = sheets(&server).call(&order(), Some(&grant())).await.outcome;

        assert!(
            matches!(outcome, ActionOutcome::Succeeded { .. }),
            "{outcome:?}"
        );
    }

    /// Appending rows without an input mode fails without sending any
    /// request to Google, including a token exchange.
    #[tokio::test]
    async fn a_step_that_cannot_be_sent_never_exchanges_the_grant() {
        let server = MockServer::start().await;
        let unsaid = step(
            "append-rows",
            vec![
                ("spreadsheet", text("sheet-of-orders")),
                ("sheet", text("Orders")),
                ("rows", FlowData::list(vec![]).unwrap()),
            ],
        );

        let outcome = sheets(&server).call(&unsaid, Some(&grant())).await.outcome;

        assert!(matches!(outcome, ActionOutcome::Failed(_)));
        assert_eq!(server.received_requests().await.unwrap().len(), 0);
    }

    /// Google's invalid-grant response fails the append step; all requests
    /// stay at the token endpoint.
    #[tokio::test]
    async fn a_revoked_grant_fails_without_calling_sheets() {
        let server = MockServer::start().await;
        Mock::given(path("/token"))
            .respond_with(
                ResponseTemplate::new(400).set_body_json(json!({ "error": "invalid_grant" })),
            )
            .mount(&server)
            .await;

        let outcome = sheets(&server).call(&order(), Some(&grant())).await.outcome;

        assert!(matches!(outcome, ActionOutcome::Failed(_)));
        let calls = server.received_requests().await.unwrap();
        assert!(calls.iter().all(|call| call.url.path() == "/token"));
    }

    /// Google reading the sample spreadsheet's id for a grant, answering
    /// `status`.
    async fn checked(server: &MockServer, status: u16) -> AccountCheck {
        Mock::given(method("GET"))
            .and(path(format!("/v4/spreadsheets/{SAMPLE_SPREADSHEET}")))
            .and(query_param("fields", "spreadsheetId"))
            .and(header("authorization", "Bearer short token"))
            .respond_with(
                ResponseTemplate::new(status)
                    .set_body_json(json!({ "spreadsheetId": SAMPLE_SPREADSHEET })),
            )
            .mount(server)
            .await;
        sheets(server).check_account(&grant()).await
    }

    /// Tess connects the grant: Google issues a token and reads the sample
    /// spreadsheet, so it is taken; a token without the spreadsheets scope
    /// is refused.
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

        let refused = sheets(&revoked).check_account(&grant()).await;
        let unknown = sheets(&down).check_account(&grant()).await;

        assert!(matches!(refused, AccountCheck::Refused(_)));
        assert_eq!(unknown, AccountCheck::Unreachable);
    }

    /// Google Sheets presents itself with a title, icon and brand colour,
    /// and explains every operation.
    #[tokio::test]
    async fn google_sheets_presents_itself_and_explains_its_operations() {
        let server = MockServer::start().await;
        let sheets = sheets(&server);

        assert_eq!(sheets.profile().icon().as_str(), "google-sheets");
        assert_eq!(sheets.profile().brand().as_str(), "188038");
        assert_eq!(sheets.guides().len(), sheets.operations().len());
        assert!(sheets.events().is_empty());
    }
}
