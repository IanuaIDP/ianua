//! Twilio as a workflow integration, installed under `twilio`: a step
//! sends, schedules, cancels, reads, lists and deletes text messages,
//! starts, ends, reads and lists phone calls, and lists the account's
//! numbers, through an account the tenant connected.
//!
//! The crate is a description handed to the SDK's
//! [`RestService`](ianua_integration::rest::service::RestService). A Twilio
//! account holds `{"account", "token"}`, its SID and auth token, or adds
//! `"key"` to sign with an API key and its secret instead. Every call goes
//! to the account's own place in Twilio's 2010-04-01 API, which takes
//! forms and answers JSON; listing the account's messages proves a
//! credential.
//!
//! A workflow may also start on a text received on one of the account's
//! numbers (`events`), by pointing the number's incoming texts at the
//! registration. Twilio has no sign-in for apps, so its accounts are always
//! connected with credentials pasted in.

#![cfg_attr(not(test), warn(clippy::too_many_lines))]

mod events;
mod operations;

use std::time::Duration;

use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::domains::workflows::integration::form::{PreviewKind, PreviewPart};
use ianua_domain::shared::errors::DomainError;
use ianua_integration::ServiceEndpoint;
use ianua_integration::describe::ProfileText;
use ianua_integration::form::PreviewText;
use ianua_integration::rest::access::Access;
use ianua_integration::rest::event::ServiceEvents;
use ianua_integration::rest::operation::Verb;
use ianua_integration::rest::service::{Answers, Probe, RestService, RestServiceParams};
use ianua_integration::rest::watch::WatchCalls;

use crate::events::Numbers;

/// Twilio's public API.
pub const PUBLIC_API: &str = "https://api.twilio.com/";

/// Where accounts sit under Twilio's API, each under its SID.
const ACCOUNTS: &[&str] = &["2010-04-01", "Accounts"];

/// How the integration presents itself.
const PROFILE: ProfileText<'static> = ProfileText {
    title: "Twilio",
    description: "Sends text and WhatsApp messages and places phone calls from a team's Twilio numbers, through an account SID and auth token or an API key the tenant connects.",
    icon: "twilio",
    picture: include_str!("../assets/icon.svg"),
    brand: "f22f46",
};

/// How sending a text is previewed: as the message on its reader's phone.
const PREVIEWS: &[PreviewText] = &[PreviewText {
    operation: "send-message",
    kind: PreviewKind::TextMessage,
    parts: &[
        (PreviewPart::Place, "to"),
        (PreviewPart::Sender, "from"),
        (PreviewPart::Body, "body"),
    ],
}];

/// How the Twilio integration is set up for this deployment.
#[derive(Debug, Clone)]
pub struct TwilioSettings {
    /// Where Twilio's API answers: [`PUBLIC_API`], or a stand-in's.
    pub endpoint: ServiceEndpoint,
    /// How long one call may take.
    pub timeout: Duration,
    /// The most sensitive data a step may send, and so the most sensitive
    /// an answer is counted as.
    pub ceiling: DataClassLevel,
}

/// The Twilio integration, set up by `settings`.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when the client cannot be built
/// or the endpoint takes no path, and `DomainError::Validation` when the
/// description breaks a rule.
pub fn integration(settings: &TwilioSettings) -> Result<RestService, DomainError> {
    let access = Access::Account {
        base: accounts(&settings.endpoint)?,
    };
    let numbers = Numbers::new(
        WatchCalls::new(access.clone(), &[], settings.timeout)?,
        settings.ceiling,
    );
    RestService::new(RestServiceParams {
        key: "twilio",
        profile: PROFILE,
        operations: operations::all().collect(),
        previews: PREVIEWS,
        access,
        headers: &[],
        probe: Probe {
            verb: Verb::Get,
            path: &["Messages.json"],
            query: &[("PageSize", "1")],
        },
        answers: Answers::ByStatus,
        timeout: settings.timeout,
        ceiling: settings.ceiling,
        sign_in: None,
        events: Some(ServiceEvents {
            described: events::all(),
            watcher: Box::new(numbers),
        }),
    })
}

/// Where accounts sit under `endpoint`.
fn accounts(endpoint: &ServiceEndpoint) -> Result<ServiceEndpoint, DomainError> {
    let Ok(url) = endpoint.url(ACCOUNTS) else {
        return Err(DomainError::infra_msg("Twilio's address takes no path"));
    };
    ServiceEndpoint::at(url.as_str())
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

    /// Twilio's own description of its 2010-04-01 API, which every
    /// operation is checked against. Twilio publishes it at
    /// `twilio/twilio-oai/spec/json/twilio_api_v2010.json`; what the
    /// operations use of it is kept in `api-description.json`. To refresh
    /// it, download the file and run the tests with
    /// `IANUA_TWILIO_API_DESCRIPTION=/path/to/twilio_api_v2010.json`. Its
    /// paths start with the account's place, which the account's address
    /// holds.
    fn description() -> Description {
        Description {
            kept: std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("api-description.json"),
            setting: "IANUA_TWILIO_API_DESCRIPTION",
            lead: &["2010-04-01", "Accounts", "{}"],
        }
    }

    /// Every operation calls an endpoint Twilio describes, with only the
    /// parameters and form fields it knows, always sending those it
    /// requires, and promising only outputs and statuses its answer
    /// carries; and the extract holds exactly those endpoints.
    #[test]
    fn every_operation_fits_twilios_api_description() {
        let description = description();
        let extract = description.extract(all()).unwrap();

        let wrong = description.misfits(all(), &extract);

        assert!(wrong.is_empty(), "{}", wrong.join("\n"));
        assert_eq!(
            Description::kept_endpoints(&extract),
            Description::called_endpoints(all()),
            "refresh the extract with IANUA_TWILIO_API_DESCRIPTION"
        );
    }

    /// An account as a test writes it: not shaped like a real one.
    const ACCOUNT: &str = r#"{"account": "AC1", "token": "test auth token"}"#;

    /// The `Authorization` header the account signs with.
    const SIGNED: &str = "Basic QUMxOnRlc3QgYXV0aCB0b2tlbg==";

    fn twilio(server: &MockServer) -> RestService {
        integration(&TwilioSettings {
            endpoint: ServiceEndpoint::at(&server.uri()).unwrap(),
            timeout: Duration::from_secs(2),
            ceiling: DataClassLevel::Internal,
        })
        .unwrap()
    }

    fn account() -> Secret {
        Secret::new(ACCOUNT.to_owned())
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
            integration: IntegrationKey::new("twilio").unwrap(),
            operation: OperationKey::new(operation).unwrap(),
            account: ActionAccount::Account(IntegrationAccountId::new()),
            arguments,
            effect: DeclaredAction::Undeclared,
            exposure: DataClassLevel::Internal,
            origin: EventOrigin::Outside,
        }
    }

    fn page() -> ActionCall {
        step(
            "send-message",
            vec![
                ("to", text("+15551234567")),
                ("from", text("+15557654321")),
                ("body", text("The nightly build failed")),
            ],
        )
    }

    /// Ann's workflow texts the person on call: the form goes to the
    /// account's messages signed with its SID and token, and Twilio's
    /// message SID is the step's output.
    #[tokio::test]
    async fn a_text_goes_to_the_accounts_messages_signed_by_it() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/2010-04-01/Accounts/AC1/Messages.json"))
            .and(header("authorization", SIGNED))
            .and(header("content-type", "application/x-www-form-urlencoded"))
            .and(body_string(
                "Body=The+nightly+build+failed&From=%2B15557654321&To=%2B15551234567",
            ))
            .respond_with(
                ResponseTemplate::new(201)
                    .set_body_json(json!({ "sid": "SM1", "status": "queued" })),
            )
            .expect(1)
            .mount(&server)
            .await;

        let outcome = twilio(&server)
            .call(&page(), Some(&account()))
            .await
            .outcome;

        let ActionOutcome::Succeeded { output, .. } = outcome else {
            panic!("the text was not sent: {outcome:?}");
        };
        let json = output.field(&FieldName::new("json").unwrap()).unwrap();
        assert_eq!(
            json.field(&FieldName::new("sid").unwrap()),
            Some(&text("SM1"))
        );
    }

    /// Twilio's invalid-number response fails the message step, while a
    /// 429 response turns it away.
    #[tokio::test]
    async fn a_refused_number_fails_and_a_busy_twilio_turns_away() {
        let refusing = MockServer::start().await;
        Mock::given(path("/2010-04-01/Accounts/AC1/Messages.json"))
            .respond_with(
                ResponseTemplate::new(400)
                    .set_body_json(json!({ "code": 21211, "message": "Invalid To number" })),
            )
            .mount(&refusing)
            .await;
        let busy = MockServer::start().await;
        Mock::given(path("/2010-04-01/Accounts/AC1/Messages.json"))
            .respond_with(ResponseTemplate::new(429))
            .mount(&busy)
            .await;

        let refused = twilio(&refusing)
            .call(&page(), Some(&account()))
            .await
            .outcome;
        let turned = twilio(&busy).call(&page(), Some(&account())).await.outcome;

        assert!(matches!(refused, ActionOutcome::Failed(_)));
        assert!(matches!(turned, ActionOutcome::TurnedAway(_)));
    }

    /// A bare token without an account SID fails the message step without
    /// sending a request to Twilio.
    #[tokio::test]
    async fn an_account_without_its_sid_sends_nothing() {
        let server = MockServer::start().await;

        let outcome = twilio(&server)
            .call(&page(), Some(&Secret::new("just a token".to_owned())))
            .await
            .outcome;

        assert!(matches!(outcome, ActionOutcome::Failed(_)));
        assert_eq!(server.received_requests().await.unwrap().len(), 0);
    }

    /// Twilio listing the account's messages for a credential.
    async fn checked(status: u16) -> AccountCheck {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/2010-04-01/Accounts/AC1/Messages.json"))
            .and(query_param("PageSize", "1"))
            .and(header("authorization", SIGNED))
            .respond_with(ResponseTemplate::new(status).set_body_json(json!({ "messages": [] })))
            .expect(1)
            .mount(&server)
            .await;
        twilio(&server).check_account(&account()).await
    }

    /// Tess connects the account: Twilio lists its messages, so it is
    /// taken; a token Twilio does not know is refused; Twilio down says
    /// nothing of it.
    #[tokio::test]
    async fn a_live_account_is_accepted_and_an_unknown_one_refused() {
        assert_eq!(checked(200).await, AccountCheck::Accepted);
        assert!(matches!(checked(401).await, AccountCheck::Refused(_)));
        assert_eq!(checked(503).await, AccountCheck::Unreachable);
    }

    /// Twilio presents itself with a title and icon, and explains every
    /// operation.
    #[tokio::test]
    async fn twilio_presents_itself_and_explains_its_operations() {
        let server = MockServer::start().await;
        let twilio = twilio(&server);

        assert_eq!(twilio.profile().icon().as_str(), "twilio");
        assert_eq!(twilio.guides().len(), twilio.operations().len());
    }
}
