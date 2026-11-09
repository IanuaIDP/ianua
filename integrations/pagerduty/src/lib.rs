//! PagerDuty as a workflow integration, installed under `pagerduty`: a step
//! lists, reads, opens, acknowledges, resolves and snoozes incidents, adds
//! a note to one, lists who is on call now, and lists the account's
//! services, escalation policies and people, through the API key of an
//! account the tenant connected.
//!
//! The crate is a description handed to the SDK's
//! [`RestService`](ianua_integration::rest::service::RestService): its
//! profile, its operations, each described once in `operations/`, how an
//! account reaches PagerDuty, the headers PagerDuty asks for, and the
//! request that proves a key. Requests, refusals, answers and key checks
//! are the SDK's.
//!
//! The account holds the key alone, which PagerDuty takes in the
//! `Authorization` header after `Token token=`, or `{"token", "from"}`. A
//! user API token acts as its person. An account-wide key reads, but
//! PagerDuty takes a change to an incident from it only beside a `From`
//! header naming one of its users: an account that holds such a key with
//! `from`, that user's email address, sends it on every call, and one
//! without has its changes refused by PagerDuty. The key is asked
//! about at PagerDuty before it is kept, with a request both kinds may
//! make, and sent only to the PagerDuty API this deployment names, never
//! to an address a step chooses: a step names an incident by its id, and
//! the address is built from it with every part checked and escaped. No
//! redirect is followed.
//!
//! A workflow may also start on an incident triggered, acknowledged or
//! resolved on one service (`events`), through a webhook subscription made
//! with the account's key and proven by the registration's own secret.

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

use crate::events::Hooks;

/// PagerDuty's public API.
pub const PUBLIC_API: &str = "https://api.pagerduty.com/";

/// How the integration presents itself.
const PROFILE: ProfileText<'static> = ProfileText {
    title: "PagerDuty",
    description: "Opens, acknowledges, resolves and snoozes incidents, adds notes and finds who is on call in a team's PagerDuty account, through an API key the tenant connects.",
    icon: "pagerduty",
    picture: include_str!("../assets/icon.svg"),
    brand: "06ac38",
};

/// How opening an incident is previewed: as an issue on its service.
const PREVIEWS: &[PreviewText] = &[PreviewText {
    operation: "create-incident",
    kind: PreviewKind::Issue,
    parts: &[
        (PreviewPart::Place, "service"),
        (PreviewPart::Title, "title"),
        (PreviewPart::Body, "details"),
    ],
}];

/// The headers PagerDuty asks every call to carry: its version 2 API.
const HEADERS: &[(&str, &str)] = &[
    ("accept", "application/vnd.pagerduty+json;version=2"),
    ("user-agent", "ianua-workflows"),
];

/// How PagerDuty takes an API key in the `Authorization` header.
const SCHEME: &str = "Token token=";

/// How the PagerDuty integration is set up for this deployment.
#[derive(Debug, Clone)]
pub struct PagerDutySettings {
    /// Where PagerDuty's API answers: [`PUBLIC_API`], or a stand-in's.
    pub endpoint: ServiceEndpoint,
    /// How long one call may take.
    pub timeout: Duration,
    /// The most sensitive data a step may send to PagerDuty, and so the
    /// most sensitive an answer or an event is counted as.
    pub ceiling: DataClassLevel,
}

/// The PagerDuty integration, set up by `settings`.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when a client cannot be built,
/// and `DomainError::Validation` when the description breaks a rule.
pub fn integration(settings: PagerDutySettings) -> Result<RestService, DomainError> {
    let access = Access::SchemeActingFor {
        endpoint: settings.endpoint,
        scheme: SCHEME,
    };
    let hooks = Hooks::new(
        WatchCalls::new(access.clone(), HEADERS, settings.timeout)?,
        settings.ceiling,
    );
    RestService::new(RestServiceParams {
        key: "pagerduty",
        profile: PROFILE,
        operations: operations::all().collect(),
        previews: PREVIEWS,
        access,
        headers: HEADERS,
        probe: Probe {
            verb: Verb::Get,
            path: &["abilities"],
            query: &[],
        },
        answers: Answers::ByStatus,
        timeout: settings.timeout,
        ceiling: settings.ceiling,
        sign_in: None,
        events: Some(ServiceEvents {
            described: events::all(),
            watcher: Box::new(hooks),
        }),
    })
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

    /// PagerDuty's own description of its REST API, which every operation
    /// is checked against. PagerDuty publishes it at
    /// `PagerDuty/api-schema/reference/REST/openapiv3.json`; what the
    /// operations use of it is kept in `api-description.json`. To refresh
    /// it, download the file and run the tests with
    /// `IANUA_PAGERDUTY_API_DESCRIPTION=/path/to/openapiv3.json`.
    fn description() -> Description {
        Description {
            kept: std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("api-description.json"),
            setting: "IANUA_PAGERDUTY_API_DESCRIPTION",
            lead: &[],
        }
    }

    /// Every operation calls an endpoint PagerDuty describes, with only the
    /// query parameters and body properties it knows, always sending those
    /// it requires, and promising only outputs and statuses its answer
    /// carries; and the extract holds exactly those endpoints.
    #[test]
    fn every_operation_fits_pagerdutys_api_description() {
        let description = description();
        let extract = description.extract(all()).unwrap();

        let wrong = description.misfits(all(), &extract);

        assert!(wrong.is_empty(), "{}", wrong.join("\n"));
        assert_eq!(
            Description::kept_endpoints(&extract),
            Description::called_endpoints(all()),
            "refresh the extract with IANUA_PAGERDUTY_API_DESCRIPTION"
        );
    }

    /// A key as a test writes it: not shaped like a real one.
    const KEY: &str = "acme pagerduty key for workflows";

    fn pagerduty(server: &MockServer) -> RestService {
        integration(PagerDutySettings {
            endpoint: ServiceEndpoint::at(&format!("{}/", server.uri())).unwrap(),
            timeout: Duration::from_secs(2),
            ceiling: DataClassLevel::Internal,
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
            integration: IntegrationKey::new("pagerduty").unwrap(),
            operation: OperationKey::new(operation).unwrap(),
            account: ActionAccount::Account(IntegrationAccountId::new()),
            arguments,
            effect: DeclaredAction::Undeclared,
            exposure: DataClassLevel::Internal,
            origin: EventOrigin::Outside,
        }
    }

    fn new_incident(service: &str) -> ActionCall {
        call(
            "create-incident",
            arguments(vec![
                ("service", text(service)),
                ("title", text("Checkout is failing")),
            ]),
        )
    }

    async fn requests_made(server: &MockServer) -> usize {
        server.received_requests().await.unwrap().len()
    }

    /// Ann's workflow opens an incident on the checkout service: PagerDuty
    /// is asked with her key after its scheme and its version 2 header,
    /// with the incident wrapped as it asks, and the new incident's id
    /// comes back in the step's output.
    #[tokio::test]
    async fn an_incident_is_opened_with_the_accounts_key() {
        let server = MockServer::start().await;
        let authorization = format!("Token token={KEY}");
        Mock::given(method("POST"))
            .and(path("/incidents"))
            .and(header("authorization", authorization.as_str()))
            .and(header("accept", "application/vnd.pagerduty+json;version=2"))
            .and(body_json(json!({
                "incident": {
                    "type": "incident",
                    "title": "Checkout is failing",
                    "service": { "id": "PWIXJZS", "type": "service_reference" },
                    "body": { "type": "incident_body" }
                }
            })))
            .respond_with(
                ResponseTemplate::new(201)
                    .set_body_json(json!({ "incident": { "id": "Q2LKJQ1" } })),
            )
            .expect(1)
            .mount(&server)
            .await;

        let outcome = pagerduty(&server)
            .call(&new_incident("PWIXJZS"), Some(&Secret::new(KEY.to_owned())))
            .await
            .outcome;

        let ActionOutcome::Succeeded { output, .. } = outcome else {
            panic!("the incident was not opened: {outcome:?}");
        };
        assert_eq!(incident_id(&output), Some(FlowValue::Text("Q2LKJQ1")));
    }

    /// Ann's account holds an account-wide key with her email address:
    /// PagerDuty is told in `From` that the incident is opened on her
    /// behalf, as it requires for such a key.
    #[tokio::test]
    async fn an_account_wide_key_acts_for_its_named_person() {
        let server = MockServer::start().await;
        let authorization = format!("Token token={KEY}");
        Mock::given(method("POST"))
            .and(path("/incidents"))
            .and(header("authorization", authorization.as_str()))
            .and(header("from", "ann@acme.test"))
            .respond_with(
                ResponseTemplate::new(201)
                    .set_body_json(json!({ "incident": { "id": "Q2LKJQ1" } })),
            )
            .expect(1)
            .mount(&server)
            .await;
        let account = json!({ "token": KEY, "from": "ann@acme.test" }).to_string();

        let outcome = pagerduty(&server)
            .call(&new_incident("PWIXJZS"), Some(&Secret::new(account)))
            .await
            .outcome;

        assert!(
            matches!(outcome, ActionOutcome::Succeeded { .. }),
            "{outcome:?}"
        );
    }

    /// An account naming someone who is no email address sends nothing.
    #[tokio::test]
    async fn a_person_to_act_for_who_is_no_address_sends_nothing() {
        let server = MockServer::start().await;
        let account = json!({ "token": KEY, "from": "ann" }).to_string();

        let outcome = pagerduty(&server)
            .call(&new_incident("PWIXJZS"), Some(&Secret::new(account)))
            .await
            .outcome;

        assert!(matches!(outcome, ActionOutcome::Failed(_)), "{outcome:?}");
        assert_eq!(requests_made(&server).await, 0);
    }

    /// The id of the incident PagerDuty answered with, in a step's output.
    fn incident_id(output: &FlowData) -> Option<FlowValue<'_>> {
        output
            .field(&FieldName::new("json").unwrap())
            .and_then(|json| json.field(&FieldName::new("incident").unwrap()))
            .and_then(|incident| incident.field(&FieldName::new("id").unwrap()))
            .map(FlowData::value)
    }

    /// Missing or blank keys fail the incident step without sending a
    /// request to PagerDuty.
    #[tokio::test]
    async fn no_key_or_a_blank_one_sends_nothing() {
        let server = MockServer::start().await;
        let pagerduty = pagerduty(&server);

        let without = pagerduty.call(&new_incident("PWIXJZS"), None).await.outcome;
        let blank = pagerduty
            .call(
                &new_incident("PWIXJZS"),
                Some(&Secret::new("  ".to_owned())),
            )
            .await
            .outcome;

        for outcome in [without, blank] {
            assert!(matches!(outcome, ActionOutcome::Failed(_)), "{outcome:?}");
        }
        assert_eq!(requests_made(&server).await, 0);
    }

    /// PagerDuty refusing a change, as it refuses an account-wide key that
    /// names nobody, fails the step; PagerDuty limiting the rate turns it
    /// away, to be tried again.
    #[tokio::test]
    async fn a_refusal_fails_and_a_busy_pagerduty_turns_away() {
        let refusing = MockServer::start().await;
        Mock::given(path("/incidents"))
            .respond_with(ResponseTemplate::new(400))
            .mount(&refusing)
            .await;
        let busy = MockServer::start().await;
        Mock::given(path("/incidents"))
            .respond_with(ResponseTemplate::new(429))
            .mount(&busy)
            .await;
        let key = Secret::new(KEY.to_owned());

        let refused = pagerduty(&refusing)
            .call(&new_incident("PWIXJZS"), Some(&key))
            .await
            .outcome;
        let turned = pagerduty(&busy)
            .call(&new_incident("PWIXJZS"), Some(&key))
            .await
            .outcome;

        assert!(matches!(refused, ActionOutcome::Failed(_)));
        assert!(matches!(turned, ActionOutcome::TurnedAway(_)));
    }

    /// PagerDuty's redirect fails the incident step, and the destination
    /// host receives no request.
    #[tokio::test]
    async fn a_redirect_is_not_followed() {
        let elsewhere = MockServer::start().await;
        let server = MockServer::start().await;
        Mock::given(path("/incidents"))
            .respond_with(
                ResponseTemplate::new(307)
                    .insert_header("location", format!("{}/steal", elsewhere.uri()).as_str()),
            )
            .mount(&server)
            .await;

        let outcome = pagerduty(&server)
            .call(&new_incident("PWIXJZS"), Some(&Secret::new(KEY.to_owned())))
            .await
            .outcome;

        assert!(matches!(outcome, ActionOutcome::Failed(_)));
        assert_eq!(requests_made(&elsewhere).await, 0);
    }

    /// PagerDuty answering what a key may do with `status`.
    async fn checked(status: u16, key: &str) -> AccountCheck {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/abilities"))
            .and(header(
                "authorization",
                format!("Token token={KEY}").as_str(),
            ))
            .respond_with(ResponseTemplate::new(status))
            .mount(&server)
            .await;
        Mock::given(path("/abilities"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&server)
            .await;
        pagerduty(&server)
            .check_account(&Secret::new(key.to_owned()))
            .await
    }

    /// Tess connects the team's key: PagerDuty says what it may do, so it
    /// is taken, whether it is a person's token or the account's key.
    #[tokio::test]
    async fn a_key_pagerduty_knows_is_accepted() {
        assert_eq!(checked(200, KEY).await, AccountCheck::Accepted);
    }

    /// PagerDuty's 401 response to a mistyped key refuses the account check.
    #[tokio::test]
    async fn a_key_pagerduty_does_not_know_is_refused() {
        let answer = checked(200, "a mistyped key").await;

        assert!(matches!(answer, AccountCheck::Refused(_)));
    }

    /// PagerDuty limiting the rate or failing says nothing of the key, so
    /// the check is unreachable, never accepted.
    #[tokio::test]
    async fn a_busy_or_failing_pagerduty_says_nothing_of_the_key() {
        for status in [429, 500, 503] {
            assert_eq!(checked(status, KEY).await, AccountCheck::Unreachable);
        }
    }

    /// PagerDuty presents itself with a title, icon and its green, and
    /// explains every one of its operations.
    #[tokio::test]
    async fn pagerduty_presents_itself_and_explains_its_operations() {
        let server = MockServer::start().await;
        let pagerduty = pagerduty(&server);

        assert_eq!(pagerduty.profile().title().as_str(), "PagerDuty");
        assert_eq!(pagerduty.profile().icon().as_str(), "pagerduty");
        assert_eq!(pagerduty.guides().len(), pagerduty.operations().len());
        assert_eq!(pagerduty.events().len(), 3);
    }
}
