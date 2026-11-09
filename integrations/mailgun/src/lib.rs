//! Mailgun as a workflow integration, installed under `mailgun`: a step
//! sends an email, reads what happened to the domain's mail, reads and
//! lifts bounces, unsubscribes and resubscribes addresses, and manages a
//! mailing list's members, through an account the tenant connected.
//!
//! The crate is a description handed to the SDK's
//! [`RestService`](ianua_integration::rest::service::RestService). A Mailgun
//! account holds its API key alone, for Mailgun's US region, or
//! `{"key", "region"}` with `us` or `eu`, and adds `"domain"` for a key
//! that may only send from that domain. The key is sent as the password of
//! the user `api`. Mailgun takes forms and answers JSON. Listing the
//! account's domains proves an account's key; a key limited to one domain
//! is proven by a send naming nobody, which Mailgun refuses for its missing
//! fields only once it has taken the key, so nothing is sent.
//!
//! A workflow may also start on mail delivered, failed for good or opened
//! on a domain (`events`), through a webhook added with an account's key.
//! Mailgun has no sign-in for apps, so its accounts are always connected
//! with a key pasted in.

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
use ianua_integration::rest::access::{Access, LimitedProbe, Regions};
use ianua_integration::rest::event::ServiceEvents;
use ianua_integration::rest::operation::Verb;
use ianua_integration::rest::service::{Answers, Probe, RestService, RestServiceParams};
use ianua_integration::rest::watch::WatchCalls;

use crate::events::Webhooks;

/// Mailgun's public API in the US.
pub const PUBLIC_API: &str = "https://api.mailgun.net/";

/// How a key that may only send from one domain proves itself: a send
/// from that domain naming nobody, which Mailgun answers `400` for its
/// missing fields once it has taken the key, and `401` or `403` otherwise.
const SENDING_KEY: LimitedProbe = LimitedProbe {
    field: "domain",
    verb: Verb::Post,
    before: &["v3"],
    after: &["messages"],
    taken: 400,
};

/// How the integration presents itself.
const PROFILE: ProfileText<'static> = ProfileText {
    title: "Mailgun",
    description: "Sends email from a team's Mailgun domains, reads what happened to it and manages suppressions and mailing lists, through an API key the tenant connects.",
    icon: "mailgun",
    picture: include_str!("../assets/icon.svg"),
    brand: "c02126",
};

/// How sending an email is previewed: as the email its reader opens.
const PREVIEWS: &[PreviewText] = &[PreviewText {
    operation: "send-message",
    kind: PreviewKind::Email,
    parts: &[
        (PreviewPart::Sender, "from"),
        (PreviewPart::Place, "to"),
        (PreviewPart::Title, "subject"),
        (PreviewPart::Body, "text"),
    ],
}];

/// How the Mailgun integration is set up for this deployment.
#[derive(Debug, Clone)]
pub struct MailgunSettings {
    /// Where Mailgun's US region answers: [`PUBLIC_API`], or a stand-in's.
    /// An account naming no region goes here.
    pub us: ServiceEndpoint,
    /// Where Mailgun's EU region answers: `https://api.eu.mailgun.net/`, or a
    /// stand-in's.
    pub eu: ServiceEndpoint,
    /// How long one call may take.
    pub timeout: Duration,
    /// The most sensitive data a step may send, and so the most sensitive
    /// an answer is counted as.
    pub ceiling: DataClassLevel,
}

/// The Mailgun integration, set up by `settings`.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when the client cannot be built,
/// and `DomainError::Validation` when the description breaks a rule.
pub fn integration(settings: MailgunSettings) -> Result<RestService, DomainError> {
    let access = Access::Key {
        regions: Regions::new(("us", settings.us), [("eu", settings.eu)]),
        user: "api",
        limited: Some(SENDING_KEY),
    };
    let webhooks = Webhooks::new(
        WatchCalls::new(access.clone(), &[], settings.timeout)?,
        settings.ceiling,
    );
    RestService::new(RestServiceParams {
        key: "mailgun",
        profile: PROFILE,
        operations: operations::all().collect(),
        previews: PREVIEWS,
        access,
        headers: &[],
        probe: Probe {
            verb: Verb::Get,
            path: &["v4", "domains"],
            query: &[("limit", "1")],
        },
        answers: Answers::ByStatus,
        timeout: settings.timeout,
        ceiling: settings.ceiling,
        sign_in: None,
        events: Some(ServiceEvents {
            described: events::all(),
            watcher: Box::new(webhooks),
        }),
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
    use ianua_integration::rest::openapi::Description;
    use serde_json::json;
    use wiremock::matchers::{body_string, header, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::operations::all;

    /// Mailgun's own description of its API, which every operation is
    /// checked against. Mailgun publishes it at
    /// `https://documentation.mailgun.com/_spec/docs/mailgun/api-reference/send/mailgun.json`;
    /// what the operations use of it is kept in `api-description.json`. To
    /// refresh it, download the file and run the tests with
    /// `IANUA_MAILGUN_API_DESCRIPTION=/path/to/mailgun.json`.
    fn description() -> Description {
        Description {
            kept: std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("api-description.json"),
            setting: "IANUA_MAILGUN_API_DESCRIPTION",
            lead: &[],
        }
    }

    /// Every operation calls an endpoint Mailgun describes, with only the
    /// parameters and form fields it knows, always sending those it
    /// requires, and promising only outputs and statuses its answer
    /// carries; and the extract holds exactly those endpoints.
    #[test]
    fn every_operation_fits_mailguns_api_description() {
        let description = description();
        let extract = description.extract(all()).unwrap();

        let wrong = description.misfits(all(), &extract);

        assert!(wrong.is_empty(), "{}", wrong.join("\n"));
        assert_eq!(
            Description::kept_endpoints(&extract),
            Description::called_endpoints(all()),
            "refresh the extract with IANUA_MAILGUN_API_DESCRIPTION"
        );
    }

    /// A key as a test writes it: not shaped like a real one.
    const KEY: &str = "test mailgun key";

    /// The `Authorization` header the key is sent in.
    const SIGNED: &str = "Basic YXBpOnRlc3QgbWFpbGd1biBrZXk=";

    /// Mailgun with its US region at `us` and its EU region at `eu`.
    fn regional(us: &MockServer, eu: &MockServer) -> RestService {
        integration(MailgunSettings {
            us: ServiceEndpoint::at(&us.uri()).unwrap(),
            eu: ServiceEndpoint::at(&eu.uri()).unwrap(),
            timeout: Duration::from_secs(2),
            ceiling: DataClassLevel::Internal,
        })
        .unwrap()
    }

    /// Mailgun with both regions at `server`.
    fn mailgun(server: &MockServer) -> RestService {
        regional(server, server)
    }

    fn key() -> Secret {
        Secret::new(KEY.to_owned())
    }

    fn text(value: &str) -> FlowData {
        FlowData::text(value).unwrap()
    }

    fn report() -> ActionCall {
        let arguments = FlowData::map(
            [
                ("domain", text("mail.acme.test")),
                ("from", text("ops@mail.acme.test")),
                ("to", FlowData::list(vec![text("ann@acme.test")]).unwrap()),
                ("subject", text("Nightly build")),
                ("text", text("The nightly build failed")),
            ]
            .into_iter()
            .map(|(name, value)| (FieldName::new(name).unwrap(), value))
            .collect(),
        )
        .unwrap();
        ActionCall {
            call_id: ActionCallId::new(),
            integration: IntegrationKey::new("mailgun").unwrap(),
            operation: OperationKey::new("send-message").unwrap(),
            account: ActionAccount::Account(IntegrationAccountId::new()),
            arguments,
            effect: DeclaredAction::Undeclared,
            exposure: DataClassLevel::Internal,
            origin: EventOrigin::Outside,
        }
    }

    /// Ann's workflow mails the build report: the form goes to the
    /// domain's messages with the key as `api`'s password, and Mailgun's
    /// message id is the step's output.
    #[tokio::test]
    async fn an_email_goes_to_the_domain_signed_by_the_key() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v3/mail.acme.test/messages"))
            .and(header("authorization", SIGNED))
            .and(header("content-type", "application/x-www-form-urlencoded"))
            .and(body_string(
                "from=ops%40mail.acme.test&subject=Nightly+build\
                 &text=The+nightly+build+failed&to=ann%40acme.test",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": "<20261102.1@mail.acme.test>",
                "message": "Queued. Thank you."
            })))
            .expect(1)
            .mount(&server)
            .await;

        let outcome = mailgun(&server).call(&report(), Some(&key())).await.outcome;

        assert!(
            matches!(outcome, ActionOutcome::Succeeded { .. }),
            "{outcome:?}"
        );
    }

    /// Mailgun's invalid-sender response fails the mail step, while a 429
    /// response turns it away.
    #[tokio::test]
    async fn a_refused_email_fails_and_a_limited_one_turns_away() {
        let refusing = MockServer::start().await;
        Mock::given(path("/v3/mail.acme.test/messages"))
            .respond_with(
                ResponseTemplate::new(400)
                    .set_body_json(json!({ "message": "from parameter is not a valid address" })),
            )
            .mount(&refusing)
            .await;
        let limited = MockServer::start().await;
        Mock::given(path("/v3/mail.acme.test/messages"))
            .respond_with(ResponseTemplate::new(429))
            .mount(&limited)
            .await;

        let refused = mailgun(&refusing)
            .call(&report(), Some(&key()))
            .await
            .outcome;
        let turned = mailgun(&limited)
            .call(&report(), Some(&key()))
            .await
            .outcome;

        assert!(matches!(refused, ActionOutcome::Failed(_)));
        assert!(matches!(turned, ActionOutcome::TurnedAway(_)));
    }

    /// Mailgun listing the account's domains for a key.
    async fn checked(status: u16) -> AccountCheck {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v4/domains"))
            .and(query_param("limit", "1"))
            .and(header("authorization", SIGNED))
            .respond_with(ResponseTemplate::new(status).set_body_json(json!({ "items": [] })))
            .expect(1)
            .mount(&server)
            .await;
        mailgun(&server).check_account(&key()).await
    }

    /// Tess connects the key: Mailgun lists the domains, so it is taken; a
    /// key Mailgun does not know is refused; Mailgun down says nothing of
    /// it.
    #[tokio::test]
    async fn a_live_key_is_accepted_and_an_unknown_one_refused() {
        assert_eq!(checked(200).await, AccountCheck::Accepted);
        assert!(matches!(checked(401).await, AccountCheck::Refused(_)));
        assert!(matches!(checked(403).await, AccountCheck::Refused(_)));
        assert_eq!(checked(503).await, AccountCheck::Unreachable);
    }

    /// Mailgun answering a key limited to `mail.acme.test` with `status`
    /// for a send naming nobody.
    async fn sending_key_checked(status: u16) -> AccountCheck {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v3/mail.acme.test/messages"))
            .and(header("authorization", SIGNED))
            .and(body_string(""))
            .respond_with(
                ResponseTemplate::new(status)
                    .set_body_json(json!({ "message": "from parameter is missing" })),
            )
            .expect(1)
            .mount(&server)
            .await;
        let account = Secret::new(json!({ "key": KEY, "domain": "mail.acme.test" }).to_string());
        mailgun(&server).check_account(&account).await
    }

    /// Tess connects a key that may only send from the team's domain:
    /// Mailgun takes it and refuses the empty send for its missing fields,
    /// so the key is accepted and nothing is mailed. A key Mailgun does not
    /// take for the domain is refused.
    #[tokio::test]
    async fn a_sending_key_is_proven_without_sending_anything() {
        let taken = sending_key_checked(400).await;
        let refused = sending_key_checked(401).await;
        let unknown = sending_key_checked(503).await;

        assert_eq!(taken, AccountCheck::Accepted);
        assert!(matches!(refused, AccountCheck::Refused(_)));
        assert_eq!(unknown, AccountCheck::Unreachable);
    }

    /// Ann's team is in Mailgun's EU region: its account names `eu`, so the
    /// email goes there and the US region hears nothing.
    #[tokio::test]
    async fn a_key_naming_the_eu_region_sends_there() {
        let us = MockServer::start().await;
        let eu = MockServer::start().await;
        Mock::given(path("/v3/mail.acme.test/messages"))
            .and(header("authorization", SIGNED))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "id": "<1@eu>" })))
            .expect(1)
            .mount(&eu)
            .await;
        let european = Secret::new(json!({ "key": KEY, "region": "eu" }).to_string());

        let outcome = regional(&us, &eu)
            .call(&report(), Some(&european))
            .await
            .outcome;

        assert!(
            matches!(outcome, ActionOutcome::Succeeded { .. }),
            "{outcome:?}"
        );
        assert_eq!(us.received_requests().await.unwrap().len(), 0);
    }

    /// Mailgun presents itself with a title and icon, and explains every
    /// operation.
    #[tokio::test]
    async fn mailgun_presents_itself_and_explains_its_operations() {
        let server = MockServer::start().await;
        let mailgun = mailgun(&server);

        assert_eq!(mailgun.profile().icon().as_str(), "mailgun");
        assert_eq!(mailgun.guides().len(), mailgun.operations().len());
    }
}
