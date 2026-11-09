//! What Linear sends that a workflow may start on: an issue created and an
//! issue changed, each in one team.
//!
//! Publishing a workflow registers a webhook for the team's issues through
//! the account's API key, carrying the platform's address for the
//! registration and its secret; Linear only lets a workspace's admins do
//! that, so a key of anyone else is refused when the workflow is published.
//! Linear signs every delivery's body with that secret in its
//! `Linear-Signature` header, and a delivery whose signature does not check
//! out, or that was sent more than a minute ago, is read no further. Only
//! the values each event describes reach the workflow. Linear's webhooks
//! never lapse, so renewing one keeps it as it stands.

use async_trait::async_trait;
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::domains::workflows::integration::InputNeed;
use ianua_domain::domains::workflows::integration::events::ServiceEventKey;
use ianua_domain::shared::clock;
use ianua_domain::shared::security::secret::Secret;
use ianua_integration::events::{
    Delivery, Events, HeldCredential, Read, Watch, WatchFailure, Watching,
};
use ianua_integration::rest::event::{EventText, FilterText, picked};
use ianua_integration::rest::operation::Verb;
use ianua_integration::rest::watch::{Answered, WatchBody, WatchCall, WatchCalls};
use ianua_integration::signature::{hmac_sha256, matches_hex};
use serde_json::{Value, json};

/// How far a delivery's time may be from now, in milliseconds, as Linear
/// asks, so a recorded delivery cannot be played again later.
const LARGEST_SKEW: i128 = 60_000;

/// What Linear calls the issues a webhook sends.
const ISSUE: &str = "Issue";

/// Registering a webhook.
const WEBHOOK_CREATE: &str = "mutation WebhookCreate($input: WebhookCreateInput!) { \
    webhookCreate(input: $input) { success webhook { id enabled } } }";

/// Removing a webhook.
const WEBHOOK_DELETE: &str = "mutation WebhookDelete($id: String!) { \
    webhookDelete(id: $id) { success } }";

/// How Linear begins the message of an error about a thing it does not
/// know, such as a webhook already removed.
const NOT_FOUND: &str = "Entity not found";

/// The code a GraphQL error carries when a key sent too much too fast.
const RATE_LIMITED: &str = "RATELIMITED";

/// The team every event is watched in.
const TEAM: FilterText = FilterText {
    name: "team",
    need: InputNeed::Required,
    meaning: "The team to watch, by its id, as the list-teams step gives it.",
};

/// An issue created.
const ISSUE_CREATED: EventText = EventText {
    key: "issue-created",
    title: "An issue is created",
    description: "Someone creates an issue in the team.",
    filters: &[TEAM],
    outputs: &[
        ("data.id", "The issue's id."),
        (
            "data.identifier",
            "The issue's identifier, such as ENG-123.",
        ),
        ("data.title", "The issue's title."),
        (
            "data.description",
            "The issue's description, as its author wrote it.",
        ),
        (
            "data.priority",
            "How urgent it is: 0 none, 1 urgent to 4 low.",
        ),
        ("data.state.name", "The state it is in, such as Todo."),
        ("data.team.key", "The key of its team, such as ENG."),
        ("data.assignee.name", "Who it is assigned to."),
        ("url", "The issue's page in Linear."),
        ("actor.name", "Who created it."),
    ],
};

/// An issue changed.
const ISSUE_UPDATED: EventText = EventText {
    key: "issue-updated",
    title: "An issue is changed",
    description: "Someone changes an issue in the team, such as its state, title or assignee.",
    filters: &[TEAM],
    outputs: &[
        ("data.id", "The issue's id."),
        (
            "data.identifier",
            "The issue's identifier, such as ENG-123.",
        ),
        ("data.title", "The issue's title."),
        (
            "data.priority",
            "How urgent it is: 0 none, 1 urgent to 4 low.",
        ),
        ("data.state.name", "The state it is in now, such as Done."),
        (
            "data.state.type",
            "The kind of that state, such as started or completed.",
        ),
        ("data.assignee.name", "Who it is assigned to now."),
        (
            "updatedFrom.stateId",
            "The id of the state it was in, when the state changed.",
        ),
        (
            "updatedFrom.assigneeId",
            "The id of who had it, when the assignee changed.",
        ),
        ("url", "The issue's page in Linear."),
        ("actor.name", "Who changed it."),
    ],
};

/// One event as Linear names it: the action on an issue.
struct Kind {
    text: &'static EventText,
    action: &'static str,
}

/// Every event, with Linear's action for it.
const KINDS: &[Kind] = &[
    Kind {
        text: &ISSUE_CREATED,
        action: "create",
    },
    Kind {
        text: &ISSUE_UPDATED,
        action: "update",
    },
];

/// Every event Linear offers, described.
pub(crate) fn all() -> Vec<&'static EventText> {
    KINDS.iter().map(|kind| kind.text).collect()
}

/// Linear's webhooks for workflow triggers.
pub(crate) struct Hooks {
    calls: WatchCalls,
    exposure: DataClassLevel,
}

impl Hooks {
    /// Webhooks registered through `calls`, their deliveries counted as
    /// sensitive as `exposure`.
    pub(crate) fn new(calls: WatchCalls, exposure: DataClassLevel) -> Self {
        Self { calls, exposure }
    }

    /// What Linear answered the GraphQL `document` with `variables`.
    async fn asked(
        &self,
        credential: &HeldCredential,
        document: &str,
        variables: Value,
    ) -> Result<Answered, WatchFailure> {
        let body = json!({ "query": document, "variables": variables });
        self.calls
            .send(
                credential,
                WatchCall {
                    verb: Verb::Post,
                    path: &["graphql"],
                    query: &[],
                    body: Some(WatchBody::Json(&body)),
                },
            )
            .await
    }
}

#[async_trait]
impl Events for Hooks {
    async fn register(
        &self,
        credential: &HeldCredential,
        watch: Watch<'_>,
    ) -> Result<Watching, WatchFailure> {
        kind_of(watch.event).ok_or_else(unknown)?;
        let team = team(watch)?;
        let input = json!({
            "url": watch.address,
            "teamId": team,
            "resourceTypes": [ISSUE],
            "secret": watch.secret.expose(),
            "label": "Ianua workflow",
        });
        let data = data_of(
            self.asked(credential, WEBHOOK_CREATE, json!({ "input": input }))
                .await?,
        )?;
        let Some(id) = data["webhookCreate"]["webhook"]["id"].as_str() else {
            return Err(WatchFailure::Refused("Linear named no webhook".to_owned()));
        };
        Ok(standing(id.to_owned()))
    }

    async fn renew(
        &self,
        _credential: &HeldCredential,
        watch: Watch<'_>,
    ) -> Result<Watching, WatchFailure> {
        let Some(remote) = watch.remote else {
            return Err(WatchFailure::Refused(
                "the webhook was never registered".to_owned(),
            ));
        };
        Ok(standing(remote.to_owned()))
    }

    async fn unregister(
        &self,
        credential: &HeldCredential,
        watch: Watch<'_>,
    ) -> Result<(), WatchFailure> {
        let Some(remote) = watch.remote else {
            return Ok(());
        };
        let answered = self
            .asked(credential, WEBHOOK_DELETE, json!({ "id": remote }))
            .await?;
        if first_error(&answered.json)
            .and_then(|error| error["message"].as_str())
            .is_some_and(|message| message.starts_with(NOT_FOUND))
        {
            return Ok(());
        }
        data_of(answered).map(|_| ())
    }

    fn read(&self, watch: Watch<'_>, delivery: Delivery<'_>) -> Read {
        if !signed(watch.secret, delivery) {
            return Read::Forged;
        }
        let Some(kind) = kind_of(watch.event) else {
            return Read::Skip;
        };
        let (Some(id), Some(ISSUE)) = (
            delivery.header("linear-delivery"),
            delivery.header("linear-event"),
        ) else {
            return Read::Skip;
        };
        let Ok(payload) = serde_json::from_slice::<Value>(delivery.body) else {
            return Read::Skip;
        };
        if !recent(&payload) || !passes(kind, &payload, watch) {
            return Read::Skip;
        }
        let Ok(input) = picked(kind.text, &payload) else {
            return Read::Skip;
        };
        Read::Start {
            delivery: id.to_owned(),
            input,
            exposure: self.exposure,
        }
    }
}

/// The event `key` names, if Linear offers it.
fn kind_of(key: &ServiceEventKey) -> Option<&'static Kind> {
    KINDS.iter().find(|kind| kind.text.key == key.as_str())
}

/// The refusal of an event Linear does not offer.
fn unknown() -> WatchFailure {
    WatchFailure::Refused("Linear sends no such event".to_owned())
}

/// The team `watch` watches.
fn team<'a>(watch: Watch<'a>) -> Result<&'a str, WatchFailure> {
    watch
        .filter(TEAM.name)
        .filter(|team| !team.trim().is_empty())
        .ok_or_else(|| WatchFailure::Refused("the trigger names no team".to_owned()))
}

/// A webhook Linear keeps as `remote` until it is removed.
fn standing(remote: String) -> Watching {
    Watching {
        remote,
        lapses: None,
        routed_by: None,
    }
}

/// The first error of a GraphQL answer, when it carries any.
fn first_error(json: &Value) -> Option<&Value> {
    json["errors"].as_array().and_then(|errors| errors.first())
}

/// The data of `answered`, a GraphQL answer, when Linear took the call:
/// an error refuses it, and a rate limit is to be tried again.
fn data_of(answered: Answered) -> Result<Value, WatchFailure> {
    let json = answered.taken("Linear")?;
    let Some(error) = first_error(&json) else {
        return Ok(json["data"].clone());
    };
    if error["extensions"]["code"].as_str() == Some(RATE_LIMITED) {
        return Err(WatchFailure::Unreachable);
    }
    let reason = error["message"].as_str().unwrap_or("an unnamed error");
    Err(WatchFailure::Refused(format!(
        "Linear refused it: {reason}"
    )))
}

/// Whether `delivery` carries Linear's signature of its body under
/// `secret`.
fn signed(secret: &Secret, delivery: Delivery<'_>) -> bool {
    let Some(given) = delivery.header("linear-signature") else {
        return false;
    };
    matches_hex(
        &hmac_sha256(secret.expose().as_bytes(), &[delivery.body]),
        given,
    )
}

/// Whether `payload` was sent within the last minute, by the time Linear
/// put in it.
fn recent(payload: &Value) -> bool {
    let Some(sent) = payload["webhookTimestamp"].as_i64() else {
        return false;
    };
    let now = clock::now().unix_timestamp_nanos() / 1_000_000;
    (now - i128::from(sent)).abs() <= LARGEST_SKEW
}

/// Whether `payload` is `kind`'s action on an issue in the watched team.
fn passes(kind: &Kind, payload: &Value, watch: Watch<'_>) -> bool {
    let action = payload["action"].as_str() == Some(kind.action);
    let issue = payload["type"].as_str() == Some(ISSUE);
    let in_team = watch
        .filter(TEAM.name)
        .is_some_and(|watched| payload["data"]["teamId"].as_str() == Some(watched));
    action && issue && in_team
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use ianua_domain::domains::workflows::data::{DataPath, FieldName, FlowData, FlowValue};
    use ianua_domain::domains::workflows::triggers::{EventFilter, FilterValue};
    use ianua_integration::ServiceEndpoint;
    use ianua_integration::rest::access::Access;
    use wiremock::matchers::{body_partial_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    const ADDRESS: &str = "https://ianua.test/api/v1/integrations/linear/events/one";

    const SECRET: &str = "the registration's secret words";

    fn hooks_at(endpoint: &str) -> Hooks {
        Hooks::new(
            WatchCalls::new(
                Access::Scheme {
                    endpoint: ServiceEndpoint::at(endpoint).unwrap(),
                    scheme: "",
                },
                &[],
                Duration::from_secs(2),
            )
            .unwrap(),
            DataClassLevel::Internal,
        )
    }

    fn hooks(server: &MockServer) -> Hooks {
        hooks_at(&server.uri())
    }

    struct Watched {
        event: ServiceEventKey,
        filters: Vec<EventFilter>,
        secret: Secret,
        remote: Option<&'static str>,
    }

    impl Watched {
        fn on(event: &str, team: &str) -> Self {
            Self {
                event: ServiceEventKey::new(event).unwrap(),
                filters: vec![EventFilter::new(
                    FieldName::new("team").unwrap(),
                    FilterValue::new(team).unwrap(),
                )],
                secret: Secret::new(SECRET.to_owned()),
                remote: Some("webhook one"),
            }
        }

        fn watch(&self) -> Watch<'_> {
            Watch {
                event: &self.event,
                filters: &self.filters,
                address: ADDRESS,
                secret: &self.secret,
                remote: self.remote,
            }
        }
    }

    fn key() -> HeldCredential {
        HeldCredential::new(Secret::new("test key for ann".to_owned()))
    }

    fn now_millis() -> i64 {
        i64::try_from(clock::now().unix_timestamp_nanos() / 1_000_000).unwrap()
    }

    fn issue_payload(action: &str, team: &str, sent: i64) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "action": action,
            "type": "Issue",
            "data": {
                "id": "issue one",
                "identifier": "ENG-7",
                "title": "Login fails",
                "description": "Steps to reproduce",
                "teamId": team,
                "team": { "key": "ENG" },
                "state": { "name": "Todo", "type": "unstarted" },
                "subscriberIds": ["someone"]
            },
            "url": "https://linear.app/acme/issue/ENG-7",
            "actor": { "name": "Pat" },
            "webhookTimestamp": sent
        }))
        .unwrap()
    }

    /// The headers Linear sends with `body`, signed with `secret`.
    fn sent(body: &[u8], secret: &str) -> Vec<(String, String)> {
        let signature = hmac_sha256(secret.as_bytes(), &[body])
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        vec![
            ("linear-event".to_owned(), "Issue".to_owned()),
            ("linear-delivery".to_owned(), "delivery one".to_owned()),
            ("linear-signature".to_owned(), signature),
        ]
    }

    fn read(watched: &Watched, headers: &[(String, String)], body: &[u8]) -> Read {
        hooks_at("https://api.linear.test/").read(
            watched.watch(),
            Delivery {
                address: ADDRESS,
                headers,
                body,
            },
        )
    }

    /// Ann's workflow watches the team for new issues: publishing registers
    /// a webhook for its issues, carrying the platform's address and the
    /// registration's secret, and keeps Linear's id for it.
    #[tokio::test]
    async fn registering_makes_a_webhook_for_the_teams_issues() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/graphql"))
            .and(header("authorization", "test key for ann"))
            .and(body_partial_json(json!({
                "query": WEBHOOK_CREATE,
                "variables": { "input": {
                    "url": ADDRESS,
                    "teamId": "team one",
                    "resourceTypes": ["Issue"],
                    "secret": SECRET
                } }
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": { "webhookCreate": { "success": true, "webhook": { "id": "webhook one", "enabled": true } } }
            })))
            .expect(1)
            .mount(&server)
            .await;
        let watched = Watched::on("issue-created", "team one");

        let watching = hooks(&server)
            .register(&key(), watched.watch())
            .await
            .unwrap();

        assert_eq!(watching.remote, "webhook one");
        assert_eq!(watching.lapses, None);
    }

    /// GraphQL errors in a 200 response prevent registration: an admin
    /// refusal retains its reason, while rate limiting returns Unreachable.
    #[tokio::test]
    async fn an_error_in_the_answer_registers_nothing() {
        let refused = MockServer::start().await;
        Mock::given(path("/graphql"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": null,
                "errors": [{ "message": "Only admins can create webhooks" }]
            })))
            .mount(&refused)
            .await;
        let limited = MockServer::start().await;
        Mock::given(path("/graphql"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "errors": [{ "message": "Slow down", "extensions": { "code": "RATELIMITED" } }]
            })))
            .mount(&limited)
            .await;
        let watched = Watched::on("issue-created", "team one");

        let no = hooks(&refused).register(&key(), watched.watch()).await;
        let busy = hooks(&limited).register(&key(), watched.watch()).await;

        assert!(matches!(no, Err(WatchFailure::Refused(why)) if why.contains("Only admins")));
        assert_eq!(busy, Err(WatchFailure::Unreachable));
    }

    /// Archiving removes the webhook; one Linear no longer knows counts as
    /// removed.
    #[tokio::test]
    async fn unregistering_removes_the_webhook_even_when_gone() {
        let removed = MockServer::start().await;
        Mock::given(path("/graphql"))
            .and(body_partial_json(
                json!({ "variables": { "id": "webhook one" } }),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": { "webhookDelete": { "success": true } }
            })))
            .expect(1)
            .mount(&removed)
            .await;
        let gone = MockServer::start().await;
        Mock::given(path("/graphql"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "errors": [{ "message": "Entity not found: Webhook" }]
            })))
            .mount(&gone)
            .await;
        let watched = Watched::on("issue-created", "team one");

        assert_eq!(
            hooks(&removed).unregister(&key(), watched.watch()).await,
            Ok(())
        );
        assert_eq!(
            hooks(&gone).unregister(&key(), watched.watch()).await,
            Ok(())
        );
    }

    /// Pat creates ENG-7 in the team: the signed delivery starts the
    /// workflow with the issue's identifier, under Linear's delivery id,
    /// and nothing the event does not describe reaches it.
    #[test]
    fn a_signed_issue_created_starts_the_workflow() {
        let watched = Watched::on("issue-created", "team one");
        let body = issue_payload("create", "team one", now_millis());

        let started = read(&watched, &sent(&body, SECRET), &body);

        let Read::Start {
            delivery, input, ..
        } = started
        else {
            panic!("the issue started nothing: {started:?}");
        };
        assert_eq!(delivery, "delivery one");
        assert_eq!(
            input
                .at(&DataPath::parse("data.identifier").unwrap())
                .map(FlowData::value),
            Some(FlowValue::Text("ENG-7"))
        );
        assert!(
            input
                .at(&DataPath::parse("data.subscriberIds").unwrap())
                .is_none()
        );
    }

    /// An issue delivery signed with another secret or sent unsigned is
    /// marked forged rather than returned as a workflow start.
    #[test]
    fn a_forged_delivery_is_not_read() {
        let watched = Watched::on("issue-created", "team one");
        let body = issue_payload("create", "team one", now_millis());
        let unsigned: Vec<(String, String)> = sent(&body, SECRET)
            .into_iter()
            .filter(|(name, _)| name != "linear-signature")
            .collect();

        let forged = read(&watched, &sent(&body, "mallory's secret words"), &body);
        let bare = read(&watched, &unsigned, &body);

        assert_eq!(forged, Read::Forged);
        assert_eq!(bare, Read::Forged);
    }

    /// A correctly signed delivery with a two-minute-old timestamp is
    /// skipped rather than returned as a workflow start.
    #[test]
    fn an_old_delivery_starts_nothing() {
        let watched = Watched::on("issue-created", "team one");
        let body = issue_payload("create", "team one", now_millis() - 120_000);

        let replayed = read(&watched, &sent(&body, SECRET), &body);

        assert_eq!(replayed, Read::Skip);
    }

    /// A change starts only a workflow watching for changes, and an issue of
    /// another team starts nothing.
    #[test]
    fn another_action_or_team_starts_nothing() {
        let created = Watched::on("issue-created", "team one");
        let updated = Watched::on("issue-updated", "team one");
        let change = issue_payload("update", "team one", now_millis());
        let elsewhere = issue_payload("create", "team two", now_millis());

        let skipped = read(&created, &sent(&change, SECRET), &change);
        let started = read(&updated, &sent(&change, SECRET), &change);
        let other_team = read(&created, &sent(&elsewhere, SECRET), &elsewhere);

        assert_eq!(skipped, Read::Skip);
        assert!(matches!(started, Read::Start { .. }), "{started:?}");
        assert_eq!(other_team, Read::Skip);
    }
}
