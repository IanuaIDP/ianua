//! What Slack sends that a workflow may start on: a message posted in one
//! channel.
//!
//! Slack sends every event of the deployment's Slack app, from every
//! workspace that installed it, to one address, signed with the app's
//! signing secret. A delivery there is routed by the workspace it names to
//! the registrations of that workspace, and each reads it again, checking
//! the signature first. Publishing a workflow learns the account's
//! workspace and has its bot join the channel, since Slack only sends a
//! bot the messages of channels it is in; nothing is registered at Slack
//! itself, so archiving removes nothing there and the bot stays for the
//! other workflows. Messages posted by a bot, the platform's own among
//! them, start nothing, so a workflow posting in the channel it watches
//! never starts itself.

use async_trait::async_trait;
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::domains::workflows::integration::InputNeed;
use ianua_domain::domains::workflows::integration::events::ServiceEventKey;
use ianua_domain::shared::clock;
use ianua_domain::shared::security::secret::Secret;
use ianua_integration::events::{
    AppRoute, Delivery, Events, HeldCredential, Read, Watch, WatchFailure, Watching,
};
use ianua_integration::rest::event::{EventText, FilterText, picked};
use ianua_integration::rest::operation::Verb;
use ianua_integration::rest::watch::{WatchBody, WatchCall, WatchCalls};
use ianua_integration::signature::{hmac_sha256, matches_hex};
use serde_json::{Value, json};

/// How far a delivery's time may be from now, in seconds, as Slack asks,
/// so a recorded delivery cannot be played again later.
const LARGEST_SKEW: i64 = 300;

/// The channel every message event is watched in.
const CHANNEL: FilterText = FilterText {
    name: "channel",
    need: InputNeed::Required,
    meaning: "The channel to watch, by its id, such as C0123ABCD; the bot joins it when the workflow is published.",
};

/// A message posted in a channel.
const MESSAGE_POSTED: EventText = EventText {
    key: "message-posted",
    title: "A message is posted",
    description: "Someone posts a message in the channel. Edits, joins and messages posted by bots start nothing.",
    filters: &[CHANNEL],
    outputs: &[
        ("team_id", "The workspace."),
        ("event.channel", "The channel."),
        ("event.user", "Who posted it."),
        ("event.text", "What it says."),
        (
            "event.ts",
            "The message's timestamp, which replies and reactions name it by.",
        ),
        (
            "event.thread_ts",
            "The thread it was posted in, when it is a reply.",
        ),
    ],
};

/// Every event Slack offers, described.
pub(crate) fn all() -> Vec<&'static EventText> {
    vec![&MESSAGE_POSTED]
}

/// Slack's events for workflow triggers, through the deployment's app.
pub(crate) struct AppEvents {
    calls: WatchCalls,
    signing: Secret,
    exposure: DataClassLevel,
}

impl AppEvents {
    /// Events of the app whose deliveries are signed with `signing`, its
    /// calls made through `calls`, counted as sensitive as `exposure`.
    pub(crate) fn new(calls: WatchCalls, signing: Secret, exposure: DataClassLevel) -> Self {
        Self {
            calls,
            signing,
            exposure,
        }
    }

    /// The JSON Slack answered `call` with, when it said yes.
    async fn asked(
        &self,
        credential: &HeldCredential,
        call: WatchCall<'_>,
    ) -> Result<Value, WatchFailure> {
        let json = self.calls.send(credential, call).await?.taken("Slack")?;
        if json["ok"].as_bool() == Some(true) {
            return Ok(json);
        }
        let reason = json["error"].as_str().unwrap_or("an unnamed error");
        Err(WatchFailure::Refused(format!("Slack refused it: {reason}")))
    }

    /// The workspace `credential`'s bot belongs to.
    async fn workspace(&self, credential: &HeldCredential) -> Result<String, WatchFailure> {
        let who = self
            .asked(
                credential,
                WatchCall {
                    verb: Verb::Get,
                    path: &["auth.test"],
                    query: &[],
                    body: None,
                },
            )
            .await?;
        who["team_id"]
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| WatchFailure::Refused("Slack named no workspace".to_owned()))
    }

    /// Whether `delivery` carries the app's signature, made within the
    /// last few minutes.
    fn signed(&self, delivery: Delivery<'_>) -> bool {
        let (Some(given), Some(sent_at)) = (
            delivery
                .header("x-slack-signature")
                .and_then(|header| header.strip_prefix("v0=")),
            delivery.header("x-slack-request-timestamp"),
        ) else {
            return false;
        };
        let Ok(seconds) = sent_at.parse::<i64>() else {
            return false;
        };
        let now = clock::now().unix_timestamp();
        if now.saturating_sub(seconds).abs() > LARGEST_SKEW {
            return false;
        }
        let signed = hmac_sha256(
            self.signing.expose().as_bytes(),
            &[b"v0:", sent_at.as_bytes(), b":", delivery.body],
        );
        matches_hex(&signed, given)
    }
}

#[async_trait]
impl Events for AppEvents {
    async fn register(
        &self,
        credential: &HeldCredential,
        watch: Watch<'_>,
    ) -> Result<Watching, WatchFailure> {
        ensure_known(watch.event)?;
        let channel = channel(watch)?;
        let team = self.workspace(credential).await?;
        let body = json!({ "channel": channel });
        self.asked(
            credential,
            WatchCall {
                verb: Verb::Post,
                path: &["conversations.join"],
                query: &[],
                body: Some(WatchBody::Json(&body)),
            },
        )
        .await?;
        Ok(routed(channel, team))
    }

    async fn renew(
        &self,
        credential: &HeldCredential,
        watch: Watch<'_>,
    ) -> Result<Watching, WatchFailure> {
        let channel = channel(watch)?;
        let team = self.workspace(credential).await?;
        Ok(routed(channel, team))
    }

    async fn unregister(
        &self,
        _credential: &HeldCredential,
        _watch: Watch<'_>,
    ) -> Result<(), WatchFailure> {
        Ok(())
    }

    fn read(&self, watch: Watch<'_>, delivery: Delivery<'_>) -> Read {
        if !self.signed(delivery) {
            return Read::Forged;
        }
        let Ok(payload) = serde_json::from_slice::<Value>(delivery.body) else {
            return Read::Skip;
        };
        let Some(id) = payload["event_id"].as_str() else {
            return Read::Skip;
        };
        if ensure_known(watch.event).is_err() || !posted_by_a_person_in(&payload, watch) {
            return Read::Skip;
        }
        let Ok(input) = picked(&MESSAGE_POSTED, &payload) else {
            return Read::Skip;
        };
        Read::Start {
            delivery: id.to_owned(),
            input,
            exposure: self.exposure,
        }
    }

    fn route(&self, delivery: Delivery<'_>) -> AppRoute {
        if !self.signed(delivery) {
            return AppRoute::Refused;
        }
        let Ok(payload) = serde_json::from_slice::<Value>(delivery.body) else {
            return AppRoute::Refused;
        };
        match (payload["type"].as_str(), payload["team_id"].as_str()) {
            (Some("url_verification"), _) => {
                let challenge = payload["challenge"].as_str().unwrap_or_default();
                AppRoute::Answer(challenge.as_bytes().to_vec())
            }
            (Some("event_callback"), Some(team)) => AppRoute::Keyed(team.to_owned()),
            _ => AppRoute::Answer(Vec::new()),
        }
    }
}

/// The refusal of an event Slack does not offer, unless `key` is one.
fn ensure_known(key: &ServiceEventKey) -> Result<(), WatchFailure> {
    if key.as_str() == MESSAGE_POSTED.key {
        return Ok(());
    }
    Err(WatchFailure::Refused(
        "Slack sends no such event".to_owned(),
    ))
}

/// The channel `watch` watches, as an id Slack gives one.
fn channel<'a>(watch: Watch<'a>) -> Result<&'a str, WatchFailure> {
    let named = watch
        .filter(CHANNEL.name)
        .ok_or_else(|| WatchFailure::Refused("the trigger names no channel".to_owned()))?;
    let plain = !named.is_empty()
        && named
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit());
    match plain {
        true => Ok(named),
        false => Err(WatchFailure::Refused(
            "the channel is named by its id, such as C0123ABCD".to_owned(),
        )),
    }
}

/// A registration Slack keeps until the bot leaves, its events routed by
/// `team`.
fn routed(channel: &str, team: String) -> Watching {
    Watching {
        remote: channel.to_owned(),
        lapses: None,
        routed_by: Some(team),
    }
}

/// Whether `payload` is a message a person posted in the watched channel:
/// not an edit, a join or any other kind, and not a bot's.
fn posted_by_a_person_in(payload: &Value, watch: Watch<'_>) -> bool {
    let event = &payload["event"];
    let a_message = payload["type"] == "event_callback" && event["type"] == "message";
    let plain = event.get("subtype").is_none() && event.get("bot_id").is_none();
    let here = watch
        .filter(CHANNEL.name)
        .is_some_and(|channel| event["channel"].as_str() == Some(channel));
    a_message && plain && here
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use ianua_domain::domains::workflows::data::{DataPath, FieldName, FlowValue};
    use ianua_domain::domains::workflows::triggers::{EventFilter, FilterValue};
    use ianua_integration::ServiceEndpoint;
    use ianua_integration::rest::access::Access;
    use wiremock::matchers::{body_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    const SIGNING: &str = "the slack app's signing words";

    fn events(endpoint: &str) -> AppEvents {
        AppEvents::new(
            WatchCalls::new(
                Access::Bearer {
                    endpoint: ServiceEndpoint::at(endpoint).unwrap(),
                },
                &[],
                Duration::from_secs(2),
            )
            .unwrap(),
            Secret::new(SIGNING.to_owned()),
            DataClassLevel::Internal,
        )
    }

    struct Watched {
        event: ServiceEventKey,
        filters: Vec<EventFilter>,
        secret: Secret,
    }

    impl Watched {
        fn on(channel: &str) -> Self {
            Self {
                event: ServiceEventKey::new("message-posted").unwrap(),
                filters: vec![EventFilter::new(
                    FieldName::new("channel").unwrap(),
                    FilterValue::new(channel).unwrap(),
                )],
                secret: Secret::new("the registration's own words".to_owned()),
            }
        }

        fn watch(&self) -> Watch<'_> {
            Watch {
                event: &self.event,
                filters: &self.filters,
                address: "https://ianua.test/api/v1/integrations/slack/events",
                secret: &self.secret,
                remote: Some("C0SUPPORT"),
            }
        }
    }

    fn token() -> HeldCredential {
        HeldCredential::new(Secret::new("test bot token for acme".to_owned()))
    }

    /// Slack's headers for `body` sent at `at`, signed with `signing`.
    fn sent(body: &[u8], at: i64, signing: &str) -> Vec<(String, String)> {
        let stamp = at.to_string();
        let signature: String =
            hmac_sha256(signing.as_bytes(), &[b"v0:", stamp.as_bytes(), b":", body])
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect();
        vec![
            ("x-slack-request-timestamp".to_owned(), stamp),
            ("x-slack-signature".to_owned(), format!("v0={signature}")),
        ]
    }

    fn now() -> i64 {
        clock::now().unix_timestamp()
    }

    fn posted(channel: &str, extra: &Value) -> Vec<u8> {
        let mut event = json!({
            "type": "message",
            "channel": channel,
            "user": "U0PAT",
            "text": "The login page is down",
            "ts": "1700000000.000100"
        });
        if let (Some(event), Some(extra)) = (event.as_object_mut(), extra.as_object()) {
            event.extend(extra.clone());
        }
        serde_json::to_vec(&json!({
            "type": "event_callback",
            "team_id": "T0ACME",
            "event_id": "Ev0001",
            "event": event
        }))
        .unwrap()
    }

    fn delivered<'a>(headers: &'a [(String, String)], body: &'a [u8]) -> Delivery<'a> {
        Delivery {
            address: "https://ianua.test/api/v1/integrations/slack/events",
            headers,
            body,
        }
    }

    /// Publishing Ann's workflow on #support learns Acme's workspace and
    /// has the bot join the channel; its events are routed by Acme's
    /// workspace.
    #[tokio::test]
    async fn registering_joins_the_channel_and_routes_by_workspace() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/auth.test"))
            .and(header("authorization", "Bearer test bot token for acme"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({ "ok": true, "team_id": "T0ACME" })),
            )
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/conversations.join"))
            .and(body_json(json!({ "channel": "C0SUPPORT" })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "ok": true })))
            .expect(1)
            .mount(&server)
            .await;
        let watched = Watched::on("C0SUPPORT");

        let watching = events(&server.uri())
            .register(&token(), watched.watch())
            .await
            .unwrap();

        assert_eq!(watching.routed_by.as_deref(), Some("T0ACME"));
        assert_eq!(watching.lapses, None);
    }

    /// Slack rejects joining the private channel, so registration fails
    /// with the service's unsupported-channel reason.
    #[tokio::test]
    async fn a_channel_the_bot_cannot_join_is_refused() {
        let server = MockServer::start().await;
        Mock::given(path("/auth.test"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({ "ok": true, "team_id": "T0ACME" })),
            )
            .mount(&server)
            .await;
        Mock::given(path("/conversations.join"))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                json!({ "ok": false, "error": "method_not_supported_for_channel_type" }),
            ))
            .mount(&server)
            .await;
        let watched = Watched::on("G0PRIVATE");

        let refused = events(&server.uri())
            .register(&token(), watched.watch())
            .await;

        assert!(
            matches!(&refused, Err(WatchFailure::Refused(why)) if why.contains("method_not_supported")),
            "{refused:?}"
        );
    }

    /// Pat posts in #support: the signed delivery is routed to Acme's
    /// workspace and starts the workflow with what Pat wrote, under
    /// Slack's event id.
    #[test]
    fn a_signed_message_is_routed_and_starts_the_workflow() {
        let events = events("https://slack.test/api/");
        let watched = Watched::on("C0SUPPORT");
        let body = posted("C0SUPPORT", &json!({}));
        let headers = sent(&body, now(), SIGNING);

        let route = events.route(delivered(&headers, &body));
        let read = events.read(watched.watch(), delivered(&headers, &body));

        assert_eq!(route, AppRoute::Keyed("T0ACME".to_owned()));
        let Read::Start {
            delivery, input, ..
        } = read
        else {
            panic!("nothing started: {read:?}");
        };
        assert_eq!(delivery, "Ev0001");
        assert_eq!(
            input
                .at(&DataPath::parse("event.text").unwrap())
                .map(|text| text.value()),
            Some(FlowValue::Text("The login page is down"))
        );
    }

    /// Slack asks the platform to prove it holds the address; the signed
    /// challenge is answered with itself.
    #[test]
    fn slacks_challenge_is_answered() {
        let events = events("https://slack.test/api/");
        let body = br#"{"type":"url_verification","challenge":"prove it"}"#;
        let headers = sent(body, now(), SIGNING);

        let route = events.route(delivered(&headers, body));

        assert_eq!(route, AppRoute::Answer(b"prove it".to_vec()));
    }

    /// A delivery signed with another secret and a genuine ten-minute-old
    /// delivery are both refused routing and marked forged by the reader.
    #[test]
    fn a_forged_or_old_delivery_is_refused() {
        let events = events("https://slack.test/api/");
        let watched = Watched::on("C0SUPPORT");
        let body = posted("C0SUPPORT", &json!({}));
        let forged = sent(&body, now(), "mallory's own words");
        let replayed = sent(&body, now() - 600, SIGNING);

        for headers in [forged, replayed] {
            assert_eq!(events.route(delivered(&headers, &body)), AppRoute::Refused);
            assert_eq!(
                events.read(watched.watch(), delivered(&headers, &body)),
                Read::Forged
            );
        }
    }

    /// The workflow's own reply posted by the bot, an edit, and a message
    /// in another channel start nothing.
    #[test]
    fn a_bots_message_an_edit_or_another_channel_starts_nothing() {
        let events = events("https://slack.test/api/");
        let watched = Watched::on("C0SUPPORT");
        let bodies = [
            posted("C0SUPPORT", &json!({ "bot_id": "B0IANUA" })),
            posted("C0SUPPORT", &json!({ "subtype": "message_changed" })),
            posted("C0RANDOM", &json!({})),
        ];

        for body in bodies {
            let headers = sent(&body, now(), SIGNING);
            assert_eq!(
                events.read(watched.watch(), delivered(&headers, &body)),
                Read::Skip
            );
        }
    }
}
