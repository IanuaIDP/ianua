//! What Google Calendar sends that a workflow may start on: a calendar
//! changed.
//!
//! Publishing a workflow opens a watch channel on its calendar through the
//! account's grant, carrying the platform's address for the registration
//! and its secret as the channel's token, which Google sends back on every
//! notification; one without it, or from a channel replaced since, is read
//! no further. A notification says only that the calendar changed, never
//! what: a workflow lists the events it needs. Google never extends a
//! channel, so renewing opens a new one and stops the old; an old one that
//! cannot be stopped lapses on its own, and what it still sends is skipped
//! as no longer the registration's channel. Archiving stops the channel.

use async_trait::async_trait;
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::domains::workflows::integration::InputNeed;
use ianua_domain::domains::workflows::integration::events::ServiceEventKey;
use ianua_domain::shared::clock;
use ianua_integration::events::{
    Delivery, Events, HeldCredential, Read, Watch, WatchFailure, Watching,
};
use ianua_integration::rest::event::{EventText, FilterText, picked};
use ianua_integration::rest::operation::Verb;
use ianua_integration::rest::watch::{WatchBody, WatchCall, WatchCalls};
use ianua_integration::signature::same_secret;
use serde_json::{Value, json};
use time::OffsetDateTime;

/// How long a channel is asked to last, in seconds: a week.
const CHANNEL_SECONDS: &str = "604800";

/// The calendar every change is watched on.
const CALENDAR: FilterText = FilterText {
    name: "calendar",
    need: InputNeed::Required,
    meaning: "The calendar to watch, such as primary or the calendar's address.",
};

/// A calendar changed.
const CALENDAR_CHANGED: EventText = EventText {
    key: "calendar-changed",
    title: "A calendar changes",
    description: "An event is added to the calendar, changed or removed. Google does not say which: list the calendar's events to find out.",
    filters: &[CALENDAR],
    outputs: &[
        ("calendar", "The calendar that changed."),
        (
            "message_number",
            "The notification's number on its channel, counting up.",
        ),
    ],
};

/// Every event Google Calendar offers, described.
pub(crate) fn all() -> Vec<&'static EventText> {
    vec![&CALENDAR_CHANGED]
}

/// Google Calendar's watch channels for workflow triggers.
pub(crate) struct Channels {
    calls: WatchCalls,
    exposure: DataClassLevel,
}

impl Channels {
    /// Channels opened through `calls`, their notifications counted as
    /// sensitive as `exposure`.
    pub(crate) fn new(calls: WatchCalls, exposure: DataClassLevel) -> Self {
        Self { calls, exposure }
    }

    /// Opens a new channel for `watch`.
    async fn open(
        &self,
        credential: &HeldCredential,
        watch: Watch<'_>,
    ) -> Result<Watching, WatchFailure> {
        ensure_known(watch.event)?;
        let calendar = calendar(watch)?;
        let id = channel_id(watch.address)?;
        let body = json!({
            "id": id,
            "type": "web_hook",
            "address": watch.address,
            "token": watch.secret.expose(),
            "params": { "ttl": CHANNEL_SECONDS },
        });
        let taken = self
            .calls
            .send(
                credential,
                WatchCall {
                    verb: Verb::Post,
                    path: &["calendars", calendar, "events", "watch"],
                    query: &[],
                    body: Some(WatchBody::Json(&body)),
                },
            )
            .await?
            .taken("Google Calendar")?;
        opened(&id, &taken)
    }
}

#[async_trait]
impl Events for Channels {
    async fn register(
        &self,
        credential: &HeldCredential,
        watch: Watch<'_>,
    ) -> Result<Watching, WatchFailure> {
        self.open(credential, watch).await
    }

    async fn renew(
        &self,
        credential: &HeldCredential,
        watch: Watch<'_>,
    ) -> Result<Watching, WatchFailure> {
        let opened = self.open(credential, watch).await?;
        let _left_to_lapse = self.unregister(credential, watch).await;
        Ok(opened)
    }

    async fn unregister(
        &self,
        credential: &HeldCredential,
        watch: Watch<'_>,
    ) -> Result<(), WatchFailure> {
        let Some((id, resource)) = watch.remote.and_then(|remote| remote.split_once(' ')) else {
            return Ok(());
        };
        let body = json!({ "id": id, "resourceId": resource });
        let answered = self
            .calls
            .send(
                credential,
                WatchCall {
                    verb: Verb::Post,
                    path: &["channels", "stop"],
                    query: &[],
                    body: Some(WatchBody::Json(&body)),
                },
            )
            .await?;
        if answered.status == 404 {
            return Ok(());
        }
        answered.taken("Google Calendar").map(|_| ())
    }

    fn read(&self, watch: Watch<'_>, delivery: Delivery<'_>) -> Read {
        let token = delivery.header("x-goog-channel-token").unwrap_or_default();
        if !same_secret(watch.secret.expose(), token) {
            return Read::Forged;
        }
        let current = watch.remote.and_then(|remote| remote.split_once(' '));
        let (Some((id, _)), Some(sent_by), Some(number)) = (
            current,
            delivery.header("x-goog-channel-id"),
            delivery.header("x-goog-message-number"),
        ) else {
            return Read::Skip;
        };
        let changed = delivery.header("x-goog-resource-state") == Some("exists");
        let calendar = watch.filter(CALENDAR.name).unwrap_or_default();
        let Ok(number) = number.parse::<u64>() else {
            return Read::Skip;
        };
        if ensure_known(watch.event).is_err() || sent_by != id || !changed {
            return Read::Skip;
        }
        let payload = json!({ "calendar": calendar, "message_number": number });
        let Ok(input) = picked(&CALENDAR_CHANGED, &payload) else {
            return Read::Skip;
        };
        Read::Start {
            delivery: format!("{id}:{number}"),
            input,
            exposure: self.exposure,
        }
    }
}

/// The refusal of an event Google Calendar does not offer, unless `key`
/// is one.
fn ensure_known(key: &ServiceEventKey) -> Result<(), WatchFailure> {
    if key.as_str() == CALENDAR_CHANGED.key {
        return Ok(());
    }
    Err(WatchFailure::Refused(
        "Google Calendar sends no such event".to_owned(),
    ))
}

/// The calendar `watch` watches.
fn calendar<'a>(watch: Watch<'a>) -> Result<&'a str, WatchFailure> {
    watch
        .filter(CALENDAR.name)
        .ok_or_else(|| WatchFailure::Refused("the trigger names no calendar".to_owned()))
}

/// A new channel's id, unique to the registration at `address` and to now,
/// so a renewal's channel never takes the id of the one it replaces.
fn channel_id(address: &str) -> Result<String, WatchFailure> {
    let registration = address
        .rsplit('/')
        .next()
        .filter(|last| !last.is_empty())
        .ok_or_else(|| WatchFailure::Refused("the registration has no address".to_owned()))?;
    Ok(format!("{registration}-{}", clock::now().unix_timestamp()))
}

/// The channel `id` Google opened, as it answered with `taken`.
fn opened(id: &str, taken: &Value) -> Result<Watching, WatchFailure> {
    let resource = taken["resourceId"]
        .as_str()
        .ok_or_else(|| WatchFailure::Refused("Google named no resource".to_owned()))?;
    let lapses = taken["expiration"]
        .as_str()
        .and_then(|millis| millis.parse::<i64>().ok())
        .and_then(|millis| OffsetDateTime::from_unix_timestamp(millis.div_euclid(1_000)).ok());
    Ok(Watching {
        remote: format!("{id} {resource}"),
        lapses,
        routed_by: None,
    })
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use ianua_domain::domains::workflows::data::{DataPath, FieldName, FlowValue};
    use ianua_domain::domains::workflows::triggers::{EventFilter, FilterValue};
    use ianua_domain::shared::security::secret::Secret;
    use ianua_integration::ServiceEndpoint;
    use ianua_integration::rest::access::Access;
    use wiremock::matchers::{body_partial_json, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    const ADDRESS: &str =
        "https://ianua.test/api/v1/integrations/events/7d3f2c1a-0000-4000-8000-000000000001";

    const GRANT: &str =
        r#"{"client_id":"the app","client_secret":"the app's words","refresh_token":"the grant"}"#;

    async fn channels(server: &MockServer) -> Channels {
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(
                    json!({ "access_token": "an hour's token", "expires_in": 3599 }),
                ),
            )
            .mount(server)
            .await;
        Channels::new(
            WatchCalls::new(
                Access::Refreshed {
                    endpoint: ServiceEndpoint::at(&format!("{}/calendar/v3/", server.uri()))
                        .unwrap(),
                    token: ServiceEndpoint::at(&format!("{}/token", server.uri())).unwrap(),
                },
                &[],
                Duration::from_secs(2),
            )
            .unwrap(),
            DataClassLevel::Internal,
        )
    }

    struct Watched {
        event: ServiceEventKey,
        filters: Vec<EventFilter>,
        secret: Secret,
        remote: Option<&'static str>,
    }

    impl Watched {
        fn on(remote: Option<&'static str>) -> Self {
            Self {
                event: ServiceEventKey::new("calendar-changed").unwrap(),
                filters: vec![EventFilter::new(
                    FieldName::new("calendar").unwrap(),
                    FilterValue::new("team@acme.example").unwrap(),
                )],
                secret: Secret::new("the registration's channel words".to_owned()),
                remote,
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

    fn grant() -> HeldCredential {
        HeldCredential::new(Secret::new(GRANT.to_owned()))
    }

    fn notified(token: &str, channel: &str, state: &str) -> Vec<(String, String)> {
        vec![
            ("x-goog-channel-token".to_owned(), token.to_owned()),
            ("x-goog-channel-id".to_owned(), channel.to_owned()),
            ("x-goog-resource-state".to_owned(), state.to_owned()),
            ("x-goog-message-number".to_owned(), "4".to_owned()),
        ]
    }

    fn read(watched: &Watched, headers: &[(String, String)]) -> Read {
        let channels = Channels::new(
            WatchCalls::new(
                Access::Bearer {
                    endpoint: ServiceEndpoint::at("https://calendar.test/").unwrap(),
                },
                &[],
                Duration::from_secs(1),
            )
            .unwrap(),
            DataClassLevel::Internal,
        );
        channels.read(
            watched.watch(),
            Delivery {
                address: ADDRESS,
                headers,
                body: b"",
            },
        )
    }

    /// Ann's workflow watches the team calendar: publishing opens a channel
    /// there with the registration's secret as its token, and keeps the
    /// channel's id and resource and when it lapses.
    #[tokio::test]
    async fn registering_opens_a_channel_with_the_secret_as_its_token() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(
                "/calendar/v3/calendars/team@acme.example/events/watch",
            ))
            .and(body_partial_json(json!({
                "type": "web_hook",
                "address": ADDRESS,
                "token": "the registration's channel words"
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "resourceId": "res-1",
                "expiration": "1900000000000"
            })))
            .expect(1)
            .mount(&server)
            .await;
        let watched = Watched::on(None);

        let watching = channels(&server)
            .await
            .register(&grant(), watched.watch())
            .await
            .unwrap();

        assert!(watching.remote.ends_with(" res-1"), "{}", watching.remote);
        assert_eq!(
            watching.lapses.map(OffsetDateTime::unix_timestamp),
            Some(1_900_000_000)
        );
    }

    /// Renewing opens a new channel and stops the one it replaces.
    #[tokio::test]
    async fn renewing_opens_a_new_channel_and_stops_the_old() {
        let server = MockServer::start().await;
        Mock::given(path(
            "/calendar/v3/calendars/team@acme.example/events/watch",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "resourceId": "res-2",
            "expiration": "1900000000000"
        })))
        .mount(&server)
        .await;
        Mock::given(method("POST"))
            .and(path("/calendar/v3/channels/stop"))
            .and(body_partial_json(
                json!({ "id": "old-channel", "resourceId": "res-1" }),
            ))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(&server)
            .await;
        let watched = Watched::on(Some("old-channel res-1"));

        let watching = channels(&server)
            .await
            .renew(&grant(), watched.watch())
            .await
            .unwrap();

        assert!(watching.remote.ends_with(" res-2"));
    }

    /// A change on the team calendar, with the channel's token, starts the
    /// workflow, naming the calendar.
    #[test]
    fn a_change_with_the_token_starts_the_workflow() {
        let watched = Watched::on(Some("chan-1 res-1"));
        let headers = notified("the registration's channel words", "chan-1", "exists");

        let read = read(&watched, &headers);

        let Read::Start {
            delivery, input, ..
        } = read
        else {
            panic!("nothing started: {read:?}");
        };
        assert_eq!(delivery, "chan-1:4");
        assert_eq!(
            input
                .at(&DataPath::parse("calendar").unwrap())
                .map(|calendar| calendar.value()),
            Some(FlowValue::Text("team@acme.example"))
        );
    }

    /// A change with the wrong channel token or no token is marked forged
    /// rather than returned as a workflow start.
    #[test]
    fn a_change_without_the_token_is_forged() {
        let watched = Watched::on(Some("chan-1 res-1"));

        let forged = read(&watched, &notified("mallory's words", "chan-1", "exists"));
        let bare = read(
            &watched,
            &[("x-goog-channel-id".to_owned(), "chan-1".to_owned())],
        );

        assert_eq!(forged, Read::Forged);
        assert_eq!(bare, Read::Forged);
    }

    /// Google's first message on a channel, and one from a channel replaced
    /// since, start nothing.
    #[test]
    fn the_first_message_or_a_replaced_channel_starts_nothing() {
        let watched = Watched::on(Some("chan-2 res-2"));
        let token = "the registration's channel words";

        assert_eq!(
            read(&watched, &notified(token, "chan-2", "sync")),
            Read::Skip
        );
        assert_eq!(
            read(&watched, &notified(token, "chan-1", "exists")),
            Read::Skip
        );
    }
}
