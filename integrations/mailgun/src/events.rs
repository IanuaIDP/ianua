//! What Mailgun sends that a workflow may start on: a message delivered, a
//! message that failed for good, and a message opened, on one domain.
//!
//! Publishing a workflow adds a webhook for the event on its domain through
//! the account's key. Mailgun signs what it sends with the account's
//! webhook signing key, which only its control panel shows, so the platform
//! cannot check that signature: each registration's address carries the
//! registration's own secret instead, and a delivery to it without that
//! secret is read no further. Mailgun's webhooks never lapse; archiving
//! removes the registration's address from the domain's webhooks, leaving
//! any others.

use async_trait::async_trait;
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::domains::workflows::integration::InputNeed;
use ianua_domain::domains::workflows::integration::events::ServiceEventKey;
use ianua_integration::events::{
    Delivery, Events, HeldCredential, Read, Watch, WatchFailure, Watching,
};
use ianua_integration::rest::event::{EventText, FilterText, picked};
use ianua_integration::rest::operation::Verb;
use ianua_integration::rest::watch::{WatchBody, WatchCall, WatchCalls};
use ianua_integration::signature::{carries_secret, with_secret};
use serde_json::Value;

/// The domain every event is watched on.
const DOMAIN: FilterText = FilterText {
    name: "domain",
    need: InputNeed::Required,
    meaning: "The sending domain to watch, such as mail.acme.example.",
};

/// What every message event gives.
const MESSAGE_VALUES: [(&str, &str); 4] = [
    ("event-data.recipient", "Who the message was sent to."),
    (
        "event-data.message.headers.message-id",
        "The message's id, as sending it answered.",
    ),
    (
        "event-data.message.headers.subject",
        "The message's subject.",
    ),
    (
        "event-data.timestamp",
        "When it happened, in seconds since 1970.",
    ),
];

/// A message delivered.
const DELIVERED: EventText = EventText {
    key: "message-delivered",
    title: "A message is delivered",
    description: "The recipient's mail server takes a message sent from the domain.",
    filters: &[DOMAIN],
    outputs: &MESSAGE_VALUES,
};

/// A message that failed for good.
const FAILED: EventText = EventText {
    key: "message-failed",
    title: "A message fails for good",
    description: "A message sent from the domain cannot be delivered and Mailgun stops trying, such as for an address that does not exist.",
    filters: &[DOMAIN],
    outputs: &[
        MESSAGE_VALUES[0],
        MESSAGE_VALUES[1],
        MESSAGE_VALUES[2],
        MESSAGE_VALUES[3],
        (
            "event-data.reason",
            "Why, in Mailgun's word, such as bounce.",
        ),
        (
            "event-data.delivery-status.description",
            "What the recipient's mail server said.",
        ),
    ],
};

/// A message opened.
const OPENED: EventText = EventText {
    key: "message-opened",
    title: "A message is opened",
    description: "The recipient opens a message sent from the domain, where open tracking is on.",
    filters: &[DOMAIN],
    outputs: &MESSAGE_VALUES,
};

/// One event as Mailgun names it: its webhook's event type, and the event
/// and severity a delivery of it carries.
struct Kind {
    text: &'static EventText,
    webhook: &'static str,
    event: &'static str,
    severity: Option<&'static str>,
}

/// Every event, with Mailgun's names for it.
const KINDS: &[Kind] = &[
    Kind {
        text: &DELIVERED,
        webhook: "delivered",
        event: "delivered",
        severity: None,
    },
    Kind {
        text: &FAILED,
        webhook: "permanent_fail",
        event: "failed",
        severity: Some("permanent"),
    },
    Kind {
        text: &OPENED,
        webhook: "opened",
        event: "opened",
        severity: None,
    },
];

/// Every event Mailgun offers, described.
pub(crate) fn all() -> Vec<&'static EventText> {
    KINDS.iter().map(|kind| kind.text).collect()
}

/// Mailgun's domain webhooks for workflow triggers.
pub(crate) struct Webhooks {
    calls: WatchCalls,
    exposure: DataClassLevel,
}

impl Webhooks {
    /// Webhooks added through `calls`, their deliveries counted as
    /// sensitive as `exposure`.
    pub(crate) fn new(calls: WatchCalls, exposure: DataClassLevel) -> Self {
        Self { calls, exposure }
    }
}

#[async_trait]
impl Events for Webhooks {
    async fn register(
        &self,
        credential: &HeldCredential,
        watch: Watch<'_>,
    ) -> Result<Watching, WatchFailure> {
        let kind = kind_of(watch.event).ok_or_else(unknown)?;
        let domain = domain(watch)?;
        let address = secret_address(watch)?;
        let form = [("url", address.as_str()), ("event_types", kind.webhook)];
        self.calls
            .send(
                credential,
                WatchCall {
                    verb: Verb::Post,
                    path: &["v4", "domains", domain, "webhooks"],
                    query: &[],
                    body: Some(WatchBody::Form(&form)),
                },
            )
            .await?
            .taken("Mailgun")?;
        Ok(standing(kind.webhook))
    }

    async fn renew(
        &self,
        _credential: &HeldCredential,
        watch: Watch<'_>,
    ) -> Result<Watching, WatchFailure> {
        let kind = kind_of(watch.event).ok_or_else(unknown)?;
        Ok(standing(kind.webhook))
    }

    async fn unregister(
        &self,
        credential: &HeldCredential,
        watch: Watch<'_>,
    ) -> Result<(), WatchFailure> {
        let domain = domain(watch)?;
        let address = secret_address(watch)?;
        let answered = self
            .calls
            .send(
                credential,
                WatchCall {
                    verb: Verb::Delete,
                    path: &["v4", "domains", domain, "webhooks"],
                    query: &[("url", address.as_str())],
                    body: None,
                },
            )
            .await?;
        if answered.status == 404 {
            return Ok(());
        }
        answered.taken("Mailgun").map(|_| ())
    }

    fn read(&self, watch: Watch<'_>, delivery: Delivery<'_>) -> Read {
        if !carries_secret(delivery.address, watch.secret) {
            return Read::Forged;
        }
        let Some(kind) = kind_of(watch.event) else {
            return Read::Skip;
        };
        let Ok(payload) = serde_json::from_slice::<Value>(delivery.body) else {
            return Read::Skip;
        };
        let data = &payload["event-data"];
        let (Some(id), Some(event)) = (data["id"].as_str(), data["event"].as_str()) else {
            return Read::Skip;
        };
        let severity_fits = kind
            .severity
            .is_none_or(|severity| data["severity"].as_str() == Some(severity));
        if event != kind.event || !severity_fits {
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

/// The event `key` names, if Mailgun offers it.
fn kind_of(key: &ServiceEventKey) -> Option<&'static Kind> {
    KINDS.iter().find(|kind| kind.text.key == key.as_str())
}

/// The refusal of an event Mailgun does not offer.
fn unknown() -> WatchFailure {
    WatchFailure::Refused("Mailgun sends no such event".to_owned())
}

/// The domain `watch` watches.
fn domain<'a>(watch: Watch<'a>) -> Result<&'a str, WatchFailure> {
    watch
        .filter(DOMAIN.name)
        .ok_or_else(|| WatchFailure::Refused("the trigger names no domain".to_owned()))
}

/// The registration's address with its secret in it, as Mailgun is given
/// it.
fn secret_address(watch: Watch<'_>) -> Result<String, WatchFailure> {
    with_secret(watch.address, watch.secret)
        .ok_or_else(|| WatchFailure::Refused("the registration's address is no address".to_owned()))
}

/// A webhook Mailgun keeps until it is removed, for its event `webhook`.
fn standing(webhook: &str) -> Watching {
    Watching {
        remote: webhook.to_owned(),
        lapses: None,
        routed_by: None,
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use ianua_domain::domains::workflows::data::{DataPath, FieldName, FlowValue};
    use ianua_domain::domains::workflows::triggers::{EventFilter, FilterValue};
    use ianua_domain::shared::security::secret::Secret;
    use ianua_integration::ServiceEndpoint;
    use ianua_integration::rest::access::{Access, Regions};
    use serde_json::json;
    use wiremock::matchers::{body_string_contains, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    const ADDRESS: &str =
        "https://ianua.test/api/v1/integrations/events/7d3f2c1a-0000-4000-8000-000000000002";

    const SECRET: &str = "the registration's mailgun words";

    fn webhooks(endpoint: &str) -> Webhooks {
        let at = ServiceEndpoint::at(endpoint).unwrap();
        Webhooks::new(
            WatchCalls::new(
                Access::Key {
                    regions: Regions::new(("us", at.clone()), [("eu", at)]),
                    user: "api",
                    limited: None,
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
    }

    impl Watched {
        fn on(event: &str) -> Self {
            Self {
                event: ServiceEventKey::new(event).unwrap(),
                filters: vec![EventFilter::new(
                    FieldName::new("domain").unwrap(),
                    FilterValue::new("mail.acme.example").unwrap(),
                )],
                secret: Secret::new(SECRET.to_owned()),
            }
        }

        fn watch(&self) -> Watch<'_> {
            Watch {
                event: &self.event,
                filters: &self.filters,
                address: ADDRESS,
                secret: &self.secret,
                remote: Some("permanent_fail"),
            }
        }
    }

    fn key() -> HeldCredential {
        HeldCredential::new(Secret::new("test mailgun key for acme".to_owned()))
    }

    fn failed() -> Vec<u8> {
        serde_json::to_vec(&json!({
            "signature": { "timestamp": "1", "token": "t", "signature": "s" },
            "event-data": {
                "id": "Ase-ev-1",
                "event": "failed",
                "severity": "permanent",
                "reason": "bounce",
                "recipient": "nobody@globex.example",
                "timestamp": 1_700_000_000.5,
                "message": { "headers": { "message-id": "m1@mail.acme.example", "subject": "Your invoice" } },
                "delivery-status": { "description": "No such mailbox" }
            }
        }))
        .unwrap()
    }

    fn read(watched: &Watched, address: &str, body: &[u8]) -> Read {
        webhooks("https://mailgun.test/").read(
            watched.watch(),
            Delivery {
                address,
                headers: &[],
                body,
            },
        )
    }

    fn secret_given(secret: &str) -> String {
        with_secret(ADDRESS, &Secret::new(secret.to_owned())).unwrap()
    }

    /// Ann's workflow watches mail.acme.example for failed mail:
    /// publishing adds the registration's address, with its secret, as a
    /// permanent-failure webhook of the domain.
    #[tokio::test]
    async fn registering_adds_the_address_with_its_secret() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v4/domains/mail.acme.example/webhooks"))
            .and(body_string_contains("event_types=permanent_fail"))
            .and(body_string_contains("token%3Dthe%2Bregistration"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "webhooks": {} })))
            .expect(1)
            .mount(&server)
            .await;
        let watched = Watched::on("message-failed");

        let watching = webhooks(&server.uri())
            .register(&key(), watched.watch())
            .await
            .unwrap();

        assert_eq!(watching.remote, "permanent_fail");
    }

    /// Archiving removes only the registration's address from the domain's
    /// webhooks.
    #[tokio::test]
    async fn unregistering_removes_only_this_address() {
        let server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .and(path("/v4/domains/mail.acme.example/webhooks"))
            .and(query_param("url", secret_given(SECRET).as_str()))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "webhooks": {} })))
            .expect(1)
            .mount(&server)
            .await;
        let watched = Watched::on("message-failed");

        let removed = webhooks(&server.uri())
            .unregister(&key(), watched.watch())
            .await;

        assert_eq!(removed, Ok(()));
    }

    /// Mail to nobody@globex.example bounces: the delivery to the address
    /// with its secret starts the workflow with the recipient and why.
    #[test]
    fn a_failure_to_the_secret_address_starts_the_workflow() {
        let watched = Watched::on("message-failed");

        let read = read(&watched, &secret_given(SECRET), &failed());

        let Read::Start {
            delivery, input, ..
        } = read
        else {
            panic!("nothing started: {read:?}");
        };
        assert_eq!(delivery, "Ase-ev-1");
        assert_eq!(
            input
                .at(&DataPath::parse("event-data.recipient").unwrap())
                .map(|recipient| recipient.value()),
            Some(FlowValue::Text("nobody@globex.example"))
        );
    }

    /// Deliveries to an address with no registration secret or the wrong
    /// secret are marked forged rather than returned as workflow starts.
    #[test]
    fn a_delivery_without_the_secret_is_forged() {
        let watched = Watched::on("message-failed");

        assert_eq!(read(&watched, ADDRESS, &failed()), Read::Forged);
        assert_eq!(
            read(&watched, &secret_given("mallory's words"), &failed()),
            Read::Forged
        );
    }

    /// A temporary failure, and a delivery, start nothing for a trigger on
    /// failures for good.
    #[test]
    fn a_temporary_failure_or_another_event_starts_nothing() {
        let watched = Watched::on("message-failed");
        let address = secret_given(SECRET);
        let temporary = serde_json::to_vec(&json!({
            "event-data": { "id": "e2", "event": "failed", "severity": "temporary" }
        }))
        .unwrap();
        let delivered = serde_json::to_vec(&json!({
            "event-data": { "id": "e3", "event": "delivered" }
        }))
        .unwrap();

        assert_eq!(read(&watched, &address, &temporary), Read::Skip);
        assert_eq!(read(&watched, &address, &delivered), Read::Skip);
    }
}
