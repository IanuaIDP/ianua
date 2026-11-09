//! What PagerDuty sends that a workflow may start on: an incident
//! triggered, acknowledged or resolved on one service.
//!
//! Publishing a workflow makes a v3 webhook subscription through the
//! account, filtered to the service and to the one event, sending to the
//! platform's address for the registration with the registration's secret
//! in a custom header. PagerDuty hides a custom header's value when the
//! subscription is read back and sends it with every delivery, and a
//! delivery without it is read no further.
//!
//! PagerDuty also signs each delivery in `X-PagerDuty-Signature`, with a
//! secret it chooses and shows once, when the subscription is made. The
//! platform keeps only the secrets it makes, so that signature is not
//! checked; the custom header proves a delivery instead. Subscriptions
//! never lapse; archiving deletes the subscription.

use async_trait::async_trait;
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::domains::workflows::integration::InputNeed;
use ianua_domain::domains::workflows::integration::events::ServiceEventKey;
use ianua_domain::shared::security::secret::Secret;
use ianua_integration::events::{
    Delivery, Events, HeldCredential, Read, Watch, WatchFailure, Watching,
};
use ianua_integration::rest::event::{EventText, FilterText, picked};
use ianua_integration::rest::operation::Verb;
use ianua_integration::rest::watch::{WatchBody, WatchCall, WatchCalls};
use ianua_integration::signature::same_secret;
use serde_json::{Value, json};

/// The header each delivery carries the registration's secret in.
const SECRET_HEADER: &str = "x-ianua-token";

/// The service every event is watched on.
const SERVICE: FilterText = FilterText {
    name: "service",
    need: InputNeed::Required,
    meaning: "The service to watch, by its PagerDuty id, such as PWIXJZS.",
};

/// What every incident event gives the workflow.
const INCIDENT_OUTPUTS: &[(&str, &str)] = &[
    ("data.id", "The incident's id, which later steps name."),
    ("data.number", "The incident's number in the account."),
    ("data.title", "The incident's title."),
    (
        "data.status",
        "Its status: triggered, acknowledged or resolved.",
    ),
    ("data.urgency", "Its urgency: high or low."),
    ("data.html_url", "The address of the incident's page."),
    ("data.service.id", "The service's id."),
    ("data.service.summary", "The service's name."),
    (
        "agent.summary",
        "Who did it, when a person did; empty when PagerDuty itself did.",
    ),
];

/// An incident triggered.
const TRIGGERED: EventText = EventText {
    key: "incident-triggered",
    title: "An incident is triggered",
    description: "An incident is opened on the service and starts paging.",
    filters: &[SERVICE],
    outputs: INCIDENT_OUTPUTS,
};

/// An incident acknowledged.
const ACKNOWLEDGED: EventText = EventText {
    key: "incident-acknowledged",
    title: "An incident is acknowledged",
    description: "Someone takes on an incident on the service, which stops it escalating.",
    filters: &[SERVICE],
    outputs: INCIDENT_OUTPUTS,
};

/// An incident resolved.
const RESOLVED: EventText = EventText {
    key: "incident-resolved",
    title: "An incident is resolved",
    description: "An incident on the service is resolved.",
    filters: &[SERVICE],
    outputs: INCIDENT_OUTPUTS,
};

/// One event and the event type PagerDuty names it by.
struct Kind {
    text: &'static EventText,
    event_type: &'static str,
}

/// Every event, with PagerDuty's name for it.
const KINDS: &[Kind] = &[
    Kind {
        text: &TRIGGERED,
        event_type: "incident.triggered",
    },
    Kind {
        text: &ACKNOWLEDGED,
        event_type: "incident.acknowledged",
    },
    Kind {
        text: &RESOLVED,
        event_type: "incident.resolved",
    },
];

/// Every event PagerDuty offers, described.
pub(crate) fn all() -> Vec<&'static EventText> {
    KINDS.iter().map(|kind| kind.text).collect()
}

/// PagerDuty's webhook subscriptions for workflow triggers.
pub(crate) struct Hooks {
    calls: WatchCalls,
    exposure: DataClassLevel,
}

impl Hooks {
    /// Subscriptions made through `calls`, their deliveries counted as
    /// sensitive as `exposure`.
    pub(crate) fn new(calls: WatchCalls, exposure: DataClassLevel) -> Self {
        Self { calls, exposure }
    }

    /// The subscription body for `watch`, asking for `kind`'s deliveries on
    /// `service` only.
    fn subscription(watch: Watch<'_>, kind: &Kind, service: &str) -> Value {
        json!({
            "webhook_subscription": {
                "type": "webhook_subscription",
                "description": "Starts a workflow",
                "delivery_method": {
                    "type": "http_delivery_method",
                    "url": watch.address,
                    "custom_headers": [
                        { "name": SECRET_HEADER, "value": watch.secret.expose() }
                    ]
                },
                "events": [kind.event_type],
                "filter": { "type": "service_reference", "id": service }
            }
        })
    }
}

#[async_trait]
impl Events for Hooks {
    async fn register(
        &self,
        credential: &HeldCredential,
        watch: Watch<'_>,
    ) -> Result<Watching, WatchFailure> {
        let kind = kind_of(watch.event).ok_or_else(unknown)?;
        let service = service(watch)?;
        let body = Self::subscription(watch, kind, service);
        let taken = self
            .calls
            .send(
                credential,
                WatchCall {
                    verb: Verb::Post,
                    path: &["webhook_subscriptions"],
                    query: &[],
                    body: Some(WatchBody::Json(&body)),
                },
            )
            .await?
            .taken("PagerDuty")?;
        let Some(id) = taken["webhook_subscription"]["id"].as_str() else {
            return Err(WatchFailure::Refused(
                "PagerDuty named no subscription".to_owned(),
            ));
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
                "the subscription was never made".to_owned(),
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
            .calls
            .send(
                credential,
                WatchCall {
                    verb: Verb::Delete,
                    path: &["webhook_subscriptions", remote],
                    query: &[],
                    body: None,
                },
            )
            .await?;
        if answered.status == 404 {
            return Ok(());
        }
        answered.taken("PagerDuty").map(|_| ())
    }

    fn read(&self, watch: Watch<'_>, delivery: Delivery<'_>) -> Read {
        if !proven(watch.secret, delivery) {
            return Read::Forged;
        }
        let Some(kind) = kind_of(watch.event) else {
            return Read::Skip;
        };
        let Ok(payload) = serde_json::from_slice::<Value>(delivery.body) else {
            return Read::Skip;
        };
        let event = &payload["event"];
        let Some(id) = event["id"].as_str() else {
            return Read::Skip;
        };
        if !passes(kind, event, watch) {
            return Read::Skip;
        }
        let Ok(input) = picked(kind.text, event) else {
            return Read::Skip;
        };
        Read::Start {
            delivery: id.to_owned(),
            input,
            exposure: self.exposure,
        }
    }
}

/// The event `key` names, if PagerDuty offers it.
fn kind_of(key: &ServiceEventKey) -> Option<&'static Kind> {
    KINDS.iter().find(|kind| kind.text.key == key.as_str())
}

/// The refusal of an event PagerDuty does not offer.
fn unknown() -> WatchFailure {
    WatchFailure::Refused("PagerDuty sends no such event".to_owned())
}

/// The service `watch` watches.
fn service<'a>(watch: Watch<'a>) -> Result<&'a str, WatchFailure> {
    watch
        .filter(SERVICE.name)
        .map(str::trim)
        .filter(|service| !service.is_empty())
        .ok_or_else(|| WatchFailure::Refused("the trigger names no service".to_owned()))
}

/// A subscription PagerDuty keeps as `remote` until it is deleted.
fn standing(remote: String) -> Watching {
    Watching {
        remote,
        lapses: None,
        routed_by: None,
    }
}

/// Whether `delivery` carries the registration's `secret` in its header.
fn proven(secret: &Secret, delivery: Delivery<'_>) -> bool {
    delivery
        .header(SECRET_HEADER)
        .is_some_and(|given| same_secret(secret.expose(), given))
}

/// Whether `event` is `kind`'s, about an incident on the watched service.
fn passes(kind: &Kind, event: &Value, watch: Watch<'_>) -> bool {
    let of_kind = event["event_type"].as_str() == Some(kind.event_type);
    let on_service = watch
        .filter(SERVICE.name)
        .is_some_and(|watched| event["data"]["service"]["id"].as_str() == Some(watched.trim()));
    of_kind && on_service
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use ianua_domain::domains::workflows::data::{DataPath, FieldName, FlowValue};
    use ianua_domain::domains::workflows::triggers::{EventFilter, FilterValue};
    use ianua_integration::ServiceEndpoint;
    use ianua_integration::rest::access::Access;
    use wiremock::matchers::{body_partial_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    const ADDRESS: &str = "https://ianua.test/api/v1/integrations/pagerduty/events/one";

    const SECRET: &str = "the registration's secret words";

    fn hooks_at(base: &str) -> Hooks {
        Hooks::new(
            WatchCalls::new(
                Access::Scheme {
                    endpoint: ServiceEndpoint::at(base).unwrap(),
                    scheme: "Token token=",
                },
                &[("accept", "application/vnd.pagerduty+json;version=2")],
                Duration::from_secs(2),
            )
            .unwrap(),
            DataClassLevel::Internal,
        )
    }

    fn hooks(server: &MockServer) -> Hooks {
        hooks_at(&format!("{}/", server.uri()))
    }

    fn filters(entries: &[(&str, &str)]) -> Vec<EventFilter> {
        entries
            .iter()
            .map(|&(name, value)| {
                EventFilter::new(
                    FieldName::new(name).unwrap(),
                    FilterValue::new(value).unwrap(),
                )
            })
            .collect()
    }

    struct Watched {
        event: ServiceEventKey,
        filters: Vec<EventFilter>,
        secret: Secret,
        remote: Option<&'static str>,
    }

    impl Watched {
        fn on(event: &str, service: &str) -> Self {
            Self {
                event: ServiceEventKey::new(event).unwrap(),
                filters: filters(&[("service", service)]),
                secret: Secret::new(SECRET.to_owned()),
                remote: Some("PY1OHUA"),
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

    fn token() -> HeldCredential {
        HeldCredential::new(Secret::new("acme pagerduty key for workflows".to_owned()))
    }

    fn sent(secret: &str) -> Vec<(String, String)> {
        vec![
            ("x-webhook-id".to_owned(), "PY1OHUA".to_owned()),
            (SECRET_HEADER.to_owned(), secret.to_owned()),
        ]
    }

    fn incident(event_type: &str, service: &str) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "event": {
                "id": "delivery one",
                "event_type": event_type,
                "resource_type": "incident",
                "agent": { "summary": "Pat Doe", "type": "user_reference" },
                "data": {
                    "id": "Q2LKJQ1",
                    "number": 42,
                    "title": "Checkout is failing",
                    "status": "triggered",
                    "urgency": "high",
                    "html_url": "https://acme.pagerduty.com/incidents/Q2LKJQ1",
                    "incident_key": "checkout errors",
                    "service": { "id": service, "summary": "Checkout" }
                }
            }
        }))
        .unwrap()
    }

    fn read(watched: &Watched, headers: &[(String, String)], body: &[u8]) -> Read {
        hooks_at("https://pagerduty.test/").read(
            watched.watch(),
            Delivery {
                address: ADDRESS,
                headers,
                body,
            },
        )
    }

    /// Ann's workflow watches the checkout service for triggered incidents:
    /// publishing makes a subscription filtered to the service and that
    /// one event, carrying the platform's address and the registration's
    /// secret in a custom header, and keeps PagerDuty's id for it.
    #[tokio::test]
    async fn registering_makes_a_subscription_on_the_service() {
        let server = MockServer::start().await;
        let authorization = "Token token=acme pagerduty key for workflows";
        Mock::given(method("POST"))
            .and(path("/webhook_subscriptions"))
            .and(header("authorization", authorization))
            .and(body_partial_json(json!({
                "webhook_subscription": {
                    "delivery_method": {
                        "type": "http_delivery_method",
                        "url": ADDRESS,
                        "custom_headers": [{ "name": SECRET_HEADER, "value": SECRET }]
                    },
                    "events": ["incident.triggered"],
                    "filter": { "type": "service_reference", "id": "PWIXJZS" }
                }
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "webhook_subscription": { "id": "PY1OHUA" }
            })))
            .expect(1)
            .mount(&server)
            .await;
        let watched = Watched::on("incident-triggered", "PWIXJZS");

        let watching = hooks(&server)
            .register(&token(), watched.watch())
            .await
            .unwrap();

        assert_eq!(watching.remote, "PY1OHUA");
        assert_eq!(watching.lapses, None);
    }

    /// A 403 from PagerDuty becomes a registration refusal instead of a
    /// successful subscription result.
    #[tokio::test]
    async fn a_refusal_registers_nothing() {
        let server = MockServer::start().await;
        Mock::given(path("/webhook_subscriptions"))
            .respond_with(ResponseTemplate::new(403))
            .mount(&server)
            .await;
        let watched = Watched::on("incident-triggered", "PWIXJZS");

        let refused = hooks(&server).register(&token(), watched.watch()).await;

        assert!(matches!(refused, Err(WatchFailure::Refused(_))));
    }

    /// Archiving deletes the subscription; one PagerDuty no longer knows
    /// counts as deleted.
    #[tokio::test]
    async fn unregistering_deletes_the_subscription_even_when_gone() {
        let server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .and(path("/webhook_subscriptions/PY1OHUA"))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(&server)
            .await;
        let hooks = hooks(&server);
        let present = Watched::on("incident-triggered", "PWIXJZS");
        let mut gone = Watched::on("incident-triggered", "PWIXJZS");
        gone.remote = Some("PGONE00");

        assert_eq!(hooks.unregister(&token(), present.watch()).await, Ok(()));
        assert_eq!(hooks.unregister(&token(), gone.watch()).await, Ok(()));
    }

    /// Checkout's incident 42 is triggered: the delivery carrying the
    /// secret starts the workflow with the incident's id and title, under
    /// PagerDuty's event id, and its incident key stays behind.
    #[test]
    fn a_triggered_incident_with_the_secret_starts_the_workflow() {
        let watched = Watched::on("incident-triggered", "PWIXJZS");
        let body = incident("incident.triggered", "PWIXJZS");

        let read = read(&watched, &sent(SECRET), &body);

        let Read::Start {
            delivery, input, ..
        } = read
        else {
            panic!("the delivery started nothing: {read:?}");
        };
        assert_eq!(delivery, "delivery one");
        assert_eq!(
            input
                .at(&DataPath::parse("data.id").unwrap())
                .map(|value| value.value()),
            Some(FlowValue::Text("Q2LKJQ1"))
        );
        assert!(
            input
                .at(&DataPath::parse("data.incident_key").unwrap())
                .is_none()
        );
    }

    /// An incident delivery with the wrong secret header or no secret
    /// header is marked forged rather than returned as a workflow start.
    #[test]
    fn a_delivery_with_another_secret_is_forged() {
        let watched = Watched::on("incident-triggered", "PWIXJZS");
        let body = incident("incident.triggered", "PWIXJZS");
        let forged = sent("mallory's own secret words");
        let unsigned: Vec<(String, String)> = forged
            .iter()
            .filter(|(name, _)| name != SECRET_HEADER)
            .cloned()
            .collect();

        assert_eq!(read(&watched, &forged, &body), Read::Forged);
        assert_eq!(read(&watched, &unsigned, &body), Read::Forged);
    }

    /// A delivery with the secret that is another event, PagerDuty's ping,
    /// or another service starts nothing.
    #[test]
    fn another_event_a_ping_or_another_service_is_skipped() {
        let watched = Watched::on("incident-triggered", "PWIXJZS");
        let resolved = incident("incident.resolved", "PWIXJZS");
        let ping = incident("pagey.ping", "PWIXJZS");
        let elsewhere = incident("incident.triggered", "PELSE00");

        for body in [resolved, ping, elsewhere] {
            assert_eq!(read(&watched, &sent(SECRET), &body), Read::Skip);
        }
    }

    /// A resolved incident starts the resolved trigger, not the triggered
    /// one.
    #[test]
    fn a_resolved_incident_starts_only_the_resolved_trigger() {
        let resolved = Watched::on("incident-resolved", "PWIXJZS");
        let triggered = Watched::on("incident-triggered", "PWIXJZS");
        let body = incident("incident.resolved", "PWIXJZS");

        let started = read(&resolved, &sent(SECRET), &body);

        assert!(matches!(started, Read::Start { .. }), "{started:?}");
        assert_eq!(read(&triggered, &sent(SECRET), &body), Read::Skip);
    }
}
