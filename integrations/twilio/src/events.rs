//! What Twilio sends that a workflow may start on: a text received on one
//! of the account's numbers.
//!
//! A number sends the texts it receives to one address. Publishing a
//! workflow points the number at the registration's address through the
//! account; a number that already sends its texts elsewhere, or to a Twilio
//! application, is refused rather than taken over. The registration's
//! address carries its own secret, since Twilio signs with the account's
//! primary auth token, which an account holding an API key does not hold;
//! a delivery without that secret is read no further. Archiving clears the
//! number's address only while it is still the registration's.

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
use serde_json::{Value, json};

/// The number every text is watched on.
const NUMBER: FilterText = FilterText {
    name: "number",
    need: InputNeed::Required,
    meaning: "The account's number to watch, written with its country code, such as +15551234567.",
};

/// A text received.
const TEXT_RECEIVED: EventText = EventText {
    key: "text-received",
    title: "A text is received",
    description: "Someone texts the number.",
    filters: &[NUMBER],
    outputs: &[
        ("from", "Who sent it, as their number."),
        ("to", "The number it was sent to."),
        ("body", "What it says."),
        ("message_sid", "Twilio's id for the message."),
    ],
};

/// Every event Twilio offers, described.
pub(crate) fn all() -> Vec<&'static EventText> {
    vec![&TEXT_RECEIVED]
}

/// A number as Twilio describes it.
struct Number {
    sid: String,
    sends_to: String,
    application: String,
}

/// Twilio's numbers' incoming-text addresses, for workflow triggers.
pub(crate) struct Numbers {
    calls: WatchCalls,
    exposure: DataClassLevel,
}

impl Numbers {
    /// Numbers pointed through `calls`, their texts counted as sensitive as
    /// `exposure`.
    pub(crate) fn new(calls: WatchCalls, exposure: DataClassLevel) -> Self {
        Self { calls, exposure }
    }

    /// The account's number written as `number`.
    async fn found(
        &self,
        credential: &HeldCredential,
        number: &str,
    ) -> Result<Number, WatchFailure> {
        let listed = self
            .calls
            .send(
                credential,
                WatchCall {
                    verb: Verb::Get,
                    path: &["IncomingPhoneNumbers.json"],
                    query: &[("PhoneNumber", number)],
                    body: None,
                },
            )
            .await?
            .taken("Twilio")?;
        described(&listed["incoming_phone_numbers"][0])
            .ok_or_else(|| WatchFailure::Refused("the account has no such number".to_owned()))
    }

    /// Points the number `sid` at `address`, or at nothing when it is
    /// empty.
    async fn point(
        &self,
        credential: &HeldCredential,
        sid: &str,
        address: &str,
    ) -> Result<(), WatchFailure> {
        let resource = format!("{sid}.json");
        let form = [("SmsUrl", address), ("SmsMethod", "POST")];
        self.calls
            .send(
                credential,
                WatchCall {
                    verb: Verb::Post,
                    path: &["IncomingPhoneNumbers", &resource],
                    query: &[],
                    body: Some(WatchBody::Form(&form)),
                },
            )
            .await?
            .taken("Twilio")
            .map(|_| ())
    }
}

#[async_trait]
impl Events for Numbers {
    async fn register(
        &self,
        credential: &HeldCredential,
        watch: Watch<'_>,
    ) -> Result<Watching, WatchFailure> {
        ensure_known(watch.event)?;
        let number = self.found(credential, number(watch)?).await?;
        let address = secret_address(watch)?;
        ensure_free(&number, &address)?;
        self.point(credential, &number.sid, &address).await?;
        Ok(standing(number.sid))
    }

    async fn renew(
        &self,
        _credential: &HeldCredential,
        watch: Watch<'_>,
    ) -> Result<Watching, WatchFailure> {
        let sid = watch
            .remote
            .ok_or_else(|| WatchFailure::Refused("the number was never pointed".to_owned()))?;
        Ok(standing(sid.to_owned()))
    }

    async fn unregister(
        &self,
        credential: &HeldCredential,
        watch: Watch<'_>,
    ) -> Result<(), WatchFailure> {
        if watch.remote.is_none() {
            return Ok(());
        }
        let number = match self.found(credential, number(watch)?).await {
            Ok(number) => number,
            Err(WatchFailure::Refused(_)) => return Ok(()),
            Err(unreachable) => return Err(unreachable),
        };
        if number.sends_to != secret_address(watch)? {
            return Ok(());
        }
        self.point(credential, &number.sid, "").await
    }

    fn read(&self, watch: Watch<'_>, delivery: Delivery<'_>) -> Read {
        if !carries_secret(delivery.address, watch.secret) {
            return Read::Forged;
        }
        let fields: Vec<(String, String)> = url::form_urlencoded::parse(delivery.body)
            .into_owned()
            .collect();
        let field = |name: &str| form_field(&fields, name);
        let (Some(sid), Some(to)) = (field("MessageSid"), field("To")) else {
            return Read::Skip;
        };
        if ensure_known(watch.event).is_err() || watch.filter(NUMBER.name) != Some(to) {
            return Read::Skip;
        }
        let payload = json!({
            "from": field("From"),
            "to": to,
            "body": field("Body"),
            "message_sid": sid,
        });
        let Ok(input) = picked(&TEXT_RECEIVED, &payload) else {
            return Read::Skip;
        };
        Read::Start {
            delivery: sid.to_owned(),
            input,
            exposure: self.exposure,
        }
    }
}

/// Reads the first occurrence of a named field in Twilio's submitted form.
fn form_field<'a>(fields: &'a [(String, String)], name: &str) -> Option<&'a str> {
    fields
        .iter()
        .find(|(given, _)| given == name)
        .map(|(_, value)| value.as_str())
}

/// The refusal of an event Twilio does not offer, unless `key` is one.
fn ensure_known(key: &ServiceEventKey) -> Result<(), WatchFailure> {
    if key.as_str() == TEXT_RECEIVED.key {
        return Ok(());
    }
    Err(WatchFailure::Refused(
        "Twilio sends no such event".to_owned(),
    ))
}

/// The number `watch` watches, written with its country code.
fn number<'a>(watch: Watch<'a>) -> Result<&'a str, WatchFailure> {
    let written = watch
        .filter(NUMBER.name)
        .ok_or_else(|| WatchFailure::Refused("the trigger names no number".to_owned()))?;
    let digits = written.strip_prefix('+').unwrap_or_default();
    let plain = (8..=15).contains(&digits.len()) && digits.chars().all(|c| c.is_ascii_digit());
    match plain {
        true => Ok(written),
        false => Err(WatchFailure::Refused(
            "the number is written with its country code, such as +15551234567".to_owned(),
        )),
    }
}

/// The number `listed` describes, if it describes one.
fn described(listed: &Value) -> Option<Number> {
    Some(Number {
        sid: listed["sid"].as_str()?.to_owned(),
        sends_to: listed["sms_url"].as_str().unwrap_or_default().to_owned(),
        application: listed["sms_application_sid"]
            .as_str()
            .unwrap_or_default()
            .to_owned(),
    })
}

/// Refuses `number` when it sends its texts anywhere but `address`.
fn ensure_free(number: &Number, address: &str) -> Result<(), WatchFailure> {
    if !number.application.is_empty() {
        return Err(WatchFailure::Refused(
            "the number's texts go to a Twilio application".to_owned(),
        ));
    }
    if !number.sends_to.is_empty() && number.sends_to != address {
        return Err(WatchFailure::Refused(
            "the number already sends its texts to another address".to_owned(),
        ));
    }
    Ok(())
}

/// The registration's address with its secret in it, as the number is
/// pointed at it.
fn secret_address(watch: Watch<'_>) -> Result<String, WatchFailure> {
    with_secret(watch.address, watch.secret)
        .ok_or_else(|| WatchFailure::Refused("the registration's address is no address".to_owned()))
}

/// A number Twilio keeps pointed until it is changed, by its `sid`.
fn standing(sid: String) -> Watching {
    Watching {
        remote: sid,
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
    use ianua_integration::rest::access::Access;
    use wiremock::matchers::{body_string_contains, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    const ADDRESS: &str =
        "https://ianua.test/api/v1/integrations/events/7d3f2c1a-0000-4000-8000-000000000003";

    const SECRET: &str = "the registration's twilio words";

    const ACCOUNT: &str = r#"{"account":"AC0ACME","token":"the account's token words"}"#;

    const NUMBERS: &str = "/2010-04-01/Accounts/AC0ACME/IncomingPhoneNumbers.json";

    const NUMBER_PATH: &str = "/2010-04-01/Accounts/AC0ACME/IncomingPhoneNumbers/PN0ONE.json";

    fn numbers(endpoint: &str) -> Numbers {
        Numbers::new(
            WatchCalls::new(
                Access::Account {
                    base: ServiceEndpoint::at(&format!("{endpoint}/2010-04-01/Accounts/")).unwrap(),
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
                event: ServiceEventKey::new("text-received").unwrap(),
                filters: vec![EventFilter::new(
                    FieldName::new("number").unwrap(),
                    FilterValue::new("+15551230000").unwrap(),
                )],
                secret: Secret::new(SECRET.to_owned()),
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

    fn account() -> HeldCredential {
        HeldCredential::new(Secret::new(ACCOUNT.to_owned()))
    }

    fn secret_given(secret: &str) -> String {
        with_secret(ADDRESS, &Secret::new(secret.to_owned())).unwrap()
    }

    async fn listing(server: &MockServer, sms_url: &str, application: &str) {
        Mock::given(method("GET"))
            .and(path(NUMBERS))
            .and(query_param("PhoneNumber", "+15551230000"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "incoming_phone_numbers": [{
                    "sid": "PN0ONE",
                    "sms_url": sms_url,
                    "sms_application_sid": application
                }]
            })))
            .mount(server)
            .await;
    }

    /// Ann's workflow watches the support number: publishing points the
    /// number's texts at the registration's address with its secret.
    #[tokio::test]
    async fn registering_points_a_free_number_at_the_address() {
        let server = MockServer::start().await;
        listing(&server, "", "").await;
        Mock::given(method("POST"))
            .and(path(NUMBER_PATH))
            .and(body_string_contains("SmsMethod=POST"))
            .and(body_string_contains("token%3Dthe%2Bregistration"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "sid": "PN0ONE" })))
            .expect(1)
            .mount(&server)
            .await;
        let watched = Watched::on(None);

        let watching = numbers(&server.uri())
            .register(&account(), watched.watch())
            .await
            .unwrap();

        assert_eq!(watching.remote, "PN0ONE");
    }

    /// A number already assigned to another address or a Twilio application
    /// cannot be registered; each attempt sends only the lookup request.
    #[tokio::test]
    async fn a_number_already_sending_elsewhere_is_refused() {
        for (sms_url, application) in [("https://desk.acme.example/sms", ""), ("", "AP0APP")] {
            let server = MockServer::start().await;
            listing(&server, sms_url, application).await;
            let watched = Watched::on(None);

            let refused = numbers(&server.uri())
                .register(&account(), watched.watch())
                .await;

            assert!(
                matches!(refused, Err(WatchFailure::Refused(_))),
                "{refused:?}"
            );
            assert_eq!(server.received_requests().await.unwrap().len(), 1);
        }
    }

    /// Archiving clears the number's address while it is still the
    /// registration's, and leaves one someone has changed since.
    #[tokio::test]
    async fn unregistering_clears_only_the_registrations_own_address() {
        let ours = MockServer::start().await;
        listing(&ours, &secret_given(SECRET), "").await;
        Mock::given(method("POST"))
            .and(path(NUMBER_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "sid": "PN0ONE" })))
            .expect(1)
            .mount(&ours)
            .await;
        let changed = MockServer::start().await;
        listing(&changed, "https://desk.acme.example/sms", "").await;
        let watched = Watched::on(Some("PN0ONE"));

        let cleared = numbers(&ours.uri())
            .unregister(&account(), watched.watch())
            .await;
        let left = numbers(&changed.uri())
            .unregister(&account(), watched.watch())
            .await;

        assert_eq!((cleared, left), (Ok(()), Ok(())));
        assert_eq!(changed.received_requests().await.unwrap().len(), 1);
    }

    fn texted(to: &str) -> Vec<u8> {
        url::form_urlencoded::Serializer::new(String::new())
            .append_pair("MessageSid", "SM0ONE")
            .append_pair("From", "+15559870000")
            .append_pair("To", to)
            .append_pair("Body", "My order never arrived")
            .finish()
            .into_bytes()
    }

    fn read(watched: &Watched, address: &str, body: &[u8]) -> Read {
        numbers("https://twilio.test").read(
            watched.watch(),
            Delivery {
                address,
                headers: &[],
                body,
            },
        )
    }

    /// Pat texts the support number: the delivery to the address with its
    /// secret starts the workflow with what Pat wrote.
    #[test]
    fn a_text_to_the_secret_address_starts_the_workflow() {
        let watched = Watched::on(Some("PN0ONE"));

        let read = read(&watched, &secret_given(SECRET), &texted("+15551230000"));

        let Read::Start {
            delivery, input, ..
        } = read
        else {
            panic!("nothing started: {read:?}");
        };
        assert_eq!(delivery, "SM0ONE");
        assert_eq!(
            input
                .at(&DataPath::parse("body").unwrap())
                .map(|body| body.value()),
            Some(FlowValue::Text("My order never arrived"))
        );
    }

    /// A text delivery without the secret is marked forged, while one with
    /// the secret for another phone number is skipped.
    #[test]
    fn a_text_without_the_secret_or_to_another_number_starts_nothing() {
        let watched = Watched::on(Some("PN0ONE"));

        assert_eq!(
            read(&watched, ADDRESS, &texted("+15551230000")),
            Read::Forged
        );
        assert_eq!(
            read(&watched, &secret_given(SECRET), &texted("+15550000000")),
            Read::Skip
        );
    }
}
