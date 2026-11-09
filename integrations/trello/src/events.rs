//! What Trello sends that a workflow may start on: a card created, a card
//! moved to another list, and a comment added to a card, each on one board.
//!
//! Publishing a workflow registers a webhook on its board through the
//! account's key and token. Trello signs what it sends with the secret of
//! the key's owner, which the platform does not hold, so the registration's
//! address carries its own secret instead, and a delivery to it without
//! that secret is read no further. Trello asks the address with a `HEAD`
//! request before it takes the webhook, and the address must answer it
//! with success. Trello's webhooks never lapse, so renewing one keeps it as
//! it stands; archiving deletes it.

use async_trait::async_trait;
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::domains::workflows::integration::InputNeed;
use ianua_domain::domains::workflows::integration::events::ServiceEventKey;
use ianua_integration::events::{
    Delivery, Events, HeldCredential, Read, Watch, WatchFailure, Watching,
};
use ianua_integration::rest::event::{EventText, FilterText, picked};
use ianua_integration::rest::operation::Verb;
use ianua_integration::rest::watch::{WatchCall, WatchCalls};
use ianua_integration::signature::{carries_secret, with_secret};
use serde_json::Value;

/// The board every event is watched on.
const BOARD: FilterText = FilterText {
    name: "board",
    need: InputNeed::Required,
    meaning: "The board to watch, by its id, such as one list-boards gives.",
};

/// A card created.
const CARD_CREATED: EventText = EventText {
    key: "card-created",
    title: "A card is created",
    description: "Someone creates a card on the board.",
    filters: &[BOARD],
    outputs: &[
        ("action.data.card.id", "The card's id."),
        ("action.data.card.name", "The card's name."),
        (
            "action.data.list.id",
            "The id of the list it was created on.",
        ),
        ("action.data.list.name", "The name of that list."),
        ("action.data.board.name", "The board's name."),
        ("action.memberCreator.fullName", "Who created it."),
    ],
};

/// A card moved to another list.
const CARD_MOVED: EventText = EventText {
    key: "card-moved",
    title: "A card is moved",
    description: "Someone moves a card on the board from one list to another.",
    filters: &[BOARD],
    outputs: &[
        ("action.data.card.id", "The card's id."),
        ("action.data.card.name", "The card's name."),
        (
            "action.data.listBefore.name",
            "The name of the list it left.",
        ),
        (
            "action.data.listAfter.id",
            "The id of the list it moved to.",
        ),
        (
            "action.data.listAfter.name",
            "The name of the list it moved to.",
        ),
        ("action.memberCreator.fullName", "Who moved it."),
    ],
};

/// A comment added to a card.
const CARD_COMMENTED: EventText = EventText {
    key: "card-commented",
    title: "A card is commented on",
    description: "Someone adds a comment to a card on the board.",
    filters: &[BOARD],
    outputs: &[
        ("action.data.card.id", "The card's id."),
        ("action.data.card.name", "The card's name."),
        ("action.data.text", "What the comment says."),
        ("action.memberCreator.fullName", "Who wrote it."),
    ],
};

/// What a Trello action must show for an event: its type and, for an
/// update, the part of its data that says what changed.
struct Kind {
    text: &'static EventText,
    action: &'static str,
    changed: Option<&'static str>,
}

/// Every event, with Trello's names for it.
const KINDS: &[Kind] = &[
    Kind {
        text: &CARD_CREATED,
        action: "createCard",
        changed: None,
    },
    Kind {
        text: &CARD_MOVED,
        action: "updateCard",
        changed: Some("listAfter"),
    },
    Kind {
        text: &CARD_COMMENTED,
        action: "commentCard",
        changed: None,
    },
];

/// What Trello is told a webhook is for.
const PURPOSE: &str = "Starts a workflow";

/// Every event Trello offers, described.
pub(crate) fn all() -> Vec<&'static EventText> {
    KINDS.iter().map(|kind| kind.text).collect()
}

/// Trello's webhooks for workflow triggers.
pub(crate) struct Webhooks {
    calls: WatchCalls,
    exposure: DataClassLevel,
}

impl Webhooks {
    /// Webhooks registered through `calls`, their deliveries counted as
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
        kind_of(watch.event).ok_or_else(unknown)?;
        let board = board(watch)?;
        let address = with_secret(watch.address, watch.secret)
            .ok_or_else(|| WatchFailure::Refused("the registration has no address".to_owned()))?;
        let taken = self
            .calls
            .send(
                credential,
                WatchCall {
                    verb: Verb::Post,
                    path: &["webhooks"],
                    query: &[
                        ("callbackURL", address.as_str()),
                        ("idModel", board),
                        ("description", PURPOSE),
                    ],
                    body: None,
                },
            )
            .await?
            .taken("Trello")?;
        let Some(id) = taken.get("id").and_then(Value::as_str) else {
            return Err(WatchFailure::Refused("Trello named no webhook".to_owned()));
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
            .calls
            .send(
                credential,
                WatchCall {
                    verb: Verb::Delete,
                    path: &["webhooks", remote],
                    query: &[],
                    body: None,
                },
            )
            .await?;
        if answered.status == 404 {
            return Ok(());
        }
        answered.taken("Trello").map(|_| ())
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
        let action = &payload["action"];
        let Some(id) = action["id"].as_str() else {
            return Read::Skip;
        };
        if !passes(kind, action, watch) {
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

/// The event `key` names, if Trello offers it.
fn kind_of(key: &ServiceEventKey) -> Option<&'static Kind> {
    KINDS.iter().find(|kind| kind.text.key == key.as_str())
}

/// The refusal of an event Trello does not offer.
fn unknown() -> WatchFailure {
    WatchFailure::Refused("Trello sends no such event".to_owned())
}

/// The board `watch` watches, by its id.
fn board<'a>(watch: Watch<'a>) -> Result<&'a str, WatchFailure> {
    let id = watch
        .filter(BOARD.name)
        .ok_or_else(|| WatchFailure::Refused("the trigger names no board".to_owned()))?;
    let plain = !id.is_empty() && id.chars().all(|c| c.is_ascii_alphanumeric());
    match plain {
        true => Ok(id),
        false => Err(WatchFailure::Refused(
            "the board is named by its id, in letters and digits".to_owned(),
        )),
    }
}

/// A webhook Trello keeps as `remote` until it is deleted.
fn standing(remote: String) -> Watching {
    Watching {
        remote,
        lapses: None,
        routed_by: None,
    }
}

/// Whether `action` is `kind`'s, on the watched board.
fn passes(kind: &Kind, action: &Value, watch: Watch<'_>) -> bool {
    let data = &action["data"];
    let typed = action["type"].as_str() == Some(kind.action);
    let changed = kind
        .changed
        .is_none_or(|part| data.get(part).is_some_and(Value::is_object));
    let on_board = watch.filter(BOARD.name).is_some_and(|watched| {
        data["board"]["id"].as_str() == Some(watched)
            || data["board"]["shortLink"].as_str() == Some(watched)
    });
    typed && changed && on_board
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use ianua_domain::domains::workflows::data::{DataPath, FieldName, FlowValue};
    use ianua_domain::domains::workflows::triggers::{EventFilter, FilterValue};
    use ianua_domain::shared::security::secret::Secret;
    use ianua_integration::ServiceEndpoint;
    use ianua_integration::rest::access::Access;
    use serde_json::json;
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, Request, ResponseTemplate};

    use super::*;

    const ADDRESS: &str =
        "https://ianua.test/api/v1/integrations/events/7d3f2c1a-0000-4000-8000-000000000005";

    const SECRET: &str = "the registration's trello words";

    const KEY_AND_TOKEN: &str = r#"{"key":"testkeyforacme","token":"testtokenforann"}"#;

    fn webhooks(endpoint: &str) -> Webhooks {
        Webhooks::new(
            WatchCalls::new(
                Access::KeyAndToken {
                    endpoint: ServiceEndpoint::at(endpoint).unwrap(),
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
        fn on(event: &str, board: &str) -> Self {
            Self {
                event: ServiceEventKey::new(event).unwrap(),
                filters: vec![EventFilter::new(
                    FieldName::new("board").unwrap(),
                    FilterValue::new(board).unwrap(),
                )],
                secret: Secret::new(SECRET.to_owned()),
                remote: Some("hookone"),
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

    /// Whether `request` carries the key and token in Trello's header,
    /// read whole: wiremock's header matcher splits a value at its commas.
    fn signed(request: &Request) -> bool {
        request.headers.get("authorization").is_some_and(|value| {
            value == r#"OAuth oauth_consumer_key="testkeyforacme", oauth_token="testtokenforann""#
        })
    }

    fn key_and_token() -> HeldCredential {
        HeldCredential::new(Secret::new(KEY_AND_TOKEN.to_owned()))
    }

    fn secret_address(secret: &str) -> String {
        with_secret(ADDRESS, &Secret::new(secret.to_owned())).unwrap()
    }

    fn action(kind: &str, board: &str, data: Value) -> Vec<u8> {
        let mut data = data;
        data["board"] = json!({ "id": board, "name": "Sales", "shortLink": "salesln" });
        data["card"] = json!({ "id": "card42", "name": "Call the supplier" });
        serde_json::to_vec(&json!({
            "model": { "id": board },
            "action": {
                "id": "action one",
                "type": kind,
                "data": data,
                "memberCreator": { "fullName": "Pat Lee", "username": "pat" }
            }
        }))
        .unwrap()
    }

    fn read(watched: &Watched, address: &str, body: &[u8]) -> Read {
        webhooks("https://api.trello.test/1/").read(
            watched.watch(),
            Delivery {
                address,
                headers: &[],
                body,
            },
        )
    }

    /// Ann's workflow watches the sales board for new cards: publishing
    /// registers a webhook on the board with her key and token, pointing
    /// at the registration's address with its secret, and keeps Trello's
    /// id for it.
    #[tokio::test]
    async fn registering_makes_a_webhook_on_the_board() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/1/webhooks"))
            .and(signed)
            .and(query_param("idModel", "salesboard"))
            .and(query_param("callbackURL", secret_address(SECRET).as_str()))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "id": "hookone" })))
            .expect(1)
            .mount(&server)
            .await;
        let watched = Watched::on("card-created", "salesboard");

        let watching = webhooks(&format!("{}/1/", server.uri()))
            .register(&key_and_token(), watched.watch())
            .await
            .unwrap();

        assert_eq!(watching.remote, "hookone");
        assert_eq!(watching.lapses, None);
    }

    /// A board containing path traversal is refused before a request;
    /// Trello's 400 also refuses registration, leaving one request recorded.
    #[tokio::test]
    async fn a_crooked_board_or_a_refusal_registers_nothing() {
        let server = MockServer::start().await;
        Mock::given(path("/1/webhooks"))
            .respond_with(ResponseTemplate::new(400))
            .mount(&server)
            .await;
        let webhooks = webhooks(&format!("{}/1/", server.uri()));
        let crooked = Watched::on("card-created", "sales/../admin");
        let refused = Watched::on("card-created", "lockedboard");

        let climbed = webhooks.register(&key_and_token(), crooked.watch()).await;
        let turned_down = webhooks.register(&key_and_token(), refused.watch()).await;

        assert!(matches!(climbed, Err(WatchFailure::Refused(_))));
        assert!(matches!(turned_down, Err(WatchFailure::Refused(_))));
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }

    /// Archiving deletes the webhook; one Trello no longer knows counts as
    /// deleted.
    #[tokio::test]
    async fn unregistering_deletes_the_webhook_even_when_gone() {
        let server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .and(path("/1/webhooks/hookone"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        Mock::given(method("DELETE"))
            .and(path("/1/webhooks/hookgone"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;
        let webhooks = webhooks(&format!("{}/1/", server.uri()));
        let kept = Watched::on("card-created", "salesboard");
        let gone = Watched {
            remote: Some("hookgone"),
            ..Watched::on("card-created", "salesboard")
        };

        assert_eq!(
            webhooks.unregister(&key_and_token(), kept.watch()).await,
            Ok(())
        );
        assert_eq!(
            webhooks.unregister(&key_and_token(), gone.watch()).await,
            Ok(())
        );
    }

    /// Pat creates a card on the sales board: the delivery to the
    /// registration's address starts the workflow with the card's id and
    /// list, under Trello's id for the action.
    #[test]
    fn a_card_created_on_the_board_starts_the_workflow() {
        let watched = Watched::on("card-created", "salesboard");
        let body = action(
            "createCard",
            "salesboard",
            json!({ "list": { "id": "inboxlist1", "name": "Inbox" } }),
        );

        let read = read(&watched, &secret_address(SECRET), &body);

        let Read::Start {
            delivery, input, ..
        } = read
        else {
            panic!("the delivery started nothing: {read:?}");
        };
        assert_eq!(delivery, "action one");
        assert_eq!(
            input
                .at(&DataPath::parse("action.data.list.id").unwrap())
                .map(|value| value.value()),
            Some(FlowValue::Text("inboxlist1"))
        );
        assert!(input.at(&DataPath::parse("model").unwrap()).is_none());
    }

    /// Card deliveries to an address with the wrong registration secret or
    /// no secret are marked forged rather than returned as workflow starts.
    #[test]
    fn a_delivery_without_the_secret_is_forged() {
        let watched = Watched::on("card-created", "salesboard");
        let body = action("createCard", "salesboard", json!({}));

        assert_eq!(
            read(&watched, &secret_address("mallory's own words"), &body),
            Read::Forged
        );
        assert_eq!(read(&watched, ADDRESS, &body), Read::Forged);
    }

    /// A card moved starts only on an update that changed its list; an
    /// update of its name, another kind of action and another board start
    /// nothing.
    #[test]
    fn only_a_change_of_list_on_the_board_is_a_move() {
        let watched = Watched::on("card-moved", "salesboard");
        let address = secret_address(SECRET);
        let moved = action(
            "updateCard",
            "salesboard",
            json!({
                "listBefore": { "id": "inboxlist1", "name": "Inbox" },
                "listAfter": { "id": "donelist", "name": "Done" }
            }),
        );
        let renamed = action(
            "updateCard",
            "salesboard",
            json!({ "old": { "name": "Call" } }),
        );
        let commented = action("commentCard", "salesboard", json!({ "text": "Done" }));
        let elsewhere = action(
            "updateCard",
            "otherboard",
            json!({ "listAfter": { "id": "donelist", "name": "Done" } }),
        );

        let on_move = read(&watched, &address, &moved);

        assert!(matches!(on_move, Read::Start { .. }), "{on_move:?}");
        for skipped in [renamed, commented, elsewhere] {
            assert_eq!(read(&watched, &address, &skipped), Read::Skip);
        }
    }
}
