//! Every operation the Gmail integration offers, grouped by topic:
//! messages and threads, and labels, each described once with the SDK's
//! [`Operation`]. Every path is the account's own mailbox, `users/me`.

mod labels;
mod messages;

use ianua_integration::form::PickerText;
use ianua_integration::rest::operation::{Field, Kind, Operation, Place};

/// The mailbox's labels, picked by id and shown by name.
pub(crate) const LABELS: PickerText = PickerText {
    filled_by: "list-labels",
    items_at: "json.labels",
    value_at: "id",
    label_at: "name",
    depends_on: None,
};

/// Gmail's own search words, in the query.
pub(crate) const SEARCH: Field = Field::optional(
    "search",
    Kind::Text,
    Place::Query,
    "What to look for, in Gmail's own search words, such as from:bob@acme.test is:unread; every message when not given.",
)
.sent_as("q")
.example("from:bob@acme.test is:unread");

/// How many a search gives at most, under Gmail's name.
pub(crate) const LIMIT: Field = Field::optional(
    "limit",
    Kind::Count,
    Place::Query,
    "How many to give back, at most 500; 100 when not given.",
)
.sent_as("maxResults")
.more_options();

/// Every operation, topic by topic.
pub(crate) fn all() -> impl Iterator<Item = &'static Operation> {
    messages::OPERATIONS.iter().chain(labels::OPERATIONS)
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use ianua_domain::domains::data_classification::level::DataClassLevel;
    use ianua_domain::domains::workflows::data::{FieldName, FlowData};
    use ianua_domain::domains::workflows::integration::IntegrationKey;
    use ianua_domain::types::{ActionClass, DeclaredAction};
    use ianua_integration::ServiceEndpoint;
    use ianua_integration::rest::checks::misdescribed;
    use ianua_integration::rest::request::call;
    use serde_json::json;

    use super::*;

    /// Every operation keeps the SDK's rules.
    #[test]
    fn every_operation_keeps_the_rules() {
        let wrong = misdescribed(&IntegrationKey::new("gmail").unwrap(), all());

        assert!(wrong.is_empty(), "{}", wrong.join("\n"));
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

    fn texts(values: &[&str]) -> FlowData {
        FlowData::list(values.iter().map(|value| text(value)).collect()).unwrap()
    }

    fn operation(key: &str) -> &'static Operation {
        all().find(|operation| operation.key == key).unwrap()
    }

    fn api() -> ServiceEndpoint {
        ServiceEndpoint::at("https://gmail.googleapis.com/gmail/v1/").unwrap()
    }

    /// Searching sends Gmail's search words and the limit under Gmail's
    /// names, in the account's own mailbox.
    #[test]
    fn searching_sends_gmails_own_words() {
        let given = arguments(vec![
            ("search", text("from:bob@acme.test is:unread")),
            ("limit", FlowData::number(10.0).unwrap()),
        ]);

        let made = call(operation("search-messages"), &api(), &given).unwrap();

        assert_eq!(
            made.url.as_str(),
            "https://gmail.googleapis.com/gmail/v1/users/me/messages\
             ?q=from%3Abob%40acme.test+is%3Aunread&maxResults=10"
        );
    }

    /// Reading a message asks for its headers alone, each named once.
    #[test]
    fn reading_a_message_asks_for_its_headers() {
        let given = arguments(vec![("message", text("18c2"))]);

        let made = call(operation("get-message"), &api(), &given).unwrap();

        assert_eq!(
            made.url.as_str(),
            "https://gmail.googleapis.com/gmail/v1/users/me/messages/18c2\
             ?format=metadata&metadataHeaders=From&metadataHeaders=To\
             &metadataHeaders=Subject&metadataHeaders=Date"
        );
    }

    /// Ann's workflow mails Bob and Cy in a thread: one whole message in
    /// `raw`, its recipients and subject as headers, and the thread beside
    /// it.
    #[test]
    fn sending_writes_one_whole_message() {
        let given = arguments(vec![
            ("to", texts(&["bob@acme.test", "cy@acme.test"])),
            ("subject", text("Build passed")),
            ("text", text("All green.")),
            ("thread", text("t-7")),
        ]);

        let made = call(operation("send-message"), &api(), &given).unwrap();

        let body = made.body.unwrap();
        let raw = URL_SAFE_NO_PAD
            .decode(body["raw"].as_str().unwrap())
            .unwrap();
        let message = String::from_utf8(raw).unwrap();
        assert!(message.contains("To: bob@acme.test, cy@acme.test\r\n"));
        assert!(message.contains("Subject: Build passed\r\n"));
        assert_eq!(body["threadId"], "t-7");
        assert_eq!(
            made.url.as_str(),
            "https://gmail.googleapis.com/gmail/v1/users/me/messages/send"
        );
    }

    /// A subject injecting another header and a message without recipients
    /// each fail request construction.
    #[test]
    fn a_smuggled_header_or_no_recipient_builds_no_call() {
        let smuggled = arguments(vec![
            ("to", texts(&["bob@acme.test"])),
            ("subject", text("Hi\nBcc: mallory@evil.test")),
            ("text", text("Hello.")),
        ]);
        let nobody = arguments(vec![("subject", text("Hi")), ("text", text("Hello."))]);

        assert!(call(operation("send-message"), &api(), &smuggled).is_err());
        assert!(call(operation("send-message"), &api(), &nobody).is_err());
    }

    /// Marking a message read takes `UNREAD` off it under Gmail's name.
    #[test]
    fn marking_read_takes_unread_off() {
        let given = arguments(vec![
            ("message", text("18c2")),
            ("remove", texts(&["UNREAD"])),
        ]);

        let made = call(operation("change-labels"), &api(), &given).unwrap();

        assert_eq!(made.body, Some(json!({ "removeLabelIds": ["UNREAD"] })));
    }

    /// The trash keeps a message for 30 days, so moving it there is a
    /// write, not a removal for good.
    #[test]
    fn the_trash_is_a_write() {
        assert_eq!(
            operation("trash-message").effect,
            DeclaredAction::Declared(ActionClass::Write)
        );
    }

    /// The labels added or taken off are picked from the mailbox's labels,
    /// which listing them gives back.
    #[test]
    fn labels_are_picked_from_the_mailbox() {
        let guide = operation("change-labels").guide(None).unwrap();
        let add = FieldName::new("add").unwrap();
        let picker = guide.input(&add).unwrap().form().block().picker().unwrap();
        let filler = operation(picker.filled_by().as_str());

        let spec = filler
            .spec(
                &IntegrationKey::new("gmail").unwrap(),
                DataClassLevel::Internal,
            )
            .unwrap();

        assert_eq!(spec.effect(), DeclaredAction::Declared(ActionClass::Read));
        assert!(
            filler
                .outputs
                .iter()
                .any(|(path, _)| *path == picker.items_at().to_string())
        );
    }
}
