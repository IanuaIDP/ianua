//! Every operation the Slack integration offers, grouped by topic:
//! messages, people and channels, each described once with the SDK's
//! [`Operation`].

mod channels;
mod messages;
mod people;

use ianua_integration::form::{Ask, PickerText};
use ianua_integration::rest::operation::{Field, Kind, Operation, Place};

/// The channels the bot can see, picked by id and shown by name.
pub(crate) const CHANNELS: PickerText = PickerText {
    filled_by: "list-channels",
    items_at: "json.channels",
    value_at: "id",
    label_at: "name",
    depends_on: None,
};

/// The channel a step acts in, in the body.
pub(crate) const CHANNEL: Field = Field::required(
    "channel",
    Kind::Text,
    Place::Body,
    "The channel's id, such as C0123ABC; the bot must be a member.",
)
.asked_with(Ask::Picker(CHANNELS));

/// The message a step acts on, in the body, under the name Slack gives it.
pub(crate) const MESSAGE: Field = Field::required(
    "message",
    Kind::Text,
    Place::Body,
    "The message's id, such as an earlier step's json.ts.",
);

/// Every operation, topic by topic.
pub(crate) fn all() -> impl Iterator<Item = &'static Operation> {
    messages::OPERATIONS
        .iter()
        .chain(people::OPERATIONS)
        .chain(channels::OPERATIONS)
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::workflows::data::{FieldName, FlowData};
    use ianua_domain::domains::workflows::integration::IntegrationKey;
    use ianua_integration::ServiceEndpoint;
    use ianua_integration::rest::checks::misdescribed;
    use ianua_integration::rest::request::call;
    use serde_json::json;

    use super::*;

    /// Every operation keeps the SDK's rules.
    #[test]
    fn every_operation_keeps_the_rules() {
        let wrong = misdescribed(&IntegrationKey::new("slack").unwrap(), all());

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

    fn operation(key: &str) -> &'static Operation {
        all().find(|operation| operation.key == key).unwrap()
    }

    fn slack() -> ServiceEndpoint {
        ServiceEndpoint::at("https://slack.com/api/").unwrap()
    }

    /// Reacting to a message sends Slack's own names for the message and
    /// the emoji.
    #[test]
    fn a_reaction_sends_slacks_names() {
        let given = arguments(vec![
            ("channel", text("C0ONCALL")),
            ("message", text("1700000000.1")),
            ("emoji", text("white_check_mark")),
        ]);

        let made = call(operation("add-reaction"), &slack(), &given).unwrap();

        assert_eq!(made.url.as_str(), "https://slack.com/api/reactions.add");
        assert_eq!(
            made.body,
            Some(
                json!({ "channel": "C0ONCALL", "timestamp": "1700000000.1", "name": "white_check_mark" })
            )
        );
    }

    /// Finding a member by email asks in the query and sends no body.
    #[test]
    fn finding_a_member_asks_in_the_query() {
        let given = arguments(vec![("email", text("pat@acme.test"))]);

        let made = call(operation("find-user-by-email"), &slack(), &given).unwrap();

        assert_eq!(
            made.url.as_str(),
            "https://slack.com/api/users.lookupByEmail?email=pat%40acme.test"
        );
        assert_eq!(made.body, None);
    }
}
