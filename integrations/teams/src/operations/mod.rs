//! Every operation the Microsoft Teams integration offers, grouped by
//! topic: teams and channels, and messages, each described once with the
//! SDK's [`Operation`], with the pickers its forms fill from the account's
//! own teams, channels and chats.

mod channels;
mod messages;

use ianua_domain::domains::workflows::integration::form::Tone;
use ianua_integration::form::{Ask, ChoiceText, PickerText};
use ianua_integration::rest::operation::{Field, Kind, Operation, Place, Segment};

/// The teams the account joined, picked by name.
const TEAMS: PickerText = PickerText {
    filled_by: "list-teams",
    items_at: "json.value",
    value_at: "id",
    label_at: "displayName",
    depends_on: None,
};

/// The chosen team's channels, picked by name.
const CHANNELS: PickerText = PickerText {
    filled_by: "list-channels",
    items_at: "json.value",
    value_at: "id",
    label_at: "displayName",
    depends_on: Some("team"),
};

/// The team a step acts in, in the path.
pub(crate) const TEAM: Field = Field::required(
    "team",
    Kind::Text,
    Place::Path,
    "The team's id, as listing the account's teams gives it.",
)
.asked_with(Ask::Picker(TEAMS));

/// The channel a step acts in, in the path.
pub(crate) const CHANNEL: Field = Field::required(
    "channel",
    Kind::Text,
    Place::Path,
    "The channel's id, such as 19:abc@thread.tacv2, as listing the team's channels gives it.",
)
.asked_with(Ask::Picker(CHANNELS));

/// A message's text, where Microsoft reads it.
pub(crate) const TEXT: Field = Field::required(
    "text",
    Kind::Text,
    Place::Body,
    "The message, as plain text or as HTML when the format says so.",
)
.sent_as("body.content")
.asked_with(Ask::LongText);

/// How a message's text is read.
pub(crate) const FORMAT: Field = Field::optional(
    "format",
    Kind::Text,
    Place::Body,
    "How the text is read: text, or html for links and formatting; text when not given.",
)
.sent_as("body.contentType")
.asked_with(Ask::Choices(&[
    ChoiceText {
        value: "text",
        label: "Plain text",
        tone: Tone::Neutral,
    },
    ChoiceText {
        value: "html",
        label: "HTML",
        tone: Tone::Info,
    },
]))
.more_options();

/// The path of a team's channels.
pub(crate) const CHANNELS_OF: &[Segment] = &[
    Segment::Fixed("teams"),
    Segment::Input("team"),
    Segment::Fixed("channels"),
];

/// The path of one channel.
pub(crate) const ONE_CHANNEL: &[Segment] = &[
    Segment::Fixed("teams"),
    Segment::Input("team"),
    Segment::Fixed("channels"),
    Segment::Input("channel"),
];

/// Every operation, topic by topic.
pub(crate) fn all() -> impl Iterator<Item = &'static Operation> {
    channels::OPERATIONS.iter().chain(messages::OPERATIONS)
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::workflows::data::{FieldName, FlowData};
    use ianua_domain::domains::workflows::execution::step::ActionOutcome;
    use ianua_domain::domains::workflows::integration::IntegrationKey;
    use ianua_integration::ServiceEndpoint;
    use ianua_integration::rest::checks::misdescribed;
    use ianua_integration::rest::request::{Call, call};
    use serde_json::json;

    use super::*;

    const TEAM_ID: &str = "8a1e6f3c-0000-4000-8000-00000000c0de";

    const GENERAL: &str = "19:general@thread.tacv2";

    /// Every operation keeps the SDK's rules: a key used once, every input
    /// explained, every picker filled by a read, every path input placed,
    /// no body on a read, something given back.
    #[test]
    fn every_operation_keeps_the_rules() {
        let wrong = misdescribed(&IntegrationKey::new("teams").unwrap(), all());

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

    fn made(key: &str, given: Vec<(&str, FlowData)>) -> Result<Call, ActionOutcome> {
        let operation = all().find(|operation| operation.key == key).unwrap();
        let graph = ServiceEndpoint::at("https://graph.microsoft.com/v1.0/").unwrap();
        call(operation, &graph, &arguments(given))
    }

    /// Ann's workflow posts to the team's General channel: the text and its
    /// format go inside the message's body, where Microsoft reads them.
    #[test]
    fn posting_a_message_nests_its_text_in_the_body() {
        let posted = made(
            "post-message",
            vec![
                ("team", text(TEAM_ID)),
                ("channel", text(GENERAL)),
                ("text", text("<b>Deploy</b> finished")),
                ("format", text("html")),
            ],
        )
        .unwrap();

        assert_eq!(
            posted.url.as_str(),
            "https://graph.microsoft.com/v1.0/teams/8a1e6f3c-0000-4000-8000-00000000c0de/channels/19:general@thread.tacv2/messages"
        );
        assert_eq!(
            posted.body,
            Some(json!({ "body": { "content": "<b>Deploy</b> finished", "contentType": "html" } }))
        );
    }

    /// A reply goes under the message it answers; without a format the
    /// text is sent alone, which Microsoft reads as plain text.
    #[test]
    fn replying_goes_under_the_message_answered() {
        let replied = made(
            "reply-to-message",
            vec![
                ("team", text(TEAM_ID)),
                ("channel", text(GENERAL)),
                ("message", text("1730700000000")),
                ("text", text("Rolled back.")),
            ],
        )
        .unwrap();

        assert_eq!(
            replied.url.as_str(),
            "https://graph.microsoft.com/v1.0/teams/8a1e6f3c-0000-4000-8000-00000000c0de/channels/19:general@thread.tacv2/messages/1730700000000/replies"
        );
        assert_eq!(
            replied.body,
            Some(json!({ "body": { "content": "Rolled back." } }))
        );
    }

    /// Sending to a chat names the chat in the path.
    #[test]
    fn sending_a_chat_message_names_the_chat() {
        let sent = made(
            "send-chat-message",
            vec![
                ("chat", text("19:meeting_abc@thread.v2")),
                ("text", text("Joining in five minutes.")),
            ],
        )
        .unwrap();

        assert_eq!(
            sent.url.as_str(),
            "https://graph.microsoft.com/v1.0/chats/19:meeting_abc@thread.v2/messages"
        );
    }

    /// Creating a channel names it and always asks for a standard channel,
    /// open to every member.
    #[test]
    fn creating_a_channel_asks_for_a_standard_one() {
        let created = made(
            "create-channel",
            vec![("team", text(TEAM_ID)), ("name", text("Incident 42"))],
        )
        .unwrap();

        assert_eq!(
            created.body,
            Some(json!({ "displayName": "Incident 42", "membershipType": "standard" }))
        );
    }

    /// Ann opens the team picker: the account's teams are listed. Choosing
    /// one lists its channels for the channel picker, and her chats fill
    /// the chat picker, ten at most.
    #[test]
    fn pickers_list_teams_then_their_channels_and_chats() {
        let teams = made("list-teams", Vec::new()).unwrap();
        let channels = made("list-channels", vec![("team", text(TEAM_ID))]).unwrap();
        let chats = made(
            "list-chats",
            vec![("limit", FlowData::number(10.0).unwrap())],
        )
        .unwrap();

        assert_eq!(
            teams.url.as_str(),
            "https://graph.microsoft.com/v1.0/me/joinedTeams"
        );
        assert_eq!(
            channels.url.as_str(),
            "https://graph.microsoft.com/v1.0/teams/8a1e6f3c-0000-4000-8000-00000000c0de/channels"
        );
        assert_eq!(
            chats.url.as_str(),
            "https://graph.microsoft.com/v1.0/me/chats?%24top=10"
        );
        assert_eq!(channels.body, None, "a read sends no body");
    }

    /// Missing team or message text, a channel ID of `..`, and a text value
    /// for the chat limit each fail request construction.
    #[test]
    fn a_missing_input_a_crooked_path_or_a_wrong_kind_builds_no_call() {
        let teamless = made("list-channels", Vec::new());
        let wordless = made(
            "post-message",
            vec![("team", text(TEAM_ID)), ("channel", text(GENERAL))],
        );
        let climbing = made(
            "delete-channel",
            vec![("team", text(TEAM_ID)), ("channel", text(".."))],
        );
        let worded = made("list-chats", vec![("limit", text("ten"))]);

        for refused in [teamless, wordless, climbing, worded] {
            assert!(matches!(refused, Err(ActionOutcome::Failed(_))));
        }
    }
}
