//! Every operation the Telegram integration offers: sending, forwarding,
//! editing, pinning and deleting a bot's messages, and reading a chat,
//! each described once with the SDK's [`Operation`] as a Bot API method.

use ianua_domain::domains::workflows::integration::form::Tone;
use ianua_domain::types::{ActionClass, DeclaredAction};
use ianua_integration::form::{Ask, ChoiceText};
use ianua_integration::rest::operation::{Field, Kind, Operation, Place, Segment, Shape, Verb};

/// The chat a step acts in, in the body.
const CHAT: Field = Field::required(
    "chat",
    Kind::Text,
    Place::Body,
    "The chat, by its id such as -1001234567890, or a public channel's @name.",
)
.sent_as("chat_id");

/// The chat a read names, in the query.
const CHAT_READ: Field = Field::required(
    "chat",
    Kind::Text,
    Place::Query,
    "The chat, by its id such as -1001234567890, or a public channel's @name.",
)
.sent_as("chat_id");

/// The message a step acts on, in the body.
const MESSAGE: Field = Field::required(
    "message",
    Kind::Count,
    Place::Body,
    "The message's id in the chat, such as an earlier step's json.result.message_id.",
)
.sent_as("message_id");

/// How a message's text is read: plain, or with Telegram's markup.
const FORMATS: &[ChoiceText] = &[
    ChoiceText {
        value: "HTML",
        label: "With HTML tags",
        tone: Tone::Neutral,
    },
    ChoiceText {
        value: "MarkdownV2",
        label: "With Markdown",
        tone: Tone::Neutral,
    },
];

/// How a message's text is read, in the body.
const FORMAT: Field = Field::optional(
    "format",
    Kind::Text,
    Place::Body,
    "How the text is read: HTML or MarkdownV2; as plain text when not given.",
)
.sent_as("parse_mode")
.asked_with(Ask::Choices(FORMATS))
.more_options();

/// What a step that sends a message gives back.
const SENT: &[(&str, &str)] = &[
    (
        "json.result.message_id",
        "The message's id, which later steps name.",
    ),
    ("json.result.chat.id", "The chat it went to."),
    ("status", "The status Telegram answered with."),
];

/// The address of a Bot API method.
macro_rules! method {
    ($name:literal) => {
        &[Segment::Fixed($name)]
    };
}

/// Every operation.
const OPERATIONS: &[Operation] = &[
    Operation {
        key: "send-message",
        title: "Send a message",
        description: "Sends a text message as the bot to a chat, group or channel it is in.",
        effect: DeclaredAction::Declared(ActionClass::Communicate),
        verb: Verb::Post,
        path: method!("sendMessage"),
        fields: &[
            CHAT,
            Field::required("text", Kind::Text, Place::Body, "The message's text.")
                .asked_with(Ask::LongText),
            FORMAT,
            Field::optional(
                "silent",
                Kind::Flag,
                Place::Body,
                "Whether it arrives without a sound; false when not given.",
            )
            .sent_as("disable_notification")
            .more_options(),
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: SENT,
    },
    Operation {
        key: "send-photo",
        title: "Send a photo",
        description: "Sends a photo found at a web address, with a caption, as the bot to a chat.",
        effect: DeclaredAction::Declared(ActionClass::Communicate),
        verb: Verb::Post,
        path: method!("sendPhoto"),
        fields: &[
            CHAT,
            Field::required(
                "photo",
                Kind::Text,
                Place::Body,
                "The photo's web address, which Telegram fetches.",
            ),
            Field::optional("caption", Kind::Text, Place::Body, "The photo's caption."),
            FORMAT,
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: SENT,
    },
    Operation {
        key: "forward-message",
        title: "Forward a message",
        description: "Forwards a message from one chat to another, as the bot.",
        effect: DeclaredAction::Declared(ActionClass::Communicate),
        verb: Verb::Post,
        path: method!("forwardMessage"),
        fields: &[
            CHAT,
            Field::required(
                "from",
                Kind::Text,
                Place::Body,
                "The chat the message is in, by id or @name.",
            )
            .sent_as("from_chat_id"),
            MESSAGE,
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: SENT,
    },
    Operation {
        key: "edit-message",
        title: "Edit a message",
        description: "Changes the text of a message the bot sent.",
        effect: DeclaredAction::Declared(ActionClass::Write),
        verb: Verb::Post,
        path: method!("editMessageText"),
        fields: &[
            CHAT,
            MESSAGE,
            Field::required("text", Kind::Text, Place::Body, "The message's new text.")
                .asked_with(Ask::LongText),
            FORMAT,
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            ("json.result.message_id", "The message's id."),
            ("status", "The status Telegram answered with."),
        ],
    },
    Operation {
        key: "pin-message",
        title: "Pin a message",
        description: "Pins a message at the top of a chat, where the bot may pin.",
        effect: DeclaredAction::Declared(ActionClass::Write),
        verb: Verb::Post,
        path: method!("pinChatMessage"),
        fields: &[
            CHAT,
            MESSAGE,
            Field::optional(
                "silent",
                Kind::Flag,
                Place::Body,
                "Whether the chat's members are not told of it; false when not given.",
            )
            .sent_as("disable_notification"),
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            ("json.result", "True once it is pinned."),
            ("status", "The status Telegram answered with."),
        ],
    },
    Operation {
        key: "delete-message",
        title: "Delete a message",
        description: "Deletes a message from a chat for everyone, for good.",
        effect: DeclaredAction::Declared(ActionClass::Delete),
        verb: Verb::Post,
        path: method!("deleteMessage"),
        fields: &[CHAT, MESSAGE],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            ("json.result", "True once it is deleted."),
            ("status", "The status Telegram answered with."),
        ],
    },
    Operation {
        key: "get-chat",
        title: "Read a chat",
        description: "Reads a chat's title, kind and description.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Get,
        path: method!("getChat"),
        fields: &[CHAT_READ],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            ("json.result.id", "The chat's id."),
            ("json.result.title", "Its title, for a group or channel."),
            (
                "json.result.type",
                "What kind of chat it is: private, group, supergroup or channel.",
            ),
            ("status", "The status Telegram answered with."),
        ],
    },
    Operation {
        key: "count-members",
        title: "Count a chat's members",
        description: "Counts the members of a group or channel.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Get,
        path: method!("getChatMemberCount"),
        fields: &[CHAT_READ],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            ("json.result", "How many members it has."),
            ("status", "The status Telegram answered with."),
        ],
    },
];

/// Every operation.
pub(crate) fn all() -> impl Iterator<Item = &'static Operation> {
    OPERATIONS.iter()
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
        let wrong = misdescribed(&IntegrationKey::new("telegram").unwrap(), all());

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

    fn bot() -> ServiceEndpoint {
        ServiceEndpoint::at("https://api.telegram.org/bot123:abc").unwrap()
    }

    /// Sending a message calls the method under the bot's own address,
    /// with the chat and text under Telegram's names.
    #[test]
    fn a_message_goes_to_the_method_under_the_bot() {
        let given = arguments(vec![
            ("chat", text("-1001234567890")),
            ("text", text("The build passed.")),
            ("silent", FlowData::bool(true)),
        ]);

        let made = call(operation("send-message"), &bot(), &given).unwrap();

        assert_eq!(
            made.url.as_str(),
            "https://api.telegram.org/bot123:abc/sendMessage"
        );
        assert_eq!(
            made.body,
            Some(json!({
                "chat_id": "-1001234567890",
                "text": "The build passed.",
                "disable_notification": true
            }))
        );
    }

    /// A public channel handle becomes an escaped `chat_id` on the bot's getChat URL.
    #[test]
    fn reading_a_chat_names_it_in_the_query() {
        let given = arguments(vec![("chat", text("@acme_news"))]);

        let made = call(operation("get-chat"), &bot(), &given).unwrap();

        assert_eq!(
            made.url.as_str(),
            "https://api.telegram.org/bot123:abc/getChat?chat_id=%40acme_news"
        );
    }

    /// Sending without a chat and deleting with a text message number each
    /// fail request construction.
    #[test]
    fn no_chat_or_a_wordy_message_builds_no_call() {
        let nowhere = arguments(vec![("text", text("Hi"))]);
        let wordy = arguments(vec![("chat", text("-100")), ("message", text("first"))]);

        assert!(call(operation("send-message"), &bot(), &nowhere).is_err());
        assert!(call(operation("delete-message"), &bot(), &wordy).is_err());
    }
}
