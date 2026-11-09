//! Messages: listing a channel's messages, posting to a channel and
//! replying in it, listing the account's chats and sending to one.

use ianua_domain::types::{ActionClass, DeclaredAction};
use ianua_integration::form::{Ask, PickerText};
use ianua_integration::rest::operation::{Field, Kind, Operation, Place, Segment, Shape, Verb};

use crate::operations::{CHANNEL, FORMAT, TEAM, TEXT};

/// The path of a channel's messages.
const MESSAGES: &[Segment] = &[
    Segment::Fixed("teams"),
    Segment::Input("team"),
    Segment::Fixed("channels"),
    Segment::Input("channel"),
    Segment::Fixed("messages"),
];

/// How many to list at most, up to Microsoft's 50.
const LIMIT: Field = Field::optional(
    "limit",
    Kind::Count,
    Place::Query,
    "How many to give at most, up to 50.",
)
.sent_as("$top")
.more_options();

/// The account's chats, picked by their topic.
const CHATS: PickerText = PickerText {
    filled_by: "list-chats",
    items_at: "json.value",
    value_at: "id",
    label_at: "topic",
    depends_on: None,
};

/// The outputs of a step answering with the message it sent.
const SENT: &[(&str, &str)] = &[
    ("json.id", "The message's id, which a reply to it names."),
    ("json.webUrl", "The address of the message in Teams."),
    ("json.createdDateTime", "When it was sent."),
];

/// Every message operation.
pub(crate) const OPERATIONS: &[Operation] = &[
    Operation {
        key: "list-channel-messages",
        title: "List channel messages",
        description: "Lists the latest messages posted in a channel, newest first, without their replies.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Get,
        path: MESSAGES,
        fields: &[TEAM, CHANNEL, LIMIT],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[(
            "json.value",
            "The messages, each with its id, from, body, createdDateTime and webUrl.",
        )],
    },
    Operation {
        key: "post-message",
        title: "Post a message",
        description: "Posts a message to a channel, as the account, for its members to see.",
        effect: DeclaredAction::Declared(ActionClass::Communicate),
        verb: Verb::Post,
        path: MESSAGES,
        fields: &[
            TEAM,
            CHANNEL,
            Field::optional(
                "subject",
                Kind::Text,
                Place::Body,
                "A subject shown above the message.",
            )
            .more_options(),
            TEXT,
            FORMAT,
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: SENT,
    },
    Operation {
        key: "reply-to-message",
        title: "Reply to a message",
        description: "Replies to a message in a channel, in its thread.",
        effect: DeclaredAction::Declared(ActionClass::Communicate),
        verb: Verb::Post,
        path: &[
            Segment::Fixed("teams"),
            Segment::Input("team"),
            Segment::Fixed("channels"),
            Segment::Input("channel"),
            Segment::Fixed("messages"),
            Segment::Input("message"),
            Segment::Fixed("replies"),
        ],
        fields: &[
            TEAM,
            CHANNEL,
            Field::required(
                "message",
                Kind::Text,
                Place::Path,
                "The id of the message replied to, such as an earlier step's json.id.",
            ),
            TEXT,
            FORMAT,
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: SENT,
    },
    Operation {
        key: "list-chats",
        title: "List my chats",
        description: "Lists the chats the account is in: one to one, group and meeting chats.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Get,
        path: &[Segment::Fixed("me"), Segment::Fixed("chats")],
        fields: &[LIMIT],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[(
            "json.value",
            "The chats, each with its id, topic, chatType and webUrl; a one to one chat has no topic.",
        )],
    },
    Operation {
        key: "send-chat-message",
        title: "Send a chat message",
        description: "Sends a message to a chat the account is in, as the account.",
        effect: DeclaredAction::Declared(ActionClass::Communicate),
        verb: Verb::Post,
        path: &[
            Segment::Fixed("chats"),
            Segment::Input("chat"),
            Segment::Fixed("messages"),
        ],
        fields: &[
            Field::required(
                "chat",
                Kind::Text,
                Place::Path,
                "The chat's id, such as 19:meeting_abc@thread.v2.",
            )
            .asked_with(Ask::Picker(CHATS)),
            TEXT,
            FORMAT,
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: SENT,
    },
];
