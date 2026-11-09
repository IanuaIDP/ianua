//! Messages: posting one, as a reply or not, editing and deleting one,
//! reacting to one, starting a thread from one, and reading a channel's
//! recent messages.

use ianua_domain::types::{ActionClass, DeclaredAction};
use ianua_integration::form::Ask;
use ianua_integration::rest::operation::{
    Field, Fixed, Kind, Operation, Place, Segment, Shape, Verb,
};

use crate::operations::{CHANNEL, CHANNEL_SERVER, MESSAGE};

/// The path of a channel's messages.
const MESSAGES: &[Segment] = &[
    Segment::Fixed("channels"),
    Segment::Input("channel"),
    Segment::Fixed("messages"),
];

/// The path of one message.
const ONE_MESSAGE: &[Segment] = &[
    Segment::Fixed("channels"),
    Segment::Input("channel"),
    Segment::Fixed("messages"),
    Segment::Input("message"),
];

/// What posting or editing a message gives back.
const MESSAGE_OUTPUTS: &[(&str, &str)] = &[
    (
        "json.id",
        "The message's id, which an edit, a reaction or a thread names.",
    ),
    ("json.channel_id", "The channel the message is in."),
    ("json.content", "What the message says."),
    (
        "status",
        "The status Discord answered with, 200 when it was done.",
    ),
];

/// Every message operation.
pub(crate) const OPERATIONS: &[Operation] = &[
    Operation {
        key: "post-message",
        title: "Post a message",
        description: "Posts a message to a channel the bot may write in, or as a reply to one of its messages.",
        effect: DeclaredAction::Declared(ActionClass::Communicate),
        verb: Verb::Post,
        path: MESSAGES,
        fields: &[
            CHANNEL_SERVER,
            CHANNEL,
            Field::required(
                "content",
                Kind::Text,
                Place::Body,
                "What the message says, at most 2,000 characters.",
            )
            .asked_with(Ask::LongText),
            Field::optional(
                "reply_to",
                Kind::Text,
                Place::Body,
                "The id of a message in the same channel to reply to, such as an earlier step's json.id.",
            )
            .sent_as("message_reference.message_id")
            .more_options(),
            Field::optional(
                "mentions",
                Kind::TextList,
                Place::Body,
                "Which mentions in the text ping people: users, roles or everyone. When not given, no one is pinged.",
            )
            .sent_as("allowed_mentions.parse")
            .more_options(),
        ],
        fixed: &[("allowed_mentions.parse", Fixed::NoItems)],
        query: &[],
        shape: Shape::Object,
        outputs: MESSAGE_OUTPUTS,
    },
    Operation {
        key: "edit-message",
        title: "Edit a message",
        description: "Changes what a message the bot posted says.",
        effect: DeclaredAction::Declared(ActionClass::Write),
        verb: Verb::Patch,
        path: ONE_MESSAGE,
        fields: &[
            CHANNEL_SERVER,
            CHANNEL,
            MESSAGE,
            Field::required(
                "content",
                Kind::Text,
                Place::Body,
                "What the message says from now on, at most 2,000 characters.",
            )
            .asked_with(Ask::LongText),
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: MESSAGE_OUTPUTS,
    },
    Operation {
        key: "delete-message",
        title: "Delete a message",
        description: "Deletes a message for good: the bot's own, or anyone's where the bot may manage messages.",
        effect: DeclaredAction::Declared(ActionClass::Delete),
        verb: Verb::Delete,
        path: ONE_MESSAGE,
        fields: &[CHANNEL_SERVER, CHANNEL, MESSAGE],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[(
            "status",
            "The status Discord answered with, 204 when it was deleted.",
        )],
    },
    Operation {
        key: "add-reaction",
        title: "React to a message",
        description: "Adds the bot's reaction to a message, with an emoji such as a thumbs up or one of the server's own.",
        effect: DeclaredAction::Declared(ActionClass::Write),
        verb: Verb::Put,
        path: &[
            Segment::Fixed("channels"),
            Segment::Input("channel"),
            Segment::Fixed("messages"),
            Segment::Input("message"),
            Segment::Fixed("reactions"),
            Segment::Input("emoji"),
            Segment::Fixed("@me"),
        ],
        fields: &[
            CHANNEL_SERVER,
            CHANNEL,
            MESSAGE,
            Field::required(
                "emoji",
                Kind::Text,
                Place::Path,
                "The emoji itself, such as a thumbs up, or a server's own as name:id.",
            )
            .example("shipit:1300000000000000003"),
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[(
            "status",
            "The status Discord answered with, 204 when the reaction was added.",
        )],
    },
    Operation {
        key: "start-thread",
        title: "Start a thread from a message",
        description: "Starts a thread from a message, named as the step says, for replies to gather in.",
        effect: DeclaredAction::Declared(ActionClass::Write),
        verb: Verb::Post,
        path: &[
            Segment::Fixed("channels"),
            Segment::Input("channel"),
            Segment::Fixed("messages"),
            Segment::Input("message"),
            Segment::Fixed("threads"),
        ],
        fields: &[
            CHANNEL_SERVER,
            CHANNEL,
            MESSAGE,
            Field::required(
                "name",
                Kind::Text,
                Place::Body,
                "The thread's name, at most 100 characters.",
            )
            .example("Nightly build"),
            Field::optional(
                "archive_after",
                Kind::Count,
                Place::Body,
                "Minutes without a message before the thread is hidden: 60, 1440, 4320 or 10080.",
            )
            .sent_as("auto_archive_duration")
            .more_options(),
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            (
                "json.id",
                "The thread's id, which is also a channel a message may be posted to.",
            ),
            ("json.name", "The thread's name."),
            (
                "status",
                "The status Discord answered with, 201 when it was started.",
            ),
        ],
    },
    Operation {
        key: "list-messages",
        title: "Get recent messages",
        description: "Reads a channel's most recent messages, newest first.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Get,
        path: MESSAGES,
        fields: &[
            CHANNEL_SERVER,
            CHANNEL,
            Field::optional(
                "limit",
                Kind::Count,
                Place::Query,
                "How many to read, at most 100; 50 when not given.",
            ),
            Field::optional(
                "before",
                Kind::Text,
                Place::Query,
                "Only messages older than the message with this id.",
            )
            .more_options(),
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            (
                "json",
                "The messages, each with its id, author, text and time.",
            ),
            ("status", "The status Discord answered with."),
        ],
    },
];
