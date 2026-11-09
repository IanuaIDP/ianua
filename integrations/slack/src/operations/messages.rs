//! Messages: posting one, as a reply in a thread or for one person only,
//! scheduling one, editing and deleting one, linking to one, and reacting.

use ianua_domain::types::{ActionClass, DeclaredAction};
use ianua_integration::form::Ask;
use ianua_integration::rest::operation::{Field, Kind, Operation, Place, Segment, Shape, Verb};

use crate::operations::{CHANNEL, CHANNELS, MESSAGE};

/// The text a message says.
const TEXT: Field = Field::required("text", Kind::Text, Place::Body, "What the message says.")
    .asked_with(Ask::LongText);

/// The thread a message replies in.
const THREAD: Field = Field::optional(
    "thread",
    Kind::Text,
    Place::Body,
    "The id of the message to reply to, such as an earlier step's json.ts.",
)
.sent_as("thread_ts");

/// Slack's layout blocks for the message, such as buttons; the text is
/// still what notifications and screen readers show.
const BLOCKS: Field = Field::optional(
    "blocks",
    Kind::Values,
    Place::Body,
    "Layout blocks, such as a section and link buttons, as Slack's Block Kit describes them.",
);

/// Every message operation.
pub(crate) const OPERATIONS: &[Operation] = &[
    Operation {
        key: "post-message",
        title: "Post a message",
        description: "Posts a message to a channel the bot is in, or as a reply in a thread.",
        effect: DeclaredAction::Declared(ActionClass::Communicate),
        verb: Verb::Post,
        path: &[Segment::Fixed("chat.postMessage")],
        fields: &[CHANNEL, TEXT, THREAD, BLOCKS],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            (
                "json.ts",
                "The message's id, which a reply names as its thread.",
            ),
            ("json.channel", "The channel the message was posted in."),
        ],
    },
    Operation {
        key: "post-ephemeral",
        title: "Post a message only one person sees",
        description: "Posts a message in a channel that only one of its members sees, and only while they are looking.",
        effect: DeclaredAction::Declared(ActionClass::Communicate),
        verb: Verb::Post,
        path: &[Segment::Fixed("chat.postEphemeral")],
        fields: &[
            CHANNEL,
            Field::required(
                "user",
                Kind::Text,
                Place::Body,
                "The member who sees it, by their user id.",
            ),
            TEXT,
            THREAD,
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[("json.message_ts", "The message's id.")],
    },
    Operation {
        key: "schedule-message",
        title: "Schedule a message",
        description: "Schedules a message to be posted to a channel later.",
        effect: DeclaredAction::Declared(ActionClass::Communicate),
        verb: Verb::Post,
        path: &[Segment::Fixed("chat.scheduleMessage")],
        fields: &[
            CHANNEL,
            TEXT,
            Field::required(
                "post_at",
                Kind::Count,
                Place::Body,
                "When to post it, in seconds since 1970, at most 120 days ahead.",
            ),
            THREAD,
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            ("json.scheduled_message_id", "The scheduled message's id."),
            (
                "json.post_at",
                "When it will be posted, in seconds since 1970.",
            ),
        ],
    },
    Operation {
        key: "update-message",
        title: "Edit a message",
        description: "Changes what a message the bot posted says.",
        effect: DeclaredAction::Declared(ActionClass::Write),
        verb: Verb::Post,
        path: &[Segment::Fixed("chat.update")],
        fields: &[
            CHANNEL,
            MESSAGE.sent_as("ts"),
            Field::required(
                "text",
                Kind::Text,
                Place::Body,
                "What the message says from now on.",
            ),
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[("json.ts", "The message's id.")],
    },
    Operation {
        key: "delete-message",
        title: "Delete a message",
        description: "Deletes a message the bot posted, for good.",
        effect: DeclaredAction::Declared(ActionClass::Delete),
        verb: Verb::Post,
        path: &[Segment::Fixed("chat.delete")],
        fields: &[CHANNEL, MESSAGE.sent_as("ts")],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[("json.ts", "The deleted message's id.")],
    },
    Operation {
        key: "get-permalink",
        title: "Get a link to a message",
        description: "Gives the lasting address of a message, to share or post elsewhere.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Get,
        path: &[Segment::Fixed("chat.getPermalink")],
        fields: &[
            Field::required(
                "channel",
                Kind::Text,
                Place::Query,
                "The channel's id, such as C0123ABC.",
            )
            .asked_with(Ask::Picker(CHANNELS)),
            Field::required(
                "message",
                Kind::Text,
                Place::Query,
                "The message's id, such as an earlier step's json.ts.",
            )
            .sent_as("message_ts"),
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[("json.permalink", "The message's lasting address.")],
    },
    Operation {
        key: "add-reaction",
        title: "React to a message",
        description: "Adds an emoji reaction to a message, as the bot.",
        effect: DeclaredAction::Declared(ActionClass::Communicate),
        verb: Verb::Post,
        path: &[Segment::Fixed("reactions.add")],
        fields: &[
            CHANNEL,
            MESSAGE.sent_as("timestamp"),
            Field::required(
                "emoji",
                Kind::Text,
                Place::Body,
                "The emoji's name without colons, such as white_check_mark.",
            )
            .sent_as("name"),
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[("json.ok", "Whether the reaction was added.")],
    },
];
