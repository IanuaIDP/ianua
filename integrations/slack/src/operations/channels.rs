//! Channels: listing them and reading one's recent messages, creating one,
//! inviting people, setting its topic, archiving it, and opening a direct
//! message.

use ianua_domain::types::{ActionClass, DeclaredAction};
use ianua_integration::form::Ask;
use ianua_integration::rest::operation::{Field, Kind, Operation, Place, Segment, Shape, Verb};

use crate::operations::{CHANNEL, CHANNELS};

/// Members named by their user ids, as Slack takes them.
const USERS: Field = Field::required(
    "users",
    Kind::Text,
    Place::Body,
    "The members' user ids, separated by commas, such as U0123,U0456.",
);

/// Every channel operation.
pub(crate) const OPERATIONS: &[Operation] = &[
    Operation {
        key: "list-channels",
        title: "List channels",
        description: "Lists the workspace's channels the bot can see.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Get,
        path: &[Segment::Fixed("conversations.list")],
        fields: &[
            Field::optional(
                "types",
                Kind::Text,
                Place::Query,
                "Which kinds, separated by commas: public_channel, private_channel, mpim, im; public channels when not given.",
            ),
            Field::optional(
                "exclude_archived",
                Kind::Flag,
                Place::Query,
                "Whether to leave archived channels out.",
            ),
            Field::optional(
                "limit",
                Kind::Count,
                Place::Query,
                "How many to list, at most 1000; 100 when not given.",
            ),
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[(
            "json.channels",
            "The channels, each with its id, name and topic.",
        )],
    },
    Operation {
        key: "get-channel-history",
        title: "Read recent messages",
        description: "Reads a channel's most recent messages, newest first.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Get,
        path: &[Segment::Fixed("conversations.history")],
        fields: &[
            Field::required(
                "channel",
                Kind::Text,
                Place::Query,
                "The channel's id, such as C0123ABC.",
            )
            .asked_with(Ask::Picker(CHANNELS)),
            Field::optional(
                "limit",
                Kind::Count,
                Place::Query,
                "How many messages, at most 999; 100 when not given.",
            ),
            Field::optional(
                "oldest",
                Kind::Text,
                Place::Query,
                "Only messages after this message id or time in seconds.",
            ),
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[(
            "json.messages",
            "The messages, each with its text, author and id.",
        )],
    },
    Operation {
        key: "create-channel",
        title: "Create a channel",
        description: "Creates a channel, public unless the step says private.",
        effect: DeclaredAction::Declared(ActionClass::Write),
        verb: Verb::Post,
        path: &[Segment::Fixed("conversations.create")],
        fields: &[
            Field::required(
                "name",
                Kind::Text,
                Place::Body,
                "The channel's name: lowercase letters, digits, dashes and underscores, at most 80.",
            ),
            Field::optional(
                "private",
                Kind::Flag,
                Place::Body,
                "Whether only invited members may see it.",
            )
            .sent_as("is_private"),
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[(
            "json.channel.id",
            "The new channel's id, which inviting and posting name.",
        )],
    },
    Operation {
        key: "invite-to-channel",
        title: "Invite people to a channel",
        description: "Invites workspace members to a channel the bot is in.",
        effect: DeclaredAction::Declared(ActionClass::Write),
        verb: Verb::Post,
        path: &[Segment::Fixed("conversations.invite")],
        fields: &[CHANNEL, USERS],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[("json.channel.id", "The channel they were invited to.")],
    },
    Operation {
        key: "set-channel-topic",
        title: "Set a channel's topic",
        description: "Sets the topic shown at the top of a channel.",
        effect: DeclaredAction::Declared(ActionClass::Write),
        verb: Verb::Post,
        path: &[Segment::Fixed("conversations.setTopic")],
        fields: &[
            CHANNEL,
            Field::required(
                "topic",
                Kind::Text,
                Place::Body,
                "The topic, at most 250 characters.",
            ),
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[("json.channel.topic", "The channel's topic as set.")],
    },
    Operation {
        key: "archive-channel",
        title: "Archive a channel",
        description: "Archives a channel: nobody can post in it any more until it is restored, so it counts as changing the workspace.",
        effect: DeclaredAction::Declared(ActionClass::Configure),
        verb: Verb::Post,
        path: &[Segment::Fixed("conversations.archive")],
        fields: &[CHANNEL],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[("json.ok", "Whether the channel was archived.")],
    },
    Operation {
        key: "open-direct-message",
        title: "Open a direct message",
        description: "Opens a direct message with one member, or a group message with several, for posting to.",
        effect: DeclaredAction::Declared(ActionClass::Write),
        verb: Verb::Post,
        path: &[Segment::Fixed("conversations.open")],
        fields: &[USERS],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[(
            "json.channel.id",
            "The conversation's id, which posting names as its channel.",
        )],
    },
];
