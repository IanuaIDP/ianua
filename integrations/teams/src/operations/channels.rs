//! Teams and channels: listing the teams the account joined, a team's
//! members and channels, and creating, archiving and deleting a channel.

use ianua_domain::types::{ActionClass, DeclaredAction};
use ianua_integration::rest::operation::{
    Field, Fixed, Kind, Operation, Place, Segment, Shape, Verb,
};

use crate::operations::{CHANNEL, CHANNELS_OF, ONE_CHANNEL, TEAM};

/// What a listing gives back: Microsoft's list under `value`.
const LISTED: &str = "json.value";

/// Every team and channel operation.
pub(crate) const OPERATIONS: &[Operation] = &[
    Operation {
        key: "list-teams",
        title: "List my teams",
        description: "Lists the teams the account is a member of.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Get,
        path: &[Segment::Fixed("me"), Segment::Fixed("joinedTeams")],
        fields: &[],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[(
            LISTED,
            "The teams, each with its id, displayName and description.",
        )],
    },
    Operation {
        key: "list-members",
        title: "List team members",
        description: "Lists the people in a team, with their roles in it.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Get,
        path: &[
            Segment::Fixed("teams"),
            Segment::Input("team"),
            Segment::Fixed("members"),
        ],
        fields: &[TEAM],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[(
            LISTED,
            "The members, each with its id, displayName, email, userId and roles.",
        )],
    },
    Operation {
        key: "list-channels",
        title: "List channels",
        description: "Lists the channels of a team the account can see.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Get,
        path: CHANNELS_OF,
        fields: &[TEAM],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[(
            LISTED,
            "The channels, each with its id, displayName, description and webUrl.",
        )],
    },
    Operation {
        key: "create-channel",
        title: "Create a channel",
        description: "Creates a standard channel in a team, open to every member.",
        effect: DeclaredAction::Declared(ActionClass::Configure),
        verb: Verb::Post,
        path: CHANNELS_OF,
        fields: &[
            TEAM,
            Field::required(
                "name",
                Kind::Text,
                Place::Body,
                "The channel's name, unique in the team.",
            )
            .sent_as("displayName")
            .example("Incident 42"),
            Field::optional(
                "description",
                Kind::Text,
                Place::Body,
                "What the channel is for.",
            ),
        ],
        fixed: &[("membershipType", Fixed::Text("standard"))],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            (
                "json.id",
                "The channel's id, which its messages' steps name.",
            ),
            ("json.webUrl", "The address of the channel in Teams."),
        ],
    },
    Operation {
        key: "archive-channel",
        title: "Archive a channel",
        description: "Archives a channel: it stays readable, and nobody can post in it until a team owner restores it.",
        effect: DeclaredAction::Declared(ActionClass::Configure),
        verb: Verb::Post,
        path: &[
            Segment::Fixed("teams"),
            Segment::Input("team"),
            Segment::Fixed("channels"),
            Segment::Input("channel"),
            Segment::Fixed("archive"),
        ],
        fields: &[
            TEAM,
            CHANNEL,
            Field::optional(
                "read_only_files",
                Kind::Flag,
                Place::Body,
                "Whether the channel's files become read-only for members too.",
            )
            .sent_as("shouldSetSpoSiteReadOnlyForMembers")
            .more_options(),
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[(
            "status",
            "The status Microsoft answered with, a success once it took the archiving, which finishes shortly after.",
        )],
    },
    Operation {
        key: "delete-channel",
        title: "Delete a channel",
        description: "Deletes a channel and its messages; a team owner may restore it within 30 days.",
        effect: DeclaredAction::Declared(ActionClass::Delete),
        verb: Verb::Delete,
        path: ONE_CHANNEL,
        fields: &[TEAM, CHANNEL],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[(
            "status",
            "The status Microsoft answered with, 204 when it was deleted.",
        )],
    },
];
