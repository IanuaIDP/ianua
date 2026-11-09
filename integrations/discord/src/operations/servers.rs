//! Servers: listing the bot's servers and a server's channels and roles,
//! and giving a member a role.

use ianua_domain::types::{ActionClass, DeclaredAction};
use ianua_integration::form::Ask;
use ianua_integration::rest::operation::{Field, Kind, Operation, Place, Segment, Shape, Verb};

use crate::operations::{ROLES, SERVER};

/// Every server operation.
pub(crate) const OPERATIONS: &[Operation] = &[
    Operation {
        key: "list-servers",
        title: "List servers",
        description: "Lists the Discord servers the bot is in, each with its id and name.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Get,
        path: &[
            Segment::Fixed("users"),
            Segment::Fixed("@me"),
            Segment::Fixed("guilds"),
        ],
        fields: &[Field::optional(
            "limit",
            Kind::Count,
            Place::Query,
            "How many to list, at most 200; 200 when not given.",
        )
        .more_options()],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            ("json", "The servers, each with its id and name."),
            ("status", "The status Discord answered with."),
        ],
    },
    Operation {
        key: "list-channels",
        title: "List channels",
        description: "Lists a server's channels and categories, each with its id, name and type.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Get,
        path: &[
            Segment::Fixed("guilds"),
            Segment::Input("server"),
            Segment::Fixed("channels"),
        ],
        fields: &[SERVER],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            (
                "json",
                "The server's channels, each with its id, name and type.",
            ),
            ("status", "The status Discord answered with."),
        ],
    },
    Operation {
        key: "list-roles",
        title: "List roles",
        description: "Lists a server's roles, each with its id, name and position.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Get,
        path: &[
            Segment::Fixed("guilds"),
            Segment::Input("server"),
            Segment::Fixed("roles"),
        ],
        fields: &[SERVER],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            ("json", "The server's roles, each with its id and name."),
            ("status", "The status Discord answered with."),
        ],
    },
    Operation {
        key: "add-role",
        title: "Give a member a role",
        description: "Gives a server member a role, and with it the role's permissions. The bot's own role must sit above it.",
        effect: DeclaredAction::Declared(ActionClass::Admin),
        verb: Verb::Put,
        path: &[
            Segment::Fixed("guilds"),
            Segment::Input("server"),
            Segment::Fixed("members"),
            Segment::Input("member"),
            Segment::Fixed("roles"),
            Segment::Input("role"),
        ],
        fields: &[
            SERVER,
            Field::required(
                "member",
                Kind::Text,
                Place::Path,
                "The member's user id, such as 1400000000000000004.",
            ),
            Field::required(
                "role",
                Kind::Text,
                Place::Path,
                "The role's id, such as one list-roles gives.",
            )
            .asked_with(Ask::Picker(ROLES)),
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[(
            "status",
            "The status Discord answered with, 204 when the member has the role.",
        )],
    },
];
