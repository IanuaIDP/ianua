//! People: finding a member by their address, and reading one.

use ianua_domain::types::{ActionClass, DeclaredAction};
use ianua_integration::rest::operation::{Field, Kind, Operation, Place, Segment, Shape, Verb};

/// What reading a member gives back.
const MEMBER_OUTPUTS: &[(&str, &str)] = &[
    (
        "json.user.id",
        "The member's user id, which posting and inviting name.",
    ),
    ("json.user.real_name", "The member's full name."),
    (
        "json.user.tz",
        "The member's time zone, such as Europe/Berlin.",
    ),
];

/// Every people operation.
pub(crate) const OPERATIONS: &[Operation] = &[
    Operation {
        key: "find-user-by-email",
        title: "Find a member by email",
        description: "Finds the workspace member with an email address, for a later step to message or invite.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Get,
        path: &[Segment::Fixed("users.lookupByEmail")],
        fields: &[Field::required(
            "email",
            Kind::Text,
            Place::Query,
            "The member's email address.",
        )],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: MEMBER_OUTPUTS,
    },
    Operation {
        key: "get-user",
        title: "Get a member",
        description: "Reads a workspace member: their name, title and time zone.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Get,
        path: &[Segment::Fixed("users.info")],
        fields: &[Field::required(
            "user",
            Kind::Text,
            Place::Query,
            "The member's user id, such as U0123ABC.",
        )],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: MEMBER_OUTPUTS,
    },
];
