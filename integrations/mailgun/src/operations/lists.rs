//! Mailing lists: adding, changing, removing and listing a list's members.

use ianua_domain::types::{ActionClass, DeclaredAction};
use ianua_integration::rest::operation::{Field, Kind, Operation, Place, Segment, Shape, Verb};

/// The list a step acts on, in the path.
const LIST: Field = Field::required(
    "list",
    Kind::Text,
    Place::Path,
    "The list's address, such as team@mail.acme.test.",
);

/// The member a step acts on, in the path.
const MEMBER: Field = Field::required(
    "member",
    Kind::Text,
    Place::Path,
    "The member's email address.",
);

/// A member's name.
const NAME: Field = Field::optional("name", Kind::Text, Place::Body, "The member's name.");

/// Values kept with a member.
const VALUES: Field = Field::optional(
    "values",
    Kind::Values,
    Place::Body,
    "Values kept with the member, which templates can fill in.",
)
.sent_as("vars");

/// Whether a member is subscribed.
const SUBSCRIBED: Field = Field::optional(
    "subscribed",
    Kind::Flag,
    Place::Body,
    "Whether the member gets the list's mail; yes when not given.",
);

/// The path of a list's members.
const MEMBERS: &[Segment] = &[
    Segment::Fixed("v3"),
    Segment::Fixed("lists"),
    Segment::Input("list"),
    Segment::Fixed("members"),
];

/// The path of one member.
const ONE: &[Segment] = &[
    Segment::Fixed("v3"),
    Segment::Fixed("lists"),
    Segment::Input("list"),
    Segment::Fixed("members"),
    Segment::Input("member"),
];

/// Every mailing list operation.
pub(crate) const OPERATIONS: &[Operation] = &[
    Operation {
        key: "add-list-member",
        title: "Add a list member",
        description: "Adds an address to a mailing list, or updates it when asked and it is there already.",
        effect: DeclaredAction::Declared(ActionClass::Write),
        verb: Verb::Post,
        path: MEMBERS,
        fields: &[
            LIST,
            Field::required(
                "address",
                Kind::Text,
                Place::Body,
                "The member's email address.",
            ),
            NAME,
            VALUES,
            SUBSCRIBED,
            Field::optional(
                "update",
                Kind::Flag,
                Place::Body,
                "Whether to update the member when it is there already, rather than fail.",
            )
            .sent_as("upsert"),
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Form,
        outputs: &[
            (
                "json.member",
                "The member as kept: address, name, values and subscribed.",
            ),
            ("json.message", "Mailgun's word that it was added."),
        ],
    },
    Operation {
        key: "update-list-member",
        title: "Update a list member",
        description: "Changes a member's name, values or subscription.",
        effect: DeclaredAction::Declared(ActionClass::Write),
        verb: Verb::Put,
        path: ONE,
        fields: &[LIST, MEMBER, NAME, VALUES, SUBSCRIBED],
        fixed: &[],
        query: &[],
        shape: Shape::Form,
        outputs: &[
            (
                "json.member",
                "The member as kept: address, name, values and subscribed.",
            ),
            ("json.message", "Mailgun's word that it was updated."),
        ],
    },
    Operation {
        key: "remove-list-member",
        title: "Remove a list member",
        description: "Removes an address from a mailing list for good.",
        effect: DeclaredAction::Declared(ActionClass::Delete),
        verb: Verb::Delete,
        path: ONE,
        fields: &[LIST, MEMBER],
        fixed: &[],
        query: &[],
        shape: Shape::Form,
        outputs: &[("json.member", "The member that was removed.")],
    },
    Operation {
        key: "list-list-members",
        title: "List a list's members",
        description: "Lists a mailing list's members, subscribed or not.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Get,
        path: MEMBERS,
        fields: &[
            LIST,
            Field::optional(
                "subscribed",
                Kind::Flag,
                Place::Query,
                "Only members who are, or are not, subscribed.",
            ),
            Field::optional(
                "most",
                Kind::Count,
                Place::Query,
                "How many to give at most, up to 100.",
            )
            .sent_as("limit"),
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Form,
        outputs: &[
            (
                "json.items",
                "The members, each with its address, name, values and subscribed.",
            ),
            ("json.total_count", "How many members the list has."),
        ],
    },
];
