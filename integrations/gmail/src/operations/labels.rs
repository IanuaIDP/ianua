//! Labels: listing the mailbox's labels, which the forms' pickers offer,
//! and making a new one.

use ianua_domain::types::{ActionClass, DeclaredAction};
use ianua_integration::rest::operation::{Field, Kind, Operation, Place, Segment, Shape, Verb};

/// Every label operation.
pub(crate) const OPERATIONS: &[Operation] = &[
    Operation {
        key: "list-labels",
        title: "List labels",
        description: "Lists the mailbox's labels: Gmail's own, such as INBOX and UNREAD, and the account's.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Get,
        path: &[
            Segment::Fixed("users"),
            Segment::Fixed("me"),
            Segment::Fixed("labels"),
        ],
        fields: &[],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            (
                "json.labels",
                "The labels, each with its id, name and type, system or user.",
            ),
            ("status", "The status Gmail answered with."),
        ],
    },
    Operation {
        key: "create-label",
        title: "Make a label",
        description: "Makes a new label of the account's own, shown in the label list and on messages.",
        effect: DeclaredAction::Declared(ActionClass::Write),
        verb: Verb::Post,
        path: &[
            Segment::Fixed("users"),
            Segment::Fixed("me"),
            Segment::Fixed("labels"),
        ],
        fields: &[Field::required(
            "name",
            Kind::Text,
            Place::Body,
            "The label's name, such as Invoices or Clients/Acme for one inside another.",
        )],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            ("json.id", "The new label's id, which later steps add by."),
            ("json.name", "Its name."),
            (
                "status",
                "The status Gmail answered with; 409 when a label of that name exists.",
            ),
        ],
    },
];
