//! Customers: finding, reading, adding and changing them.

use ianua_domain::types::{ActionClass, DeclaredAction};
use ianua_integration::rest::operation::{Field, Kind, Operation, Place, Segment, Shape, Verb};

use crate::operations::{CUSTOMER, LIMIT};

/// The address of one customer.
const ONE: &[Segment] = &[Segment::Fixed("customers"), Segment::Input("customer")];

/// A customer's address, in the body.
const EMAIL: Field = Field::optional(
    "email",
    Kind::Text,
    Place::Body,
    "The customer's email address, which Stripe sends receipts and invoices to.",
);

/// A customer's full name, in the body.
const NAME: Field = Field::optional("name", Kind::Text, Place::Body, "The customer's full name.");

/// A note about the customer, in the body.
const DESCRIPTION: Field = Field::optional(
    "description",
    Kind::Text,
    Place::Body,
    "A note about the customer, shown in Stripe's dashboard.",
)
.more_options();

/// Every customer operation.
pub(crate) const OPERATIONS: &[Operation] = &[
    Operation {
        key: "list-customers",
        title: "List customers",
        description: "Lists customers, newest first, or those with one email address.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Get,
        path: &[Segment::Fixed("customers")],
        fields: &[
            Field::optional(
                "email",
                Kind::Text,
                Place::Query,
                "Only the customers with this email address.",
            ),
            LIMIT,
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Form,
        outputs: &[
            (
                "json.data",
                "The customers, each with its id, email and name.",
            ),
            ("json.has_more", "Whether there are more than were given."),
            ("status", "The status Stripe answered with."),
        ],
    },
    Operation {
        key: "get-customer",
        title: "Read a customer",
        description: "Reads a customer's email, name, balance and default currency.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Get,
        path: ONE,
        fields: &[CUSTOMER],
        fixed: &[],
        query: &[],
        shape: Shape::Form,
        outputs: &[
            ("json.id", "The customer's id."),
            ("json.email", "Their email address."),
            ("json.name", "Their name."),
            (
                "json.balance",
                "What they owe or are owed, in the smallest unit of the currency.",
            ),
            (
                "status",
                "The status Stripe answered with; 404 when there is no such customer.",
            ),
        ],
    },
    Operation {
        key: "create-customer",
        title: "Add a customer",
        description: "Adds a customer with an email address and name, charged nothing.",
        effect: DeclaredAction::Declared(ActionClass::Write),
        verb: Verb::Post,
        path: &[Segment::Fixed("customers")],
        fields: &[
            EMAIL,
            NAME,
            DESCRIPTION,
            Field::optional(
                "phone",
                Kind::Text,
                Place::Body,
                "The customer's phone number.",
            )
            .more_options(),
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Form,
        outputs: &[
            ("json.id", "The new customer's id, which later steps name."),
            ("status", "The status Stripe answered with."),
        ],
    },
    Operation {
        key: "update-customer",
        title: "Change a customer",
        description: "Changes a customer's email address, name or note, leaving the rest as it is.",
        effect: DeclaredAction::Declared(ActionClass::Write),
        verb: Verb::Post,
        path: ONE,
        fields: &[CUSTOMER, EMAIL, NAME, DESCRIPTION],
        fixed: &[],
        query: &[],
        shape: Shape::Form,
        outputs: &[
            ("json.email", "Their email address now."),
            ("status", "The status Stripe answered with."),
        ],
    },
];
