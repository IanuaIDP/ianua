//! Suppressions: the addresses a domain no longer mails, because mail to
//! them bounced or they unsubscribed. Reading, adding and lifting them.

use ianua_domain::types::{ActionClass, DeclaredAction};
use ianua_integration::rest::operation::{Field, Kind, Operation, Place, Segment, Shape, Verb};

use crate::operations::DOMAIN;

/// The address a suppression is for, in the path.
const ADDRESS: Field = Field::required(
    "address",
    Kind::Text,
    Place::Path,
    "The email address, such as ann@acme.test.",
);

/// The path of one bounced address.
const BOUNCE: &[Segment] = &[
    Segment::Fixed("v3"),
    Segment::Input("domain"),
    Segment::Fixed("bounces"),
    Segment::Input("address"),
];

/// Every suppression operation.
pub(crate) const OPERATIONS: &[Operation] = &[
    Operation {
        key: "get-bounce",
        title: "Get a bounced address",
        description: "Reads why mail to an address bounced, when the domain no longer mails it for that reason.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Get,
        path: BOUNCE,
        fields: &[DOMAIN, ADDRESS],
        fixed: &[],
        query: &[],
        shape: Shape::Form,
        outputs: &[
            (
                "json.code",
                "The code the receiving server answered with, such as 550.",
            ),
            ("json.error", "What the receiving server said."),
            ("json.created_at", "When it bounced."),
        ],
    },
    Operation {
        key: "remove-bounce",
        title: "Remove a bounced address",
        description: "Lifts a bounce, so the domain mails the address again. The record of the bounce is gone for good.",
        effect: DeclaredAction::Declared(ActionClass::Delete),
        verb: Verb::Delete,
        path: BOUNCE,
        fields: &[DOMAIN, ADDRESS],
        fixed: &[],
        query: &[],
        shape: Shape::Form,
        outputs: &[(
            "json.message",
            "Mailgun's word that the bounce was removed.",
        )],
    },
    Operation {
        key: "add-unsubscribe",
        title: "Unsubscribe an address",
        description: "Stops the domain mailing an address, from mail with one tag or from all of it.",
        effect: DeclaredAction::Declared(ActionClass::Write),
        verb: Verb::Post,
        path: &[
            Segment::Fixed("v3"),
            Segment::Input("domain"),
            Segment::Fixed("unsubscribes"),
        ],
        fields: &[
            DOMAIN,
            Field::required(
                "address",
                Kind::Text,
                Place::Body,
                "The email address, such as ann@acme.test.",
            ),
            Field::optional(
                "tag",
                Kind::Text,
                Place::Body,
                "Only mail with this tag; all mail when not given.",
            )
            .sent_as("tags"),
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Form,
        outputs: &[(
            "json.message",
            "Mailgun's word that the address was unsubscribed.",
        )],
    },
    Operation {
        key: "remove-unsubscribe",
        title: "Resubscribe an address",
        description: "Lifts an unsubscribe, so the domain mails the address again. The record of the unsubscribe is gone for good.",
        effect: DeclaredAction::Declared(ActionClass::Delete),
        verb: Verb::Delete,
        path: &[
            Segment::Fixed("v3"),
            Segment::Input("domain"),
            Segment::Fixed("unsubscribes"),
            Segment::Input("address"),
        ],
        fields: &[DOMAIN, ADDRESS],
        fixed: &[],
        query: &[],
        shape: Shape::Form,
        outputs: &[(
            "json.message",
            "Mailgun's word that the unsubscribe was removed.",
        )],
    },
];
