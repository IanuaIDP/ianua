//! Messages: sending a text now or later, cancelling one not yet sent,
//! reading, listing and deleting them.

use ianua_domain::types::{ActionClass, DeclaredAction};
use ianua_integration::form::Ask;
use ianua_integration::rest::operation::{
    Field, Fixed, Kind, Operation, Place, Segment, Shape, Verb,
};

use crate::operations::MOST;

/// The number a message goes to.
const TO: Field = Field::required(
    "to",
    Kind::Text,
    Place::Body,
    "The number to send to, such as +15551234567, or whatsapp:+15551234567.",
)
.sent_as("To");

/// What a message says.
const BODY: Field = Field::optional(
    "body",
    Kind::Text,
    Place::Body,
    "What the message says, up to 1,600 characters.",
)
.sent_as("Body")
.asked_with(Ask::LongText);

/// Pictures or files sent with a message.
const MEDIA: Field = Field::optional(
    "media",
    Kind::TextList,
    Place::Body,
    "Addresses of pictures or files to send with it, which Twilio fetches.",
)
.sent_as("MediaUrl");

/// The message a step acts on, in the path.
const MESSAGE: Field = Field::required(
    "message",
    Kind::Text,
    Place::Path,
    "The message's SID, such as an earlier step's json.sid.",
);

/// The path of one message.
const ONE: &[Segment] = &[
    Segment::Fixed("Messages"),
    Segment::Suffixed {
        input: "message",
        suffix: ".json",
    },
];

/// The path of every message.
const ALL: &[Segment] = &[Segment::Fixed("Messages.json")];

/// Every message operation.
pub(crate) const OPERATIONS: &[Operation] = &[
    Operation {
        key: "send-message",
        title: "Send a text message",
        description: "Sends a text, picture or WhatsApp message from one of the account's numbers or a messaging service.",
        effect: DeclaredAction::Declared(ActionClass::Communicate),
        verb: Verb::Post,
        path: ALL,
        fields: &[
            TO,
            Field::optional(
                "from",
                Kind::Text,
                Place::Body,
                "The account's number to send from; give this or a messaging service.",
            )
            .sent_as("From"),
            Field::optional(
                "messaging_service",
                Kind::Text,
                Place::Body,
                "The SID of a messaging service to send through, which picks the number.",
            )
            .sent_as("MessagingServiceSid"),
            BODY,
            MEDIA,
            Field::optional(
                "template",
                Kind::Text,
                Place::Body,
                "The SID of a content template to send in place of a body.",
            )
            .sent_as("ContentSid"),
            Field::optional(
                "template_values",
                Kind::Values,
                Place::Body,
                "The values filling the template's placeholders, such as {\"1\": \"Ann\"}.",
            )
            .sent_as("ContentVariables"),
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Form,
        outputs: &[
            (
                "json.sid",
                "The message's SID, which reading or cancelling it names.",
            ),
            ("json.status", "Where the message is, such as queued."),
            (
                "status",
                "The status Twilio answered with, 201 when it took the message.",
            ),
        ],
    },
    Operation {
        key: "schedule-message",
        title: "Schedule a text message",
        description: "Sends a text message through a messaging service at a set time, between 15 minutes and 35 days ahead.",
        effect: DeclaredAction::Declared(ActionClass::Communicate),
        verb: Verb::Post,
        path: ALL,
        fields: &[
            TO,
            Field::required(
                "messaging_service",
                Kind::Text,
                Place::Body,
                "The SID of the messaging service to send through.",
            )
            .sent_as("MessagingServiceSid"),
            Field::required(
                "send_at",
                Kind::Text,
                Place::Body,
                "When to send it, such as 2026-11-03T09:00:00Z.",
            )
            .sent_as("SendAt"),
            BODY,
            MEDIA,
        ],
        fixed: &[("ScheduleType", Fixed::Text("fixed"))],
        query: &[],
        shape: Shape::Form,
        outputs: &[
            ("json.sid", "The message's SID, which cancelling it names."),
            ("json.status", "Where the message is: scheduled."),
            (
                "status",
                "The status Twilio answered with, 201 when it was scheduled.",
            ),
        ],
    },
    Operation {
        key: "cancel-message",
        title: "Cancel a scheduled message",
        description: "Stops a scheduled message from being sent.",
        effect: DeclaredAction::Declared(ActionClass::Write),
        verb: Verb::Post,
        path: ONE,
        fields: &[MESSAGE],
        fixed: &[("Status", Fixed::Text("canceled"))],
        query: &[],
        shape: Shape::Form,
        outputs: &[
            ("json.status", "Where the message is: canceled."),
            (
                "status",
                "The status Twilio answered with, 200 when it was cancelled.",
            ),
        ],
    },
    Operation {
        key: "get-message",
        title: "Get a message",
        description: "Reads a message: where it is, what it said and why it failed if it did.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Get,
        path: ONE,
        fields: &[MESSAGE],
        fixed: &[],
        query: &[],
        shape: Shape::Form,
        outputs: &[
            (
                "json.status",
                "Where the message is, such as delivered or failed.",
            ),
            (
                "json.error_code",
                "Twilio's code for why it failed, when it did.",
            ),
            ("json.body", "What the message said."),
            ("json.date_sent", "When it was sent."),
        ],
    },
    Operation {
        key: "list-messages",
        title: "List messages",
        description: "Lists the account's messages, newest first, to or from a number or sent on a day.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Get,
        path: ALL,
        fields: &[
            Field::optional(
                "to",
                Kind::Text,
                Place::Query,
                "Only messages to this number.",
            )
            .sent_as("To"),
            Field::optional(
                "from",
                Kind::Text,
                Place::Query,
                "Only messages from this number.",
            )
            .sent_as("From"),
            Field::optional(
                "sent_on",
                Kind::Text,
                Place::Query,
                "Only messages sent on this day, such as 2026-11-02.",
            )
            .sent_as("DateSent"),
            MOST,
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Form,
        outputs: &[
            (
                "json.messages",
                "The messages, each with its sid, to, from, body and status.",
            ),
            (
                "json.next_page_uri",
                "Where the next page is, when there is one.",
            ),
        ],
    },
    Operation {
        key: "delete-message",
        title: "Delete a message",
        description: "Deletes a message's record from the account for good.",
        effect: DeclaredAction::Declared(ActionClass::Delete),
        verb: Verb::Delete,
        path: ONE,
        fields: &[MESSAGE],
        fixed: &[],
        query: &[],
        shape: Shape::Form,
        outputs: &[(
            "status",
            "The status Twilio answered with, 204 when it was deleted.",
        )],
    },
];
