//! Calls and numbers: starting a call that speaks or plays what it is told,
//! ending, reading and listing calls, and listing the account's numbers.

use ianua_domain::types::{ActionClass, DeclaredAction};
use ianua_integration::rest::operation::{
    Field, Fixed, Kind, Operation, Place, Segment, Shape, Verb,
};

use crate::operations::MOST;

/// The call a step acts on, in the path.
const CALL: Field = Field::required(
    "call",
    Kind::Text,
    Place::Path,
    "The call's SID, such as an earlier step's json.sid.",
);

/// The path of one call.
const ONE: &[Segment] = &[
    Segment::Fixed("Calls"),
    Segment::Suffixed {
        input: "call",
        suffix: ".json",
    },
];

/// Every call and number operation.
pub(crate) const OPERATIONS: &[Operation] = &[
    Operation {
        key: "start-call",
        title: "Start a phone call",
        description: "Calls a number from one of the account's numbers and does what the TwiML says, such as <Response><Say>The build failed</Say></Response>. TwiML can also record, forward or fetch further instructions, so the call counts as an undeclared action and waits for an approval.",
        effect: DeclaredAction::Undeclared,
        verb: Verb::Post,
        path: &[Segment::Fixed("Calls.json")],
        fields: &[
            Field::required(
                "to",
                Kind::Text,
                Place::Body,
                "The number to call, such as +15551234567.",
            )
            .sent_as("To"),
            Field::required(
                "from",
                Kind::Text,
                Place::Body,
                "The account's number to call from.",
            )
            .sent_as("From"),
            Field::required(
                "twiml",
                Kind::Text,
                Place::Body,
                "What the call does, as TwiML.",
            )
            .sent_as("Twiml"),
            Field::optional(
                "time_limit",
                Kind::Count,
                Place::Body,
                "The most seconds the call may last.",
            )
            .sent_as("TimeLimit"),
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Form,
        outputs: &[
            (
                "json.sid",
                "The call's SID, which reading or ending it names.",
            ),
            ("json.status", "Where the call is, such as queued."),
            (
                "status",
                "The status Twilio answered with, 201 when it placed the call.",
            ),
        ],
    },
    Operation {
        key: "end-call",
        title: "End a phone call",
        description: "Hangs up a call that is ringing or under way.",
        effect: DeclaredAction::Declared(ActionClass::Write),
        verb: Verb::Post,
        path: ONE,
        fields: &[CALL],
        fixed: &[("Status", Fixed::Text("completed"))],
        query: &[],
        shape: Shape::Form,
        outputs: &[
            ("json.status", "Where the call is: completed."),
            (
                "status",
                "The status Twilio answered with, 200 when it was ended.",
            ),
        ],
    },
    Operation {
        key: "get-call",
        title: "Get a phone call",
        description: "Reads a call: where it is, who answered and how long it lasted.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Get,
        path: ONE,
        fields: &[CALL],
        fixed: &[],
        query: &[],
        shape: Shape::Form,
        outputs: &[
            (
                "json.status",
                "Where the call is, such as in-progress, completed or no-answer.",
            ),
            (
                "json.duration",
                "How many seconds it lasted, once it ended.",
            ),
            (
                "json.answered_by",
                "Who answered, such as human or machine, when asked to find out.",
            ),
        ],
    },
    Operation {
        key: "list-calls",
        title: "List phone calls",
        description: "Lists the account's calls, newest first, to or from a number or in a state.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Get,
        path: &[Segment::Fixed("Calls.json")],
        fields: &[
            Field::optional("to", Kind::Text, Place::Query, "Only calls to this number.")
                .sent_as("To"),
            Field::optional(
                "from",
                Kind::Text,
                Place::Query,
                "Only calls from this number.",
            )
            .sent_as("From"),
            Field::optional(
                "state",
                Kind::Text,
                Place::Query,
                "Only calls in this state, such as completed or busy.",
            )
            .sent_as("Status"),
            MOST,
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Form,
        outputs: &[
            (
                "json.calls",
                "The calls, each with its sid, to, from, status and duration.",
            ),
            (
                "json.next_page_uri",
                "Where the next page is, when there is one.",
            ),
        ],
    },
    Operation {
        key: "list-numbers",
        title: "List phone numbers",
        description: "Lists the account's phone numbers, which messages and calls can come from.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Get,
        path: &[Segment::Fixed("IncomingPhoneNumbers.json")],
        fields: &[
            Field::optional(
                "number",
                Kind::Text,
                Place::Query,
                "Only numbers containing these digits.",
            )
            .sent_as("PhoneNumber"),
            Field::optional(
                "name",
                Kind::Text,
                Place::Query,
                "Only numbers with this friendly name.",
            )
            .sent_as("FriendlyName"),
            MOST,
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Form,
        outputs: &[
            (
                "json.incoming_phone_numbers",
                "The numbers, each with its phone_number, friendly_name and capabilities.",
            ),
            (
                "json.next_page_uri",
                "Where the next page is, when there is one.",
            ),
        ],
    },
];
