//! Calendars: listing the account's calendars, creating one, and finding
//! when calendars are busy.

use ianua_domain::types::{ActionClass, DeclaredAction};
use ianua_integration::rest::operation::{Field, Kind, Operation, Place, Segment, Shape, Verb};

/// Every calendar operation.
pub(crate) const OPERATIONS: &[Operation] = &[
    Operation {
        key: "list-calendars",
        title: "List calendars",
        description: "Lists the calendars the account sees, with how far it may act on each.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Get,
        path: &[
            Segment::Fixed("users"),
            Segment::Fixed("me"),
            Segment::Fixed("calendarList"),
        ],
        fields: &[Field::optional(
            "most",
            Kind::Count,
            Place::Query,
            "How many to give at most, up to 250.",
        )
        .sent_as("maxResults")],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            (
                "json.items",
                "The calendars, each with its id, summary and accessRole.",
            ),
            (
                "json.nextPageToken",
                "Where the next page starts, when there is one.",
            ),
        ],
    },
    Operation {
        key: "create-calendar",
        title: "Create a calendar",
        description: "Creates a calendar the account owns.",
        effect: DeclaredAction::Declared(ActionClass::Write),
        verb: Verb::Post,
        path: &[Segment::Fixed("calendars")],
        fields: &[
            Field::required("summary", Kind::Text, Place::Body, "The calendar's name."),
            Field::optional(
                "description",
                Kind::Text,
                Place::Body,
                "What the calendar is for.",
            ),
            Field::optional(
                "time_zone",
                Kind::Text,
                Place::Body,
                "Its time zone, such as Europe/Berlin.",
            )
            .sent_as("timeZone"),
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[(
            "json.id",
            "The calendar's id, which its events' steps name.",
        )],
    },
    Operation {
        key: "find-free-busy",
        title: "Find busy times",
        description: "Finds when calendars are busy between two times, to pick a time everyone is free.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Post,
        path: &[Segment::Fixed("freeBusy")],
        fields: &[
            Field::required(
                "from",
                Kind::Text,
                Place::Body,
                "The start of the time to look at, such as 2026-11-03T08:00:00Z.",
            )
            .sent_as("timeMin"),
            Field::required(
                "until",
                Kind::Text,
                Place::Body,
                "The end of the time to look at.",
            )
            .sent_as("timeMax"),
            Field::required(
                "calendars",
                Kind::Values,
                Place::Body,
                "The calendars to look at, as a list such as [{\"id\": \"ann@acme.test\"}].",
            )
            .sent_as("items"),
            Field::optional(
                "time_zone",
                Kind::Text,
                Place::Body,
                "The time zone of the answer, UTC when not given.",
            )
            .sent_as("timeZone"),
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[(
            "json.calendars",
            "Each calendar's busy times, as a list of start and end.",
        )],
    },
];
