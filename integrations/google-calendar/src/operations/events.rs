//! Events: listing and reading them, creating one written out or from a
//! sentence, changing, moving and deleting one.

use ianua_domain::types::{ActionClass, DeclaredAction};
use ianua_integration::form::Ask;
use ianua_integration::rest::operation::{Field, Kind, Operation, Place, Segment, Shape, Verb};

use crate::operations::CALENDAR;

/// The event a step acts on, in the path.
const EVENT: Field = Field::required(
    "event",
    Kind::Text,
    Place::Path,
    "The event's id, such as an earlier step's json.id.",
);

/// Who Google tells of a change.
const NOTIFY: Field = Field::optional(
    "notify",
    Kind::Text,
    Place::Query,
    "Who Google mails about it: all, externalOnly or none; none when not given.",
)
.sent_as("sendUpdates");

/// An event's title.
const SUMMARY: Field = Field::optional("summary", Kind::Text, Place::Body, "The event's title.");

/// An event's description.
const DESCRIPTION: Field = Field::optional(
    "description",
    Kind::Text,
    Place::Body,
    "What the event is about.",
)
.asked_with(Ask::LongText);

/// An event's place.
const LOCATION: Field = Field::optional(
    "location",
    Kind::Text,
    Place::Body,
    "Where it happens, as text.",
);

/// The people invited to an event.
const ATTENDEES: Field = Field::optional(
    "attendees",
    Kind::Values,
    Place::Body,
    "The people invited, as a list such as [{\"email\": \"ann@acme.test\"}].",
);

/// The path of a calendar's events.
const EVENTS: &[Segment] = &[
    Segment::Fixed("calendars"),
    Segment::Input("calendar"),
    Segment::Fixed("events"),
];

/// The path of one event.
const ONE: &[Segment] = &[
    Segment::Fixed("calendars"),
    Segment::Input("calendar"),
    Segment::Fixed("events"),
    Segment::Input("event"),
];

/// The outputs of a step answering with an event.
const AN_EVENT: &[(&str, &str)] = &[
    (
        "json.id",
        "The event's id, which changing, moving or deleting it names.",
    ),
    (
        "json.htmlLink",
        "The address of the event in Google Calendar.",
    ),
    (
        "json.start",
        "When it starts: dateTime, or date for an all-day event.",
    ),
    ("json.end", "When it ends."),
];

/// Every event operation.
pub(crate) const OPERATIONS: &[Operation] = &[
    Operation {
        key: "list-events",
        title: "List events",
        description: "Lists a calendar's events between two times, soonest first, with each repeat of a recurring event on its own.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Get,
        path: EVENTS,
        fields: &[
            CALENDAR,
            Field::optional(
                "from",
                Kind::Text,
                Place::Query,
                "Only events ending after this time, such as 2026-11-02T00:00:00Z.",
            )
            .sent_as("timeMin"),
            Field::optional(
                "until",
                Kind::Text,
                Place::Query,
                "Only events starting before this time.",
            )
            .sent_as("timeMax"),
            Field::optional(
                "search",
                Kind::Text,
                Place::Query,
                "Only events whose text holds these words.",
            )
            .sent_as("q"),
            Field::optional(
                "most",
                Kind::Count,
                Place::Query,
                "How many to give at most, up to 2,500; Google's default is 250.",
            )
            .sent_as("maxResults"),
        ],
        fixed: &[],
        query: &[("singleEvents", "true"), ("orderBy", "startTime")],
        shape: Shape::Object,
        outputs: &[
            (
                "json.items",
                "The events, each with its id, summary, start, end and attendees.",
            ),
            (
                "json.nextPageToken",
                "Where the next page starts, when there is one.",
            ),
        ],
    },
    Operation {
        key: "get-event",
        title: "Get an event",
        description: "Reads an event: its title, times, place, people and their answers.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Get,
        path: ONE,
        fields: &[CALENDAR, EVENT],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            ("json.summary", "The event's title."),
            ("json.start", "When it starts."),
            ("json.end", "When it ends."),
            (
                "json.attendees",
                "The people invited, each with their responseStatus.",
            ),
            (
                "json.status",
                "Whether it is confirmed, tentative or cancelled.",
            ),
        ],
    },
    Operation {
        key: "create-event",
        title: "Create an event",
        description: "Adds an event to a calendar, inviting the people named, who see it on their own calendars.",
        effect: DeclaredAction::Declared(ActionClass::Communicate),
        verb: Verb::Post,
        path: EVENTS,
        fields: &[
            CALENDAR,
            Field::required("summary", Kind::Text, Place::Body, "The event's title."),
            Field::required(
                "start",
                Kind::Text,
                Place::Body,
                "When it starts, with its offset, such as 2026-11-03T09:00:00+01:00.",
            )
            .sent_as("start.dateTime"),
            Field::required(
                "end",
                Kind::Text,
                Place::Body,
                "When it ends, with its offset.",
            )
            .sent_as("end.dateTime"),
            DESCRIPTION,
            LOCATION,
            ATTENDEES,
            NOTIFY,
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: AN_EVENT,
    },
    Operation {
        key: "quick-add-event",
        title: "Add an event from a sentence",
        description: "Adds an event to a calendar from a sentence Google reads, such as Review with Ann tomorrow at 3pm.",
        effect: DeclaredAction::Declared(ActionClass::Write),
        verb: Verb::Post,
        path: &[
            Segment::Fixed("calendars"),
            Segment::Input("calendar"),
            Segment::Fixed("events"),
            Segment::Fixed("quickAdd"),
        ],
        fields: &[
            CALENDAR,
            Field::required(
                "text",
                Kind::Text,
                Place::Query,
                "The sentence describing the event.",
            ),
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: AN_EVENT,
    },
    Operation {
        key: "update-event",
        title: "Update an event",
        description: "Changes what is given of an event, leaving the rest; people invited see the change.",
        effect: DeclaredAction::Declared(ActionClass::Communicate),
        verb: Verb::Patch,
        path: ONE,
        fields: &[
            CALENDAR,
            EVENT,
            SUMMARY,
            Field::optional(
                "start",
                Kind::Text,
                Place::Body,
                "When it now starts, with its offset.",
            )
            .sent_as("start.dateTime"),
            Field::optional(
                "end",
                Kind::Text,
                Place::Body,
                "When it now ends, with its offset.",
            )
            .sent_as("end.dateTime"),
            DESCRIPTION,
            LOCATION,
            ATTENDEES,
            NOTIFY,
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: AN_EVENT,
    },
    Operation {
        key: "move-event",
        title: "Move an event",
        description: "Moves an event to another calendar the account can write to.",
        effect: DeclaredAction::Declared(ActionClass::Write),
        verb: Verb::Post,
        path: &[
            Segment::Fixed("calendars"),
            Segment::Input("calendar"),
            Segment::Fixed("events"),
            Segment::Input("event"),
            Segment::Fixed("move"),
        ],
        fields: &[
            CALENDAR,
            EVENT,
            Field::required(
                "destination",
                Kind::Text,
                Place::Query,
                "The calendar to move it to, such as team@group.calendar.google.com.",
            ),
            NOTIFY,
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: AN_EVENT,
    },
    Operation {
        key: "delete-event",
        title: "Delete an event",
        description: "Deletes an event from a calendar for good; people invited see it cancelled.",
        effect: DeclaredAction::Declared(ActionClass::Delete),
        verb: Verb::Delete,
        path: ONE,
        fields: &[CALENDAR, EVENT, NOTIFY],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[(
            "status",
            "The status Google answered with once the event was deleted.",
        )],
    },
];
