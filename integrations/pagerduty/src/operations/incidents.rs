//! Incidents: listing and reading them, opening one, acknowledging,
//! resolving and snoozing it, and adding a note.
//!
//! PagerDuty takes a change to an incident only from a person: with a
//! user API token the change is that person's. An account-wide key would
//! have to name someone in a `From` header for each change, which these
//! steps do not send, so PagerDuty refuses their changes and the step
//! fails with its reason.

use ianua_domain::domains::workflows::integration::form::Tone;
use ianua_domain::types::{ActionClass, DeclaredAction};
use ianua_integration::form::{Ask, ChoiceText};
use ianua_integration::rest::operation::{
    Field, Fixed, Kind, Operation, Place, Segment, Shape, Verb,
};

use crate::operations::{LIMIT, SERVICES, user_filter};

/// The path of the account's incidents.
const INCIDENTS: &[Segment] = &[Segment::Fixed("incidents")];

/// The path of one incident.
const ONE_INCIDENT: &[Segment] = &[Segment::Fixed("incidents"), Segment::Input("incident")];

/// The incident a step acts on.
const INCIDENT: Field = Field::required(
    "incident",
    Kind::Text,
    Place::Path,
    "The incident's id, such as an earlier step's json.incident.id.",
)
.example("Q2LKJQ1");

/// How urgent an incident is, as PagerDuty names it.
const URGENCIES: &[ChoiceText] = &[
    ChoiceText {
        value: "high",
        label: "High",
        tone: Tone::Danger,
    },
    ChoiceText {
        value: "low",
        label: "Low",
        tone: Tone::Neutral,
    },
];

/// What changing one incident gives back.
const INCIDENT_OUTPUTS: &[(&str, &str)] = &[
    ("json.incident.id", "The incident's id."),
    (
        "json.incident.number",
        "The incident's number in the account.",
    ),
    (
        "json.incident.status",
        "Its status: triggered, acknowledged or resolved.",
    ),
    (
        "json.incident.html_url",
        "The address of the incident's page.",
    ),
    (
        "status",
        "The status PagerDuty answered with, 200 when it was changed.",
    ),
];

/// Every incident operation.
pub(crate) const OPERATIONS: &[Operation] = &[
    Operation {
        key: "list-incidents",
        title: "List incidents",
        description: "Lists the account's incidents, newest first, optionally narrowed by status, service, urgency and assigned person.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Get,
        path: INCIDENTS,
        fields: &[
            Field::optional(
                "statuses",
                Kind::RepeatedList,
                Place::Query,
                "Only incidents in these statuses: triggered, acknowledged or resolved.",
            )
            .sent_as("statuses[]")
            .asked_with(Ask::Choices(&[
                ChoiceText {
                    value: "triggered",
                    label: "Triggered",
                    tone: Tone::Danger,
                },
                ChoiceText {
                    value: "acknowledged",
                    label: "Acknowledged",
                    tone: Tone::Warning,
                },
                ChoiceText {
                    value: "resolved",
                    label: "Resolved",
                    tone: Tone::Success,
                },
            ])),
            Field::optional(
                "services",
                Kind::RepeatedList,
                Place::Query,
                "Only incidents on these services, by id.",
            )
            .sent_as("service_ids[]")
            .asked_with(Ask::Picker(SERVICES)),
            Field::optional(
                "urgencies",
                Kind::RepeatedList,
                Place::Query,
                "Only incidents of these urgencies: high or low.",
            )
            .sent_as("urgencies[]")
            .asked_with(Ask::Choices(URGENCIES))
            .more_options(),
            user_filter("Only incidents assigned to these people, by id."),
            LIMIT,
        ],
        fixed: &[],
        query: &[("sort_by", "created_at:desc")],
        shape: Shape::Object,
        outputs: &[
            (
                "json.incidents",
                "The incidents, each with its id, number, title, status, urgency, service and html_url.",
            ),
            ("status", "The status PagerDuty answered with."),
        ],
    },
    Operation {
        key: "get-incident",
        title: "Get an incident",
        description: "Reads one incident: its title, status, urgency, service, who it is assigned to and its page.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Get,
        path: ONE_INCIDENT,
        fields: &[INCIDENT],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            ("json.incident.title", "The incident's title."),
            ("json.incident.number", "The incident's number in the account."),
            (
                "json.incident.status",
                "Its status: triggered, acknowledged or resolved.",
            ),
            ("json.incident.urgency", "Its urgency: high or low."),
            ("json.incident.service", "The service it is on."),
            (
                "json.incident.assignments",
                "The people it is assigned to.",
            ),
            ("json.incident.html_url", "The address of the incident's page."),
            ("status", "The status PagerDuty answered with."),
        ],
    },
    Operation {
        key: "create-incident",
        title: "Open an incident",
        description: "Opens an incident on a service, which pages whoever its escalation policy has on call. Needs a user API token: the incident is opened as that person.",
        effect: DeclaredAction::Declared(ActionClass::Communicate),
        verb: Verb::Post,
        path: INCIDENTS,
        fields: &[
            Field::required(
                "service",
                Kind::Text,
                Place::Body,
                "The service the incident is on, by its id; its escalation policy decides who is paged.",
            )
            .sent_as("incident.service.id")
            .asked_with(Ask::Picker(SERVICES)),
            Field::required("title", Kind::Text, Place::Body, "What is wrong, in a line.")
                .sent_as("incident.title")
                .example("Checkout is failing"),
            Field::optional(
                "urgency",
                Kind::Text,
                Place::Body,
                "How urgent it is: high or low; the service's own setting when not given.",
            )
            .sent_as("incident.urgency")
            .asked_with(Ask::Choices(URGENCIES)),
            Field::optional(
                "details",
                Kind::Text,
                Place::Body,
                "What responders should know, in plain text.",
            )
            .sent_as("incident.body.details")
            .asked_with(Ask::LongText),
            Field::optional(
                "incident_key",
                Kind::Text,
                Place::Body,
                "A key that stops a second open incident with the same key on the service.",
            )
            .sent_as("incident.incident_key")
            .more_options(),
        ],
        fixed: &[
            ("incident.type", Fixed::Text("incident")),
            ("incident.service.type", Fixed::Text("service_reference")),
            ("incident.body.type", Fixed::Text("incident_body")),
        ],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            (
                "json.incident.id",
                "The new incident's id, which later steps name.",
            ),
            ("json.incident.number", "The incident's number in the account."),
            ("json.incident.html_url", "The address of the incident's page."),
            (
                "status",
                "The status PagerDuty answered with, 201 when the incident was opened.",
            ),
        ],
    },
    Operation {
        key: "acknowledge-incident",
        title: "Acknowledge an incident",
        description: "Marks an incident as being worked on, which stops it escalating. Needs a user API token: it is acknowledged as that person.",
        effect: DeclaredAction::Declared(ActionClass::Write),
        verb: Verb::Put,
        path: ONE_INCIDENT,
        fields: &[INCIDENT],
        fixed: &[
            ("incident.type", Fixed::Text("incident_reference")),
            ("incident.status", Fixed::Text("acknowledged")),
        ],
        query: &[],
        shape: Shape::Object,
        outputs: INCIDENT_OUTPUTS,
    },
    Operation {
        key: "resolve-incident",
        title: "Resolve an incident",
        description: "Resolves an incident, saying how when a resolution is given. Needs a user API token: it is resolved as that person.",
        effect: DeclaredAction::Declared(ActionClass::Write),
        verb: Verb::Put,
        path: ONE_INCIDENT,
        fields: &[
            INCIDENT,
            Field::optional(
                "resolution",
                Kind::Text,
                Place::Body,
                "How it was resolved, added to the incident as a note.",
            )
            .sent_as("incident.resolution")
            .asked_with(Ask::LongText),
        ],
        fixed: &[
            ("incident.type", Fixed::Text("incident_reference")),
            ("incident.status", Fixed::Text("resolved")),
        ],
        query: &[],
        shape: Shape::Object,
        outputs: INCIDENT_OUTPUTS,
    },
    Operation {
        key: "snooze-incident",
        title: "Snooze an incident",
        description: "Puts an acknowledged incident aside for a while; it is triggered again once the time is up. Needs a user API token: it is snoozed as that person.",
        effect: DeclaredAction::Declared(ActionClass::Write),
        verb: Verb::Post,
        path: &[
            Segment::Fixed("incidents"),
            Segment::Input("incident"),
            Segment::Fixed("snooze"),
        ],
        fields: &[
            INCIDENT,
            Field::required(
                "duration",
                Kind::Count,
                Place::Body,
                "How long to snooze it, in seconds, at most 604800 (a week).",
            )
            .example("3600"),
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            ("json.incident.id", "The incident's id."),
            (
                "json.incident.status",
                "Its status, acknowledged while snoozed.",
            ),
            ("json.incident.html_url", "The address of the incident's page."),
            (
                "status",
                "The status PagerDuty answered with, 201 when it was snoozed.",
            ),
        ],
    },
    Operation {
        key: "add-note",
        title: "Add a note to an incident",
        description: "Adds a note to an incident's timeline, which responders read; nobody is paged. Needs a user API token: the note is that person's.",
        effect: DeclaredAction::Declared(ActionClass::Write),
        verb: Verb::Post,
        path: &[
            Segment::Fixed("incidents"),
            Segment::Input("incident"),
            Segment::Fixed("notes"),
        ],
        fields: &[
            INCIDENT,
            Field::required("content", Kind::Text, Place::Body, "What the note says.")
                .sent_as("note.content")
                .asked_with(Ask::LongText),
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            ("json.note.id", "The note's id."),
            ("json.note.created_at", "When the note was added."),
            (
                "status",
                "The status PagerDuty answered with, 200 when the note was added.",
            ),
        ],
    },
];
