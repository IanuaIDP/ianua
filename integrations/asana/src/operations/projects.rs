//! Workspaces and what sits in them: listing workspaces, projects,
//! sections and people, which the pickers read, and putting a task in a
//! project.

use ianua_domain::types::{ActionClass, DeclaredAction};
use ianua_integration::form::Ask;
use ianua_integration::rest::operation::{Field, Kind, Operation, Place, Segment, Shape, Verb};

use crate::operations::{ANY_PROJECT, SECTIONS, TASK, WORKSPACES};

/// The most each list gives back, which Asana asks a large list to name.
const PAGE: (&str, &str) = ("limit", "100");

/// The workspace a list is narrowed to, in the query.
const IN_WORKSPACE: Field = Field::optional(
    "workspace",
    Kind::Text,
    Place::Query,
    "Only those in this workspace, by its gid; every workspace when left out.",
)
.asked_with(Ask::Picker(WORKSPACES));

/// What a list gives back.
const LISTED: &[(&str, &str)] = &[
    ("json.data", "Each one's gid and name."),
    ("status", "The status Asana answered with."),
];

/// Every workspace and placement operation.
pub(crate) const OPERATIONS: &[Operation] = &[
    Operation {
        key: "list-workspaces",
        title: "List workspaces",
        description: "Lists the workspaces and organizations the account belongs to.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Get,
        path: &[Segment::Fixed("workspaces")],
        fields: &[],
        fixed: &[],
        query: &[PAGE],
        shape: Shape::Object,
        outputs: LISTED,
    },
    Operation {
        key: "list-projects",
        title: "List projects",
        description: "Lists the projects the account can see that are not archived, in one workspace or all of them.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Get,
        path: &[Segment::Fixed("projects")],
        fields: &[IN_WORKSPACE],
        fixed: &[],
        query: &[PAGE, ("archived", "false")],
        shape: Shape::Object,
        outputs: LISTED,
    },
    Operation {
        key: "list-sections",
        title: "List sections",
        description: "Lists the sections of a project.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Get,
        path: &[
            Segment::Fixed("projects"),
            Segment::Input("project"),
            Segment::Fixed("sections"),
        ],
        fields: &[Field::required(
            "project",
            Kind::Text,
            Place::Path,
            "The project's gid.",
        )
        .asked_with(Ask::Picker(ANY_PROJECT))],
        fixed: &[],
        query: &[PAGE],
        shape: Shape::Object,
        outputs: LISTED,
    },
    Operation {
        key: "list-users",
        title: "List people",
        description: "Lists the people the account can see, in one workspace or all of them.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Get,
        path: &[Segment::Fixed("users")],
        fields: &[IN_WORKSPACE],
        fixed: &[],
        query: &[PAGE],
        shape: Shape::Object,
        outputs: LISTED,
    },
    Operation {
        key: "add-task-to-project",
        title: "Add a task to a project",
        description: "Puts a task at the end of a project, or of one of its sections, keeping the projects it is already in.",
        effect: DeclaredAction::Declared(ActionClass::Write),
        verb: Verb::Post,
        path: &[
            Segment::Fixed("tasks"),
            Segment::Input("task"),
            Segment::Fixed("addProject"),
        ],
        fields: &[
            TASK,
            Field::required(
                "project",
                Kind::Text,
                Place::Body,
                "The project's gid.",
            )
            .sent_as("data.project")
            .asked_with(Ask::Picker(ANY_PROJECT)),
            Field::optional(
                "section",
                Kind::Text,
                Place::Body,
                "The section the task goes to the end of, by its gid; the end of the project when left out.",
            )
            .sent_as("data.section")
            .asked_with(Ask::Picker(SECTIONS)),
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[(
            "status",
            "The status Asana answered with, 200 when the task was added.",
        )],
    },
];
