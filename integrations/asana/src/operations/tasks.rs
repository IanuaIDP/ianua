//! Tasks: creating, reading, editing, completing, reopening, deleting and
//! searching them, and commenting on one.

use ianua_domain::domains::workflows::integration::form::Tone;
use ianua_domain::types::{ActionClass, DeclaredAction};
use ianua_integration::form::{Ask, ChoiceText};
use ianua_integration::rest::operation::{
    Field, Fixed, Kind, Operation, Place, Segment, Shape, Verb,
};

use crate::operations::{ANY_USER, PROJECTS, TASK, USERS, WORKSPACE, WORKSPACES};

/// The path of one task.
const ONE_TASK: &[Segment] = &[Segment::Fixed("tasks"), Segment::Input("task")];

/// What changing one task gives back.
const TASK_OUTPUTS: &[(&str, &str)] = &[
    ("json.data.gid", "The task's gid."),
    ("json.data.name", "The task's name."),
    ("json.data.completed", "Whether the task is completed."),
    (
        "json.data.permalink_url",
        "The address of the task in Asana.",
    ),
    (
        "status",
        "The status Asana answered with, 200 when it was changed.",
    ),
];

/// Who a task is assigned to, in a step that names no workspace.
const ASSIGNEE: Field = Field::optional(
    "assignee",
    Kind::Text,
    Place::Body,
    "Who the task is assigned to: a person's gid, their email, or me.",
)
.sent_as("data.assignee")
.asked_with(Ask::Picker(ANY_USER))
.example("me");

/// When a task is due.
const DUE_ON: Field = Field::optional(
    "due_on",
    Kind::Text,
    Place::Body,
    "The day the task is due, written as year-month-day.",
)
.sent_as("data.due_on")
.example("2026-11-30");

/// Every task operation.
pub(crate) const OPERATIONS: &[Operation] = &[
    Operation {
        key: "create-task",
        title: "Create a task",
        description: "Creates a task in an Asana workspace, optionally assigned, due on a day and placed in projects.",
        effect: DeclaredAction::Declared(ActionClass::Write),
        verb: Verb::Post,
        path: &[Segment::Fixed("tasks")],
        fields: &[
            Field::required(
                "workspace",
                Kind::Text,
                Place::Body,
                "The workspace's gid, where the task is made.",
            )
            .sent_as("data.workspace")
            .asked_with(Ask::Picker(WORKSPACES)),
            Field::required("name", Kind::Text, Place::Body, "The task's name.")
                .sent_as("data.name")
                .example("Renew the support contract"),
            Field::optional(
                "notes",
                Kind::Text,
                Place::Body,
                "The task's description, as plain text.",
            )
            .sent_as("data.notes")
            .asked_with(Ask::LongText),
            Field::optional(
                "assignee",
                Kind::Text,
                Place::Body,
                "Who the task is assigned to: a person's gid, their email, or me.",
            )
            .sent_as("data.assignee")
            .asked_with(Ask::Picker(USERS))
            .example("me"),
            Field::optional(
                "projects",
                Kind::TextList,
                Place::Body,
                "The projects the task is put in, each by its gid.",
            )
            .sent_as("data.projects")
            .asked_with(Ask::MultiPicker(PROJECTS)),
            DUE_ON.more_options(),
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            (
                "json.data.gid",
                "The new task's gid, which later steps name it by.",
            ),
            (
                "json.data.permalink_url",
                "The address of the task in Asana.",
            ),
            (
                "status",
                "The status Asana answered with, 201 when the task was created.",
            ),
        ],
    },
    Operation {
        key: "get-task",
        title: "Get a task",
        description: "Reads one task: its name, description, assignee, due day, projects and whether it is completed.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Get,
        path: ONE_TASK,
        fields: &[TASK],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            ("json.data.name", "The task's name."),
            ("json.data.notes", "The task's description."),
            ("json.data.completed", "Whether the task is completed."),
            ("json.data.assignee", "Who the task is assigned to."),
            ("json.data.due_on", "The day the task is due."),
            ("json.data.projects", "The projects the task is in."),
            (
                "json.data.permalink_url",
                "The address of the task in Asana.",
            ),
            ("status", "The status Asana answered with."),
        ],
    },
    Operation {
        key: "update-task",
        title: "Edit a task",
        description: "Changes a task's name, description, assignee or due day; what is not given stays as it was.",
        effect: DeclaredAction::Declared(ActionClass::Write),
        verb: Verb::Put,
        path: ONE_TASK,
        fields: &[
            TASK,
            Field::optional("name", Kind::Text, Place::Body, "The task's new name.")
                .sent_as("data.name"),
            Field::optional(
                "notes",
                Kind::Text,
                Place::Body,
                "The task's new description, as plain text.",
            )
            .sent_as("data.notes")
            .asked_with(Ask::LongText),
            ASSIGNEE,
            DUE_ON,
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: TASK_OUTPUTS,
    },
    Operation {
        key: "complete-task",
        title: "Complete a task",
        description: "Marks a task completed.",
        effect: DeclaredAction::Declared(ActionClass::Write),
        verb: Verb::Put,
        path: ONE_TASK,
        fields: &[TASK],
        fixed: &[("data.completed", Fixed::Flag(true))],
        query: &[],
        shape: Shape::Object,
        outputs: TASK_OUTPUTS,
    },
    Operation {
        key: "reopen-task",
        title: "Reopen a task",
        description: "Marks a completed task not completed again.",
        effect: DeclaredAction::Declared(ActionClass::Write),
        verb: Verb::Put,
        path: ONE_TASK,
        fields: &[TASK],
        fixed: &[("data.completed", Fixed::Flag(false))],
        query: &[],
        shape: Shape::Object,
        outputs: TASK_OUTPUTS,
    },
    Operation {
        key: "comment-on-task",
        title: "Comment on a task",
        description: "Adds a comment to a task, which notifies everyone following it.",
        effect: DeclaredAction::Declared(ActionClass::Communicate),
        verb: Verb::Post,
        path: &[
            Segment::Fixed("tasks"),
            Segment::Input("task"),
            Segment::Fixed("stories"),
        ],
        fields: &[
            TASK,
            Field::required(
                "text",
                Kind::Text,
                Place::Body,
                "The comment's text, as plain text.",
            )
            .sent_as("data.text")
            .asked_with(Ask::LongText),
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            ("json.data.gid", "The comment's gid."),
            (
                "status",
                "The status Asana answered with, 201 when the comment was added.",
            ),
        ],
    },
    Operation {
        key: "delete-task",
        title: "Delete a task",
        description: "Deletes a task; Asana keeps it in the trash for 30 days, after which it is gone for good.",
        effect: DeclaredAction::Declared(ActionClass::Delete),
        verb: Verb::Delete,
        path: ONE_TASK,
        fields: &[TASK],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[(
            "status",
            "The status Asana answered with, 200 when the task was deleted.",
        )],
    },
    Operation {
        key: "search-tasks",
        title: "Search tasks",
        description: "Finds tasks in a workspace by their text, assignee, projects and whether they are completed. Asana offers search only to premium workspaces and teams.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Get,
        path: &[
            Segment::Fixed("workspaces"),
            Segment::Input("workspace"),
            Segment::Fixed("tasks"),
            Segment::Fixed("search"),
        ],
        fields: &[
            WORKSPACE,
            Field::optional(
                "text",
                Kind::Text,
                Place::Query,
                "Words to find in a task's name or description.",
            )
            .example("contract"),
            Field::optional(
                "assignee",
                Kind::Text,
                Place::Query,
                "Only tasks assigned to this person: their gid, their email, or me.",
            )
            .sent_as("assignee.any")
            .asked_with(Ask::Picker(USERS)),
            Field::optional(
                "projects",
                Kind::TextList,
                Place::Query,
                "Only tasks in one of these projects, each by its gid.",
            )
            .sent_as("projects.any")
            .asked_with(Ask::MultiPicker(PROJECTS)),
            Field::optional(
                "completed",
                Kind::Flag,
                Place::Query,
                "Only completed tasks when on, only open ones when off; both when not given.",
            ),
            Field::optional(
                "sort_by",
                Kind::Text,
                Place::Query,
                "What the tasks are sorted by; when they last changed when not given.",
            )
            .asked_with(Ask::Choices(&[
                ChoiceText {
                    value: "modified_at",
                    label: "Last changed",
                    tone: Tone::Neutral,
                },
                ChoiceText {
                    value: "due_date",
                    label: "Due day",
                    tone: Tone::Info,
                },
                ChoiceText {
                    value: "created_at",
                    label: "Created",
                    tone: Tone::Neutral,
                },
                ChoiceText {
                    value: "relevance",
                    label: "Best match",
                    tone: Tone::Info,
                },
            ]))
            .more_options(),
            Field::optional(
                "limit",
                Kind::Count,
                Place::Query,
                "How many to find, at most 100.",
            )
            .more_options(),
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            ("json.data", "The tasks found, each with its gid and name."),
            ("status", "The status Asana answered with."),
        ],
    },
];
