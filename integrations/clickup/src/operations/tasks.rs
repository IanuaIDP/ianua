//! Tasks: creating, reading, editing, moving to another status, tagging,
//! commenting on and deleting them.

use ianua_domain::domains::workflows::integration::form::Tone;
use ianua_domain::types::{ActionClass, DeclaredAction};
use ianua_integration::form::{Ask, ChoiceText};
use ianua_integration::rest::operation::{
    Field, Fixed, Kind, Operation, Place, Segment, Shape, Verb,
};

use crate::operations::{
    LIST, LIST_PEOPLE, PICKING_FOLDER, PICKING_SPACE, PICKING_WORKSPACE, STATUSES, TASK,
};

/// The path of one task.
const ONE_TASK: &[Segment] = &[Segment::Fixed("task"), Segment::Input("task")];

/// What changing one task gives back.
const TASK_OUTPUTS: &[(&str, &str)] = &[
    ("json.id", "The task's id."),
    ("json.name", "The task's name."),
    ("json.status", "The task's status, its name in status."),
    ("json.url", "The address of the task in ClickUp."),
    (
        "status",
        "The status ClickUp answered with, 200 when it was changed.",
    ),
];

/// A task's description, written in Markdown.
const DESCRIPTION: Field = Field::optional(
    "description",
    Kind::Text,
    Place::Body,
    "The task's description, in Markdown.",
)
.sent_as("markdown_content")
.asked_with(Ask::LongText);

/// How urgent a task is, by ClickUp's number for it.
const PRIORITY: Field = Field::optional(
    "priority",
    Kind::Count,
    Place::Body,
    "How urgent the task is: 1 urgent, 2 high, 3 normal or 4 low.",
)
.asked_with(Ask::Choices(&[
    ChoiceText {
        value: "1",
        label: "Urgent",
        tone: Tone::Danger,
    },
    ChoiceText {
        value: "2",
        label: "High",
        tone: Tone::Warning,
    },
    ChoiceText {
        value: "3",
        label: "Normal",
        tone: Tone::Info,
    },
    ChoiceText {
        value: "4",
        label: "Low",
        tone: Tone::Neutral,
    },
]));

/// When a task is due.
const DUE_DATE: Field = Field::optional(
    "due_date",
    Kind::Count,
    Place::Body,
    "When the task is due, as Unix time in milliseconds.",
)
.example("1767225600000")
.more_options();

/// Every task operation.
pub(crate) const OPERATIONS: &[Operation] = &[
    Operation {
        key: "create-task",
        title: "Create a task",
        description: "Creates a task in a ClickUp list, optionally in a status, with a priority, tags, people assigned and a due time.",
        effect: DeclaredAction::Declared(ActionClass::Write),
        verb: Verb::Post,
        path: &[
            Segment::Fixed("list"),
            Segment::Input("list"),
            Segment::Fixed("task"),
        ],
        fields: &[
            PICKING_WORKSPACE,
            PICKING_SPACE,
            PICKING_FOLDER,
            LIST,
            Field::required("name", Kind::Text, Place::Body, "The task's name.")
                .example("Renew the support contract"),
            DESCRIPTION,
            Field::optional(
                "status",
                Kind::Text,
                Place::Body,
                "The status the task starts in, by its name in the list; the list's first when left out.",
            )
            .asked_with(Ask::Picker(STATUSES)),
            PRIORITY,
            Field::optional(
                "tags",
                Kind::TextList,
                Place::Body,
                "The tags the task carries, each by its name.",
            ),
            Field::optional(
                "assignees",
                Kind::CountList,
                Place::Body,
                "The people the task is assigned to, by their numeric ids such as 183, which list-members gives back.",
            )
            .asked_with(Ask::MultiPicker(LIST_PEOPLE))
            .more_options(),
            DUE_DATE,
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            ("json.id", "The new task's id, which later steps name it by."),
            ("json.url", "The address of the task in ClickUp."),
            (
                "status",
                "The status ClickUp answered with, 200 when the task was created.",
            ),
        ],
    },
    Operation {
        key: "get-task",
        title: "Get a task",
        description: "Reads one task: its name, description, status, priority, people assigned, tags and due time.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Get,
        path: ONE_TASK,
        fields: &[TASK],
        fixed: &[],
        query: &[("include_markdown_description", "true")],
        shape: Shape::Object,
        outputs: &[
            ("json.name", "The task's name."),
            (
                "json.markdown_description",
                "The task's description, in Markdown.",
            ),
            ("json.status", "The task's status, its name in status."),
            ("json.priority", "How urgent the task is."),
            (
                "json.assignees",
                "The people the task is assigned to, each with their numeric id.",
            ),
            ("json.tags", "The tags on the task."),
            (
                "json.due_date",
                "When the task is due, as Unix time in milliseconds.",
            ),
            ("json.list", "The list the task is in."),
            ("json.url", "The address of the task in ClickUp."),
            ("status", "The status ClickUp answered with."),
        ],
    },
    Operation {
        key: "update-task",
        title: "Edit a task",
        description: "Changes a task's name, description, priority or due time, and who it is assigned to; what is not given stays as it was.",
        effect: DeclaredAction::Declared(ActionClass::Write),
        verb: Verb::Put,
        path: ONE_TASK,
        fields: &[
            TASK,
            Field::optional("name", Kind::Text, Place::Body, "The task's new name."),
            DESCRIPTION,
            PRIORITY,
            Field::optional(
                "add_assignees",
                Kind::CountList,
                Place::Body,
                "People to assign the task to, by their numeric ids such as 183.",
            )
            .sent_as("assignees.add")
            .more_options(),
            Field::optional(
                "remove_assignees",
                Kind::CountList,
                Place::Body,
                "People to take off the task, by their numeric ids such as 183.",
            )
            .sent_as("assignees.rem")
            .more_options(),
            DUE_DATE,
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: TASK_OUTPUTS,
    },
    Operation {
        key: "set-task-status",
        title: "Set a task's status",
        description: "Moves a task to another status of its list, such as in progress or complete.",
        effect: DeclaredAction::Declared(ActionClass::Write),
        verb: Verb::Put,
        path: ONE_TASK,
        fields: &[
            TASK,
            Field::required(
                "status",
                Kind::Text,
                Place::Body,
                "The status to move the task to, by its name in the task's list.",
            )
            .example("in progress"),
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: TASK_OUTPUTS,
    },
    Operation {
        key: "add-tag-to-task",
        title: "Tag a task",
        description: "Puts a tag of the task's space on the task, by the tag's name.",
        effect: DeclaredAction::Declared(ActionClass::Write),
        verb: Verb::Post,
        path: &[
            Segment::Fixed("task"),
            Segment::Input("task"),
            Segment::Fixed("tag"),
            Segment::Input("tag"),
        ],
        fields: &[
            TASK,
            Field::required(
                "tag",
                Kind::Text,
                Place::Path,
                "The tag's name, as the task's space knows it.",
            )
            .example("billing"),
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[(
            "status",
            "The status ClickUp answered with, 200 when the tag was put on.",
        )],
    },
    Operation {
        key: "comment-on-task",
        title: "Comment on a task",
        description: "Adds a comment to a task, which notifies the people watching it, optionally assigning the comment to someone.",
        effect: DeclaredAction::Declared(ActionClass::Communicate),
        verb: Verb::Post,
        path: &[
            Segment::Fixed("task"),
            Segment::Input("task"),
            Segment::Fixed("comment"),
        ],
        fields: &[
            TASK,
            Field::required(
                "text",
                Kind::Text,
                Place::Body,
                "The comment's text, as plain text.",
            )
            .sent_as("comment_text")
            .asked_with(Ask::LongText),
            Field::optional(
                "assignee",
                Kind::Count,
                Place::Body,
                "The person the comment is assigned to, by the numeric id list-members gives back.",
            )
            .more_options(),
        ],
        fixed: &[("notify_all", Fixed::Flag(false))],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            ("json.id", "The comment's id."),
            (
                "status",
                "The status ClickUp answered with, 200 when the comment was added.",
            ),
        ],
    },
    Operation {
        key: "delete-task",
        title: "Delete a task",
        description: "Deletes a task, with its comments and subtasks.",
        effect: DeclaredAction::Declared(ActionClass::Delete),
        verb: Verb::Delete,
        path: ONE_TASK,
        fields: &[TASK],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[(
            "status",
            "The status ClickUp answered with, 204 when the task was deleted.",
        )],
    },
];
