//! Issues: opening, reading, editing and deleting one, commenting, moving
//! it through its workflow, assigning it, and searching with JQL.

use ianua_domain::types::{ActionClass, DeclaredAction};
use ianua_integration::form::{Ask, PickerText};
use ianua_integration::rest::operation::{Field, Kind, Operation, Place, Segment, Shape, Verb};

use crate::operations::ISSUE;

/// The path of one issue.
const ONE_ISSUE: &[Segment] = &[Segment::Fixed("issue"), Segment::Input("issue")];

/// Every issue operation.
pub(crate) const OPERATIONS: &[Operation] = &[
    Operation {
        key: "create-issue",
        title: "Create an issue",
        description: "Creates an issue in a Jira project, of a type the project has, such as Task or Bug.",
        effect: DeclaredAction::Declared(ActionClass::Write),
        verb: Verb::Post,
        path: &[Segment::Fixed("issue")],
        fields: &[
            Field::required("project", Kind::Text, Place::Body, "The project's key, such as OPS.")
                .sent_as("fields.project.key"),
            Field::required("type", Kind::Text, Place::Body, "The issue type's name, such as Task or Bug.")
                .sent_as("fields.issuetype.name"),
            Field::required("summary", Kind::Text, Place::Body, "The issue's summary line.")
                .sent_as("fields.summary"),
            Field::optional("description", Kind::Text, Place::Body, "The issue's description, in Jira's wiki markup.")
                .sent_as("fields.description")
                .asked_with(Ask::LongText),
            Field::optional("labels", Kind::TextList, Place::Body, "Labels to put on the issue.")
                .sent_as("fields.labels"),
            Field::optional("assignee", Kind::Text, Place::Body, "The account id of the person to assign it to, such as an earlier step's json.accountId.")
                .sent_as("fields.assignee.accountId"),
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            ("json.key", "The new issue's key, such as OPS-42, which later steps name."),
            ("json.id", "The new issue's id."),
            ("status", "The status Jira answered with, 201 when the issue was created."),
        ],
    },
    Operation {
        key: "get-issue",
        title: "Get an issue",
        description: "Reads one issue: its summary, status, assignee and other fields.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Get,
        path: ONE_ISSUE,
        fields: &[
            ISSUE,
            Field::optional("fields", Kind::Text, Place::Query, "Only these fields, separated by commas, such as summary,status; every field when not given."),
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            ("json.key", "The issue's key."),
            ("json.fields.summary", "The issue's summary line."),
            ("json.fields.status.name", "The issue's status, such as In Progress."),
            ("status", "The status Jira answered with."),
        ],
    },
    Operation {
        key: "update-issue",
        title: "Edit an issue",
        description: "Changes an issue's summary, description or labels; what is not given stays as it was.",
        effect: DeclaredAction::Declared(ActionClass::Write),
        verb: Verb::Put,
        path: ONE_ISSUE,
        fields: &[
            ISSUE,
            Field::optional("summary", Kind::Text, Place::Body, "The issue's new summary line.")
                .sent_as("fields.summary"),
            Field::optional("description", Kind::Text, Place::Body, "The issue's new description, in Jira's wiki markup.")
                .sent_as("fields.description"),
            Field::optional("labels", Kind::TextList, Place::Body, "The issue's labels from now on, replacing those it had.")
                .sent_as("fields.labels"),
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[("status", "The status Jira answered with, 204 when the issue was changed.")],
    },
    Operation {
        key: "delete-issue",
        title: "Delete an issue",
        description: "Deletes an issue for good, with its comments and history.",
        effect: DeclaredAction::Declared(ActionClass::Delete),
        verb: Verb::Delete,
        path: ONE_ISSUE,
        fields: &[ISSUE],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[("status", "The status Jira answered with, 204 when the issue was deleted.")],
    },
    Operation {
        key: "comment-on-issue",
        title: "Comment on an issue",
        description: "Adds a comment to an issue, which notifies everyone watching it.",
        effect: DeclaredAction::Declared(ActionClass::Communicate),
        verb: Verb::Post,
        path: &[Segment::Fixed("issue"), Segment::Input("issue"), Segment::Fixed("comment")],
        fields: &[
            ISSUE,
            Field::required("body", Kind::Text, Place::Body, "The comment's text, in Jira's wiki markup."),
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            ("json.id", "The comment's id."),
            ("status", "The status Jira answered with, 201 when the comment was added."),
        ],
    },
    Operation {
        key: "list-transitions",
        title: "List an issue's next statuses",
        description: "Lists the transitions an issue can take from its status now, each with the id moving it needs.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Get,
        path: &[Segment::Fixed("issue"), Segment::Input("issue"), Segment::Fixed("transitions")],
        fields: &[ISSUE],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[("json.transitions", "The transitions, each with its id and the status it leads to.")],
    },
    Operation {
        key: "transition-issue",
        title: "Move an issue to another status",
        description: "Moves an issue along its workflow by a transition it can take now, such as Start Progress or Done.",
        effect: DeclaredAction::Declared(ActionClass::Write),
        verb: Verb::Post,
        path: &[Segment::Fixed("issue"), Segment::Input("issue"), Segment::Fixed("transitions")],
        fields: &[
            ISSUE,
            Field::required("transition", Kind::Text, Place::Body, "The transition's id, from listing the issue's next statuses.")
                .sent_as("transition.id")
                .asked_with(Ask::Picker(PickerText {
                    filled_by: "list-transitions",
                    items_at: "json.transitions",
                    value_at: "id",
                    label_at: "name",
                    depends_on: Some("issue"),
                })),
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[("status", "The status Jira answered with, 204 when the issue moved.")],
    },
    Operation {
        key: "assign-issue",
        title: "Assign an issue",
        description: "Assigns an issue to a person, by their account id.",
        effect: DeclaredAction::Declared(ActionClass::Write),
        verb: Verb::Put,
        path: &[Segment::Fixed("issue"), Segment::Input("issue"), Segment::Fixed("assignee")],
        fields: &[
            ISSUE,
            Field::required("assignee", Kind::Text, Place::Body, "The account id of the person, such as an earlier step's json.accountId.")
                .sent_as("accountId"),
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[("status", "The status Jira answered with, 204 when the issue was assigned.")],
    },
    Operation {
        key: "search-issues",
        title: "Search issues",
        description: "Finds issues with a JQL query, such as project = OPS AND status = \"To Do\".",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Get,
        path: &[Segment::Fixed("search"), Segment::Fixed("jql")],
        fields: &[
            Field::required("jql", Kind::Text, Place::Query, "The JQL query, bounded, such as project = OPS AND created >= -1d."),
            Field::optional("limit", Kind::Count, Place::Query, "How many issues to give back, at most 100.").sent_as("maxResults"),
            Field::optional("fields", Kind::Text, Place::Query, "Which fields each issue carries, separated by commas, such as summary,status."),
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[("json.issues", "The issues found, each with its key and the fields asked for.")],
    },
];
