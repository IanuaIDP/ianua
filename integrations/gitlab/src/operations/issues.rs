//! Issues: listing and reading them, opening, editing, closing and
//! reopening one, commenting and labelling.

use ianua_domain::domains::workflows::integration::form::Tone;
use ianua_domain::types::{ActionClass, DeclaredAction};
use ianua_integration::form::{Ask, ChoiceText};
use ianua_integration::rest::operation::{
    Field, Fixed, Kind, Operation, Place, Segment, Shape, Verb,
};

use crate::operations::{LABELS, LIMIT, PROJECT};

/// The path of a project's issues.
const ISSUES: &[Segment] = &[
    Segment::Fixed("projects"),
    Segment::Input("project"),
    Segment::Fixed("issues"),
];

/// The path of one issue.
const ONE_ISSUE: &[Segment] = &[
    Segment::Fixed("projects"),
    Segment::Input("project"),
    Segment::Fixed("issues"),
    Segment::Input("issue"),
];

/// The number of an issue in its project.
const ISSUE: Field = Field::required(
    "issue",
    Kind::Count,
    Place::Path,
    "The issue's number in the project, such as an earlier step's json.iid.",
);

/// What reading or changing one issue gives back.
const ISSUE_OUTPUTS: &[(&str, &str)] = &[
    ("json.iid", "The issue's number in the project."),
    ("json.state", "Whether the issue is opened or closed."),
    ("json.title", "The issue's title."),
    ("json.labels", "The labels on the issue."),
    ("json.web_url", "The address of the issue's page."),
    ("status", "The status GitLab answered with."),
];

/// Every issue operation.
pub(crate) const OPERATIONS: &[Operation] = &[
    Operation {
        key: "list-issues",
        title: "List issues",
        description: "Lists a project's issues, newest first, optionally narrowed by state, labels and words they contain.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Get,
        path: ISSUES,
        fields: &[
            PROJECT,
            Field::optional(
                "state",
                Kind::Text,
                Place::Query,
                "Which to list: opened, closed or all; all when not given.",
            )
            .asked_with(Ask::Choices(&[
                ChoiceText {
                    value: "opened",
                    label: "Open",
                    tone: Tone::Success,
                },
                ChoiceText {
                    value: "closed",
                    label: "Closed",
                    tone: Tone::Neutral,
                },
                ChoiceText {
                    value: "all",
                    label: "All",
                    tone: Tone::Info,
                },
            ])),
            Field::optional(
                "labels",
                Kind::TextList,
                Place::Query,
                "Only issues carrying every one of these labels.",
            )
            .asked_with(Ask::MultiPicker(LABELS)),
            Field::optional(
                "search",
                Kind::Text,
                Place::Query,
                "Only issues whose title or text holds these words.",
            )
            .more_options(),
            LIMIT,
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            (
                "json",
                "The issues, each with its iid, title, state, labels and web_url.",
            ),
            ("status", "The status GitLab answered with."),
        ],
    },
    Operation {
        key: "get-issue",
        title: "Get an issue",
        description: "Reads one issue: its title, text, state, labels and assignees.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Get,
        path: ONE_ISSUE,
        fields: &[PROJECT, ISSUE],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            ("json.title", "The issue's title."),
            ("json.description", "The issue's text."),
            ("json.state", "Whether the issue is opened or closed."),
            ("json.labels", "The labels on the issue."),
            ("json.assignees", "The people the issue is assigned to."),
            ("json.web_url", "The address of the issue's page."),
            ("status", "The status GitLab answered with."),
        ],
    },
    Operation {
        key: "create-issue",
        title: "Open an issue",
        description: "Opens an issue in a GitLab project, as the account's token allows.",
        effect: DeclaredAction::Declared(ActionClass::Write),
        verb: Verb::Post,
        path: ISSUES,
        fields: &[
            PROJECT,
            Field::required("title", Kind::Text, Place::Body, "The issue's title.")
                .example("Login fails on Safari"),
            Field::optional(
                "description",
                Kind::Text,
                Place::Body,
                "The issue's text, in Markdown.",
            )
            .asked_with(Ask::LongText),
            Field::optional(
                "labels",
                Kind::TextList,
                Place::Body,
                "Labels to put on the issue, each by its name.",
            )
            .asked_with(Ask::MultiPicker(LABELS)),
            Field::optional(
                "confidential",
                Kind::Flag,
                Place::Body,
                "Whether only project members may see it.",
            )
            .more_options(),
            Field::optional(
                "due_date",
                Kind::Text,
                Place::Body,
                "When it is due, as a date such as 2026-12-01.",
            )
            .example("2026-12-01")
            .more_options(),
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            (
                "json.iid",
                "The new issue's number in the project, which a comment names.",
            ),
            ("json.web_url", "The address of the issue's page."),
            (
                "status",
                "The status GitLab answered with, 201 when the issue was opened.",
            ),
        ],
    },
    Operation {
        key: "update-issue",
        title: "Edit an issue",
        description: "Changes an issue's title or text; what is not given stays as it was.",
        effect: DeclaredAction::Declared(ActionClass::Write),
        verb: Verb::Put,
        path: ONE_ISSUE,
        fields: &[
            PROJECT,
            ISSUE,
            Field::optional("title", Kind::Text, Place::Body, "The issue's new title."),
            Field::optional(
                "description",
                Kind::Text,
                Place::Body,
                "The issue's new text, in Markdown.",
            )
            .asked_with(Ask::LongText),
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: ISSUE_OUTPUTS,
    },
    Operation {
        key: "close-issue",
        title: "Close an issue",
        description: "Closes an open issue.",
        effect: DeclaredAction::Declared(ActionClass::Write),
        verb: Verb::Put,
        path: ONE_ISSUE,
        fields: &[PROJECT, ISSUE],
        fixed: &[("state_event", Fixed::Text("close"))],
        query: &[],
        shape: Shape::Object,
        outputs: ISSUE_OUTPUTS,
    },
    Operation {
        key: "reopen-issue",
        title: "Reopen an issue",
        description: "Opens a closed issue again.",
        effect: DeclaredAction::Declared(ActionClass::Write),
        verb: Verb::Put,
        path: ONE_ISSUE,
        fields: &[PROJECT, ISSUE],
        fixed: &[("state_event", Fixed::Text("reopen"))],
        query: &[],
        shape: Shape::Object,
        outputs: ISSUE_OUTPUTS,
    },
    Operation {
        key: "comment-on-issue",
        title: "Comment on an issue",
        description: "Adds a comment to an issue, which notifies everyone following it.",
        effect: DeclaredAction::Declared(ActionClass::Communicate),
        verb: Verb::Post,
        path: &[
            Segment::Fixed("projects"),
            Segment::Input("project"),
            Segment::Fixed("issues"),
            Segment::Input("issue"),
            Segment::Fixed("notes"),
        ],
        fields: &[
            PROJECT,
            ISSUE,
            Field::required(
                "body",
                Kind::Text,
                Place::Body,
                "The comment's text, in Markdown.",
            )
            .asked_with(Ask::LongText),
            Field::optional(
                "internal",
                Kind::Flag,
                Place::Body,
                "Whether only project members may see the comment.",
            )
            .more_options(),
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            ("json.id", "The comment's id."),
            ("json.body", "The comment's text as GitLab kept it."),
            (
                "status",
                "The status GitLab answered with, 201 when the comment was added.",
            ),
        ],
    },
    Operation {
        key: "add-labels",
        title: "Add labels",
        description: "Puts labels on an issue, keeping those it has.",
        effect: DeclaredAction::Declared(ActionClass::Write),
        verb: Verb::Put,
        path: ONE_ISSUE,
        fields: &[
            PROJECT,
            ISSUE,
            Field::required(
                "labels",
                Kind::TextList,
                Place::Body,
                "The labels to add, each by its name.",
            )
            .sent_as("add_labels")
            .asked_with(Ask::MultiPicker(LABELS)),
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: ISSUE_OUTPUTS,
    },
];
