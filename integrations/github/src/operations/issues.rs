//! Issues: reading and listing them, opening, editing, closing and
//! reopening one, commenting, labelling and assigning.

use ianua_domain::domains::workflows::integration::form::Tone;
use ianua_domain::types::{ActionClass, DeclaredAction};
use ianua_integration::form::{Ask, ChoiceText};
use ianua_integration::rest::operation::{
    Field, Fixed, Kind, Operation, Place, Segment, Shape, Verb,
};

use crate::operations::{ISSUE, LABELS, REPOSITORY};

/// The path of a repository's issues.
const ISSUES: &[Segment] = &[
    Segment::Fixed("repos"),
    Segment::Pair("repository"),
    Segment::Fixed("issues"),
];

/// The path of one issue.
const ONE_ISSUE: &[Segment] = &[
    Segment::Fixed("repos"),
    Segment::Pair("repository"),
    Segment::Fixed("issues"),
    Segment::Input("issue"),
];

/// What reading or changing one issue gives back.
const ISSUE_OUTPUTS: &[(&str, &str)] = &[
    ("json.number", "The issue's number in the repository."),
    ("json.state", "Whether the issue is open or closed."),
    ("json.title", "The issue's title."),
    ("json.html_url", "The address of the issue's page."),
    ("status", "The status GitHub answered with."),
];

/// Why an issue is closed, in GitHub's words.
const STATE_REASON: Field = Field::optional(
    "reason",
    Kind::Text,
    Place::Body,
    "Why it is closed: completed or not_planned.",
)
.sent_as("state_reason")
.asked_with(Ask::Choices(&[
    ChoiceText {
        value: "completed",
        label: "Completed",
        tone: Tone::Success,
    },
    ChoiceText {
        value: "not_planned",
        label: "Not planned",
        tone: Tone::Neutral,
    },
]));

/// Every issue operation.
pub(crate) const OPERATIONS: &[Operation] = &[
    Operation {
        key: "list-issues",
        title: "List issues",
        description: "Lists a repository's issues and pull requests, newest first, optionally narrowed by state and labels.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Get,
        path: ISSUES,
        fields: &[
            REPOSITORY,
            Field::optional(
                "state",
                Kind::Text,
                Place::Query,
                "Which to list: open, closed or all; open when not given.",
            )
            .asked_with(Ask::Choices(&[
                ChoiceText {
                    value: "open",
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
                "limit",
                Kind::Count,
                Place::Query,
                "How many to list, at most 100; 30 when not given.",
            )
            .sent_as("per_page")
            .more_options(),
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            (
                "json",
                "The issues, each with its number, title, state and labels.",
            ),
            ("status", "The status GitHub answered with."),
        ],
    },
    Operation {
        key: "get-issue",
        title: "Get an issue",
        description: "Reads one issue or pull request: its title, text, state, labels and assignees.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Get,
        path: ONE_ISSUE,
        fields: &[REPOSITORY, ISSUE],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            ("json.title", "The issue's title."),
            ("json.body", "The issue's text."),
            ("json.state", "Whether the issue is open or closed."),
            ("json.labels", "The labels on the issue."),
            ("json.assignees", "The people the issue is assigned to."),
            ("status", "The status GitHub answered with."),
        ],
    },
    Operation {
        key: "create-issue",
        title: "Open an issue",
        description: "Opens an issue in a GitHub repository, as the account's token allows.",
        effect: DeclaredAction::Declared(ActionClass::Write),
        verb: Verb::Post,
        path: ISSUES,
        fields: &[
            REPOSITORY,
            Field::required("title", Kind::Text, Place::Body, "The issue's title.")
                .example("Login fails on Safari"),
            Field::optional(
                "body",
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
                "assignees",
                Kind::TextList,
                Place::Body,
                "The GitHub logins to assign it to.",
            )
            .more_options(),
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            (
                "json.number",
                "The new issue's number in the repository, which a comment names.",
            ),
            ("json.html_url", "The address of the issue's page."),
            (
                "status",
                "The status GitHub answered with, 201 when the issue was opened.",
            ),
        ],
    },
    Operation {
        key: "update-issue",
        title: "Edit an issue",
        description: "Changes an issue's title or text; what is not given stays as it was.",
        effect: DeclaredAction::Declared(ActionClass::Write),
        verb: Verb::Patch,
        path: ONE_ISSUE,
        fields: &[
            REPOSITORY,
            ISSUE,
            Field::optional("title", Kind::Text, Place::Body, "The issue's new title."),
            Field::optional(
                "body",
                Kind::Text,
                Place::Body,
                "The issue's new text, in Markdown.",
            ),
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: ISSUE_OUTPUTS,
    },
    Operation {
        key: "close-issue",
        title: "Close an issue",
        description: "Closes an issue or pull request, saying why when the step gives a reason.",
        effect: DeclaredAction::Declared(ActionClass::Write),
        verb: Verb::Patch,
        path: ONE_ISSUE,
        fields: &[REPOSITORY, ISSUE, STATE_REASON],
        fixed: &[("state", Fixed::Text("closed"))],
        query: &[],
        shape: Shape::Object,
        outputs: ISSUE_OUTPUTS,
    },
    Operation {
        key: "reopen-issue",
        title: "Reopen an issue",
        description: "Opens a closed issue or pull request again.",
        effect: DeclaredAction::Declared(ActionClass::Write),
        verb: Verb::Patch,
        path: ONE_ISSUE,
        fields: &[REPOSITORY, ISSUE],
        fixed: &[("state", Fixed::Text("open"))],
        query: &[],
        shape: Shape::Object,
        outputs: ISSUE_OUTPUTS,
    },
    Operation {
        key: "comment-on-issue",
        title: "Comment on an issue",
        description: "Adds a comment to an issue or pull request, which notifies everyone watching it.",
        effect: DeclaredAction::Declared(ActionClass::Communicate),
        verb: Verb::Post,
        path: &[
            Segment::Fixed("repos"),
            Segment::Pair("repository"),
            Segment::Fixed("issues"),
            Segment::Input("issue"),
            Segment::Fixed("comments"),
        ],
        fields: &[
            REPOSITORY,
            ISSUE,
            Field::required(
                "body",
                Kind::Text,
                Place::Body,
                "The comment's text, in Markdown.",
            ),
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            ("json.id", "The comment's id, which removing it names."),
            ("json.html_url", "The address of the comment."),
            (
                "status",
                "The status GitHub answered with, 201 when the comment was added.",
            ),
        ],
    },
    Operation {
        key: "delete-comment",
        title: "Remove a comment",
        description: "Removes a comment from an issue or pull request for good.",
        effect: DeclaredAction::Declared(ActionClass::Delete),
        verb: Verb::Delete,
        path: &[
            Segment::Fixed("repos"),
            Segment::Pair("repository"),
            Segment::Fixed("issues"),
            Segment::Fixed("comments"),
            Segment::Input("comment"),
        ],
        fields: &[
            REPOSITORY,
            Field::required(
                "comment",
                Kind::Count,
                Place::Path,
                "The comment's id, such as an earlier step's json.id.",
            ),
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[(
            "status",
            "The status GitHub answered with, 204 when the comment was removed.",
        )],
    },
    Operation {
        key: "add-labels",
        title: "Add labels",
        description: "Puts labels on an issue or pull request, keeping those it has.",
        effect: DeclaredAction::Declared(ActionClass::Write),
        verb: Verb::Post,
        path: &[
            Segment::Fixed("repos"),
            Segment::Pair("repository"),
            Segment::Fixed("issues"),
            Segment::Input("issue"),
            Segment::Fixed("labels"),
        ],
        fields: &[
            REPOSITORY,
            ISSUE,
            Field::required(
                "labels",
                Kind::TextList,
                Place::Body,
                "The labels to add, each by its name.",
            )
            .asked_with(Ask::MultiPicker(LABELS)),
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            ("json", "Every label the issue now has."),
            ("status", "The status GitHub answered with."),
        ],
    },
    Operation {
        key: "remove-label",
        title: "Remove a label",
        description: "Takes one label off an issue or pull request.",
        effect: DeclaredAction::Declared(ActionClass::Write),
        verb: Verb::Delete,
        path: &[
            Segment::Fixed("repos"),
            Segment::Pair("repository"),
            Segment::Fixed("issues"),
            Segment::Input("issue"),
            Segment::Fixed("labels"),
            Segment::Input("label"),
        ],
        fields: &[
            REPOSITORY,
            ISSUE,
            Field::required("label", Kind::Text, Place::Path, "The label's name."),
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            ("json", "The labels the issue still has."),
            ("status", "The status GitHub answered with."),
        ],
    },
    Operation {
        key: "add-assignees",
        title: "Assign people",
        description: "Assigns people to an issue or pull request, keeping those already assigned.",
        effect: DeclaredAction::Declared(ActionClass::Write),
        verb: Verb::Post,
        path: &[
            Segment::Fixed("repos"),
            Segment::Pair("repository"),
            Segment::Fixed("issues"),
            Segment::Input("issue"),
            Segment::Fixed("assignees"),
        ],
        fields: &[
            REPOSITORY,
            ISSUE,
            Field::required(
                "assignees",
                Kind::TextList,
                Place::Body,
                "The GitHub logins to assign.",
            ),
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            ("json.assignees", "Everyone the issue is now assigned to."),
            ("status", "The status GitHub answered with."),
        ],
    },
];
