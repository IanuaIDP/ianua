//! Issues: reading and searching them, opening, editing, moving,
//! assigning, commenting on and archiving one.

use ianua_domain::domains::workflows::integration::form::Tone;
use ianua_domain::types::{ActionClass, DeclaredAction};
use ianua_integration::form::{Ask, ChoiceText};
use ianua_integration::rest::operation::{Field, Fixed, Kind, Operation, Place, Shape, Verb};

use crate::operations::{
    DOCUMENT, GRAPHQL, ISSUE, ISSUE_TEAM, LABELS, LIMIT, PEOPLE, PICKING_TEAM, PROJECTS, STATES,
    TEAMS,
};

/// Reading one issue.
const GET_ISSUE: &str = "query Issue($issue: String!) { \
    issue(id: $issue) { id identifier title description url priority priorityLabel dueDate \
    state { id name type } assignee { id name } team { id key name } labels { nodes { id name } } } }";

/// Searching issues by their words.
const SEARCH_ISSUES: &str = "query SearchIssues($term: String!, $team: String, $first: Int) { \
    searchIssues(term: $term, teamId: $team, first: $first) { \
    nodes { id identifier title url priority state { name } assignee { name } } } }";

/// Opening an issue.
const CREATE_ISSUE: &str = "mutation IssueCreate($input: IssueCreateInput!) { \
    issueCreate(input: $input) { success issue { id identifier title url state { name } } } }";

/// Changing an issue, used for editing, moving and assigning it.
const UPDATE_ISSUE: &str = "mutation IssueUpdate($issue: String!, $input: IssueUpdateInput!) { \
    issueUpdate(id: $issue, input: $input) { success issue { id identifier title url \
    state { name } assignee { name } } } }";

/// Commenting on an issue.
const CREATE_COMMENT: &str = "mutation CommentCreate($input: CommentCreateInput!) { \
    commentCreate(input: $input) { success comment { id url } } }";

/// Archiving an issue.
const ARCHIVE_ISSUE: &str = "mutation IssueArchive($issue: String!) { \
    issueArchive(id: $issue) { success } }";

/// What changing one issue gives back, under the mutation `issueUpdate`.
const UPDATED_OUTPUTS: &[(&str, &str)] = &[
    (
        "json.data.issueUpdate.issue.identifier",
        "The issue's identifier, such as ENG-123.",
    ),
    ("json.data.issueUpdate.issue.title", "The issue's title."),
    (
        "json.data.issueUpdate.issue.state.name",
        "The issue's state, such as In Progress.",
    ),
    (
        "json.data.issueUpdate.issue.assignee.name",
        "Who the issue is assigned to.",
    ),
    (
        "json.data.issueUpdate.issue.url",
        "The address of the issue's page.",
    ),
];

/// How urgent an issue is, in Linear's numbers.
const PRIORITIES: &[ChoiceText] = &[
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
        label: "Medium",
        tone: Tone::Info,
    },
    ChoiceText {
        value: "4",
        label: "Low",
        tone: Tone::Neutral,
    },
];

/// An issue's priority, inside the input.
const PRIORITY: Field = Field::optional(
    "priority",
    Kind::Count,
    Place::Body,
    "How urgent it is: 1 urgent, 2 high, 3 medium or 4 low.",
)
.sent_as("variables.input.priority")
.asked_with(Ask::Choices(PRIORITIES));

/// An issue's due date, inside the input.
const DUE_DATE: Field = Field::optional(
    "due_date",
    Kind::Text,
    Place::Body,
    "When it is due, as a date such as 2026-12-01.",
)
.sent_as("variables.input.dueDate")
.example("2026-12-01")
.more_options();

/// Every issue operation.
pub(crate) const OPERATIONS: &[Operation] = &[
    Operation {
        key: "get-issue",
        title: "Get an issue",
        description: "Reads one issue: its title, description, state, priority, assignee, team and labels.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Post,
        path: GRAPHQL,
        fields: &[ISSUE],
        fixed: &[(DOCUMENT, Fixed::Text(GET_ISSUE))],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            ("json.data.issue.id", "The issue's id."),
            (
                "json.data.issue.identifier",
                "The issue's identifier, such as ENG-123.",
            ),
            ("json.data.issue.title", "The issue's title."),
            (
                "json.data.issue.description",
                "The issue's description, in Markdown.",
            ),
            (
                "json.data.issue.state.name",
                "The issue's state, such as Todo.",
            ),
            (
                "json.data.issue.priorityLabel",
                "The issue's priority, such as High.",
            ),
            (
                "json.data.issue.assignee.name",
                "Who the issue is assigned to.",
            ),
            (
                "json.data.issue.team.key",
                "The key of the issue's team, such as ENG.",
            ),
            ("json.data.issue.labels.nodes", "The labels on the issue."),
            ("json.data.issue.url", "The address of the issue's page."),
        ],
    },
    Operation {
        key: "search-issues",
        title: "Search issues",
        description: "Finds issues whose title, description or identifier match some words, optionally in one team.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Post,
        path: GRAPHQL,
        fields: &[
            Field::required("term", Kind::Text, Place::Body, "The words to look for.")
                .sent_as("variables.term")
                .example("login"),
            Field::optional(
                "team",
                Kind::Text,
                Place::Body,
                "Only issues in this team, by its id; every team when left out.",
            )
            .sent_as("variables.team")
            .asked_with(Ask::Picker(TEAMS))
            .more_options(),
            LIMIT,
        ],
        fixed: &[(DOCUMENT, Fixed::Text(SEARCH_ISSUES))],
        query: &[],
        shape: Shape::Object,
        outputs: &[(
            "json.data.searchIssues.nodes",
            "The issues found, each with its identifier, title, state, assignee and address.",
        )],
    },
    Operation {
        key: "create-issue",
        title: "Create an issue",
        description: "Creates an issue in a Linear team, as the account's API key allows.",
        effect: DeclaredAction::Declared(ActionClass::Write),
        verb: Verb::Post,
        path: GRAPHQL,
        fields: &[
            ISSUE_TEAM,
            Field::required("title", Kind::Text, Place::Body, "The issue's title.")
                .sent_as("variables.input.title")
                .example("Login fails on Safari"),
            Field::optional(
                "description",
                Kind::Text,
                Place::Body,
                "The issue's description, in Markdown.",
            )
            .sent_as("variables.input.description")
            .asked_with(Ask::LongText),
            Field::optional(
                "state",
                Kind::Text,
                Place::Body,
                "The state it starts in, by its id; the team's first state when left out.",
            )
            .sent_as("variables.input.stateId")
            .asked_with(Ask::Picker(STATES)),
            Field::optional(
                "labels",
                Kind::TextList,
                Place::Body,
                "Labels to put on the issue, each by its id.",
            )
            .sent_as("variables.input.labelIds")
            .asked_with(Ask::MultiPicker(LABELS)),
            PRIORITY,
            Field::optional(
                "assignee",
                Kind::Text,
                Place::Body,
                "Who to assign it to, by their id.",
            )
            .sent_as("variables.input.assigneeId")
            .asked_with(Ask::Picker(PEOPLE))
            .more_options(),
            Field::optional(
                "project",
                Kind::Text,
                Place::Body,
                "The project it belongs to, by its id.",
            )
            .sent_as("variables.input.projectId")
            .asked_with(Ask::Picker(PROJECTS))
            .more_options(),
            DUE_DATE,
        ],
        fixed: &[(DOCUMENT, Fixed::Text(CREATE_ISSUE))],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            ("json.data.issueCreate.issue.id", "The new issue's id."),
            (
                "json.data.issueCreate.issue.identifier",
                "The new issue's identifier, such as ENG-123, which later steps name it by.",
            ),
            (
                "json.data.issueCreate.issue.state.name",
                "The state it started in.",
            ),
            (
                "json.data.issueCreate.issue.url",
                "The address of the issue's page.",
            ),
        ],
    },
    Operation {
        key: "update-issue",
        title: "Edit an issue",
        description: "Changes an issue's title, description, priority or due date, or adds labels; what is not given stays as it was.",
        effect: DeclaredAction::Declared(ActionClass::Write),
        verb: Verb::Post,
        path: GRAPHQL,
        fields: &[
            ISSUE,
            Field::optional("title", Kind::Text, Place::Body, "The issue's new title.")
                .sent_as("variables.input.title"),
            Field::optional(
                "description",
                Kind::Text,
                Place::Body,
                "The issue's new description, in Markdown.",
            )
            .sent_as("variables.input.description")
            .asked_with(Ask::LongText),
            PRIORITY,
            PICKING_TEAM,
            Field::optional(
                "labels",
                Kind::TextList,
                Place::Body,
                "Labels to add, each by its id; the labels it has stay.",
            )
            .sent_as("variables.input.addedLabelIds")
            .asked_with(Ask::MultiPicker(LABELS))
            .more_options(),
            DUE_DATE,
        ],
        fixed: &[(DOCUMENT, Fixed::Text(UPDATE_ISSUE))],
        query: &[],
        shape: Shape::Object,
        outputs: UPDATED_OUTPUTS,
    },
    Operation {
        key: "move-issue",
        title: "Move an issue",
        description: "Moves an issue to another state of its team, such as In Progress or Done; naming another team moves it there too.",
        effect: DeclaredAction::Declared(ActionClass::Write),
        verb: Verb::Post,
        path: GRAPHQL,
        fields: &[
            ISSUE,
            ISSUE_TEAM,
            Field::required(
                "state",
                Kind::Text,
                Place::Body,
                "The state to move it to, by its id, one of the team's.",
            )
            .sent_as("variables.input.stateId")
            .asked_with(Ask::Picker(STATES)),
        ],
        fixed: &[(DOCUMENT, Fixed::Text(UPDATE_ISSUE))],
        query: &[],
        shape: Shape::Object,
        outputs: UPDATED_OUTPUTS,
    },
    Operation {
        key: "assign-issue",
        title: "Assign an issue",
        description: "Assigns an issue to one person in the workspace, in place of whoever had it.",
        effect: DeclaredAction::Declared(ActionClass::Write),
        verb: Verb::Post,
        path: GRAPHQL,
        fields: &[
            ISSUE,
            Field::required(
                "assignee",
                Kind::Text,
                Place::Body,
                "Who to assign it to, by their id.",
            )
            .sent_as("variables.input.assigneeId")
            .asked_with(Ask::Picker(PEOPLE)),
        ],
        fixed: &[(DOCUMENT, Fixed::Text(UPDATE_ISSUE))],
        query: &[],
        shape: Shape::Object,
        outputs: UPDATED_OUTPUTS,
    },
    Operation {
        key: "comment-on-issue",
        title: "Comment on an issue",
        description: "Adds a comment to an issue; the people following it are notified.",
        effect: DeclaredAction::Declared(ActionClass::Communicate),
        verb: Verb::Post,
        path: GRAPHQL,
        fields: &[
            ISSUE.sent_as("variables.input.issueId"),
            Field::required(
                "body",
                Kind::Text,
                Place::Body,
                "What the comment says, in Markdown.",
            )
            .sent_as("variables.input.body")
            .asked_with(Ask::LongText),
        ],
        fixed: &[(DOCUMENT, Fixed::Text(CREATE_COMMENT))],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            ("json.data.commentCreate.comment.id", "The comment's id."),
            (
                "json.data.commentCreate.comment.url",
                "The address of the comment.",
            ),
        ],
    },
    Operation {
        key: "archive-issue",
        title: "Archive an issue",
        description: "Archives an issue, taking it out of the team's views; it can be brought back from the archive in Linear.",
        effect: DeclaredAction::Declared(ActionClass::Write),
        verb: Verb::Post,
        path: GRAPHQL,
        fields: &[ISSUE],
        fixed: &[(DOCUMENT, Fixed::Text(ARCHIVE_ISSUE))],
        query: &[],
        shape: Shape::Object,
        outputs: &[(
            "json.data.issueArchive.success",
            "Whether Linear archived the issue.",
        )],
    },
];
