//! Merge requests: listing and reading them, opening one and merging it.

use ianua_domain::domains::workflows::integration::form::Tone;
use ianua_domain::types::{ActionClass, DeclaredAction};
use ianua_integration::form::{Ask, ChoiceText};
use ianua_integration::rest::operation::{Field, Kind, Operation, Place, Segment, Shape, Verb};

use crate::operations::{BRANCHES, LABELS, LIMIT, PROJECT};

/// The path of a project's merge requests.
const MERGE_REQUESTS: &[Segment] = &[
    Segment::Fixed("projects"),
    Segment::Input("project"),
    Segment::Fixed("merge_requests"),
];

/// The number of a merge request in its project.
const MERGE_REQUEST: Field = Field::required(
    "merge_request",
    Kind::Count,
    Place::Path,
    "The merge request's number in the project, such as an earlier step's json.iid.",
);

/// Every merge request operation.
pub(crate) const OPERATIONS: &[Operation] = &[
    Operation {
        key: "list-merge-requests",
        title: "List merge requests",
        description: "Lists a project's merge requests, newest first, optionally narrowed by state, labels and target branch.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Get,
        path: MERGE_REQUESTS,
        fields: &[
            PROJECT,
            Field::optional(
                "state",
                Kind::Text,
                Place::Query,
                "Which to list: opened, merged, closed or all; all when not given.",
            )
            .asked_with(Ask::Choices(&[
                ChoiceText {
                    value: "opened",
                    label: "Open",
                    tone: Tone::Success,
                },
                ChoiceText {
                    value: "merged",
                    label: "Merged",
                    tone: Tone::Info,
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
                "Only merge requests carrying every one of these labels.",
            )
            .asked_with(Ask::MultiPicker(LABELS)),
            Field::optional(
                "target_branch",
                Kind::Text,
                Place::Query,
                "Only merge requests going into this branch, such as main.",
            )
            .asked_with(Ask::Picker(BRANCHES))
            .more_options(),
            LIMIT,
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            (
                "json",
                "The merge requests, each with its iid, title, state, source_branch and target_branch.",
            ),
            ("status", "The status GitLab answered with."),
        ],
    },
    Operation {
        key: "get-merge-request",
        title: "Get a merge request",
        description: "Reads one merge request: its title, branches, state and whether it can be merged.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Get,
        path: &[
            Segment::Fixed("projects"),
            Segment::Input("project"),
            Segment::Fixed("merge_requests"),
            Segment::Input("merge_request"),
        ],
        fields: &[PROJECT, MERGE_REQUEST],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            ("json.title", "The merge request's title."),
            ("json.state", "Whether it is opened, merged or closed."),
            (
                "json.detailed_merge_status",
                "Whether GitLab can merge it, such as mergeable, or what stops it.",
            ),
            ("json.has_conflicts", "Whether its changes conflict."),
            ("json.source_branch", "The branch it brings in."),
            ("json.target_branch", "The branch it goes into."),
            ("json.web_url", "The address of its page."),
            ("status", "The status GitLab answered with."),
        ],
    },
    Operation {
        key: "create-merge-request",
        title: "Open a merge request",
        description: "Opens a merge request bringing one branch into another.",
        effect: DeclaredAction::Declared(ActionClass::Write),
        verb: Verb::Post,
        path: MERGE_REQUESTS,
        fields: &[
            PROJECT,
            Field::required(
                "title",
                Kind::Text,
                Place::Body,
                "The merge request's title; one starting with Draft: opens as a draft.",
            ),
            Field::required(
                "source_branch",
                Kind::Text,
                Place::Body,
                "The branch with the changes, such as fix-login.",
            )
            .asked_with(Ask::Picker(BRANCHES)),
            Field::required(
                "target_branch",
                Kind::Text,
                Place::Body,
                "The branch to bring them into, such as main.",
            )
            .asked_with(Ask::Picker(BRANCHES)),
            Field::optional(
                "description",
                Kind::Text,
                Place::Body,
                "The merge request's text, in Markdown.",
            )
            .asked_with(Ask::LongText),
            Field::optional(
                "labels",
                Kind::TextList,
                Place::Body,
                "Labels to put on it, each by its name.",
            )
            .asked_with(Ask::MultiPicker(LABELS)),
            Field::optional(
                "remove_source_branch",
                Kind::Flag,
                Place::Body,
                "Whether the source branch is deleted once it is merged.",
            )
            .more_options(),
            Field::optional(
                "squash",
                Kind::Flag,
                Place::Body,
                "Whether its commits are squashed into one when it is merged.",
            )
            .more_options(),
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            (
                "json.iid",
                "The new merge request's number, which merging names.",
            ),
            ("json.web_url", "The address of its page."),
            (
                "status",
                "The status GitLab answered with, 201 when it was opened.",
            ),
        ],
    },
    Operation {
        key: "merge-merge-request",
        title: "Merge a merge request",
        description: "Merges a merge request into its target branch, or sets it to merge once its pipeline passes.",
        effect: DeclaredAction::Declared(ActionClass::Write),
        verb: Verb::Put,
        path: &[
            Segment::Fixed("projects"),
            Segment::Input("project"),
            Segment::Fixed("merge_requests"),
            Segment::Input("merge_request"),
            Segment::Fixed("merge"),
        ],
        fields: &[
            PROJECT,
            MERGE_REQUEST,
            Field::optional(
                "squash",
                Kind::Flag,
                Place::Body,
                "Whether its commits are squashed into one.",
            ),
            Field::optional(
                "remove_source_branch",
                Kind::Flag,
                Place::Body,
                "Whether the source branch is deleted once merged.",
            )
            .sent_as("should_remove_source_branch"),
            Field::optional(
                "merge_commit_message",
                Kind::Text,
                Place::Body,
                "The message of the merge commit.",
            )
            .more_options(),
            Field::optional(
                "auto_merge",
                Kind::Flag,
                Place::Body,
                "Whether to wait and merge once its pipeline passes, instead of now.",
            )
            .more_options(),
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            ("json.state", "Whether it is merged now, or still opened."),
            ("json.merge_commit_sha", "The commit the merge made."),
            ("json.web_url", "The address of its page."),
            (
                "status",
                "The status GitLab answered with, 200 when it was merged; 405 or 422 when it cannot be.",
            ),
        ],
    },
];
