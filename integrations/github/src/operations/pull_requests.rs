//! Pull requests: reading one, opening one, merging it, and asking people
//! to review it.

use ianua_domain::types::{ActionClass, DeclaredAction};
use ianua_integration::form::Ask;
use ianua_integration::rest::operation::{Field, Kind, Operation, Place, Segment, Shape, Verb};

use crate::operations::{BRANCHES, ISSUE, REPOSITORY};

/// The path of one pull request.
const ONE_PULL: &[Segment] = &[
    Segment::Fixed("repos"),
    Segment::Pair("repository"),
    Segment::Fixed("pulls"),
    Segment::Input("issue"),
];

/// Every pull request operation.
pub(crate) const OPERATIONS: &[Operation] = &[
    Operation {
        key: "get-pull-request",
        title: "Get a pull request",
        description: "Reads one pull request: its title, branches, state and whether it can be merged.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Get,
        path: ONE_PULL,
        fields: &[REPOSITORY, ISSUE],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            ("json.title", "The pull request's title."),
            ("json.state", "Whether it is open or closed."),
            ("json.merged", "Whether it was merged."),
            (
                "json.mergeable",
                "Whether GitHub can merge it, or null while it is still working that out.",
            ),
            ("json.head.ref", "The branch it brings in."),
            ("json.base.ref", "The branch it goes into."),
            ("status", "The status GitHub answered with."),
        ],
    },
    Operation {
        key: "create-pull-request",
        title: "Open a pull request",
        description: "Opens a pull request bringing one branch into another.",
        effect: DeclaredAction::Declared(ActionClass::Write),
        verb: Verb::Post,
        path: &[
            Segment::Fixed("repos"),
            Segment::Pair("repository"),
            Segment::Fixed("pulls"),
        ],
        fields: &[
            REPOSITORY,
            Field::required(
                "title",
                Kind::Text,
                Place::Body,
                "The pull request's title.",
            ),
            Field::required(
                "head",
                Kind::Text,
                Place::Body,
                "The branch with the changes, such as fix-login.",
            )
            .asked_with(Ask::Picker(BRANCHES)),
            Field::required(
                "base",
                Kind::Text,
                Place::Body,
                "The branch to bring them into, such as main.",
            )
            .asked_with(Ask::Picker(BRANCHES)),
            Field::optional(
                "body",
                Kind::Text,
                Place::Body,
                "The pull request's text, in Markdown.",
            )
            .asked_with(Ask::LongText),
            Field::optional(
                "draft",
                Kind::Flag,
                Place::Body,
                "Whether it opens as a draft, not yet ready for review.",
            ),
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            (
                "json.number",
                "The new pull request's number, which merging and reviewing name.",
            ),
            ("json.html_url", "The address of the pull request's page."),
            (
                "status",
                "The status GitHub answered with, 201 when it was opened.",
            ),
        ],
    },
    Operation {
        key: "merge-pull-request",
        title: "Merge a pull request",
        description: "Merges a pull request into its base branch, as a merge commit, a squash or a rebase.",
        effect: DeclaredAction::Declared(ActionClass::Write),
        verb: Verb::Put,
        path: &[
            Segment::Fixed("repos"),
            Segment::Pair("repository"),
            Segment::Fixed("pulls"),
            Segment::Input("issue"),
            Segment::Fixed("merge"),
        ],
        fields: &[
            REPOSITORY,
            ISSUE,
            Field::optional(
                "method",
                Kind::Text,
                Place::Body,
                "How to merge: merge, squash or rebase; merge when not given.",
            )
            .sent_as("merge_method"),
            Field::optional(
                "commit_title",
                Kind::Text,
                Place::Body,
                "The title of the merge commit.",
            ),
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            ("json.merged", "Whether it was merged."),
            ("json.sha", "The commit the merge made."),
            (
                "status",
                "The status GitHub answered with; 405 when it cannot be merged.",
            ),
        ],
    },
    Operation {
        key: "request-reviewers",
        title: "Ask for a review",
        description: "Asks people to review a pull request, which notifies them.",
        effect: DeclaredAction::Declared(ActionClass::Communicate),
        verb: Verb::Post,
        path: &[
            Segment::Fixed("repos"),
            Segment::Pair("repository"),
            Segment::Fixed("pulls"),
            Segment::Input("issue"),
            Segment::Fixed("requested_reviewers"),
        ],
        fields: &[
            REPOSITORY,
            ISSUE,
            Field::required(
                "reviewers",
                Kind::TextList,
                Place::Body,
                "The GitHub logins to ask.",
            ),
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            (
                "json.requested_reviewers",
                "Everyone now asked to review it.",
            ),
            (
                "status",
                "The status GitHub answered with, 201 when they were asked.",
            ),
        ],
    },
];
