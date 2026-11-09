//! Repositories: opening a pull request, and reading one.

use ianua_domain::types::{ActionClass, DeclaredAction};
use ianua_integration::rest::operation::{Field, Kind, Operation, Place, Segment, Shape, Verb};

use crate::operations::{API_VERSION, PROJECT};

/// The repository a step acts in, in the path.
const REPOSITORY: Field = Field::required(
    "repository",
    Kind::Text,
    Place::Path,
    "The repository's name or id.",
);

/// Every repository operation.
pub(crate) const OPERATIONS: &[Operation] = &[
    Operation {
        key: "create-pull-request",
        title: "Open a pull request",
        description: "Opens a pull request bringing one branch into another.",
        effect: DeclaredAction::Declared(ActionClass::Write),
        verb: Verb::Post,
        path: &[
            Segment::Input("project"),
            Segment::Fixed("_apis"),
            Segment::Fixed("git"),
            Segment::Fixed("repositories"),
            Segment::Input("repository"),
            Segment::Fixed("pullrequests"),
        ],
        fields: &[
            PROJECT,
            REPOSITORY,
            Field::required(
                "source",
                Kind::Text,
                Place::Body,
                "The branch with the changes, such as refs/heads/fix-login.",
            )
            .sent_as("sourceRefName"),
            Field::required(
                "target",
                Kind::Text,
                Place::Body,
                "The branch to bring them into, such as refs/heads/main.",
            )
            .sent_as("targetRefName"),
            Field::required(
                "title",
                Kind::Text,
                Place::Body,
                "The pull request's title.",
            ),
            Field::optional(
                "description",
                Kind::Text,
                Place::Body,
                "The pull request's description, in Markdown.",
            ),
            Field::optional(
                "draft",
                Kind::Flag,
                Place::Body,
                "Whether it opens as a draft.",
            )
            .sent_as("isDraft"),
        ],
        fixed: &[],
        query: API_VERSION,
        shape: Shape::Object,
        outputs: &[
            (
                "json.pullRequestId",
                "The new pull request's number, which reading it names.",
            ),
            ("json.status", "Its status, active when opened."),
        ],
    },
    Operation {
        key: "get-pull-request",
        title: "Get a pull request",
        description: "Reads a pull request: its status and whether it can be merged.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Get,
        path: &[
            Segment::Input("project"),
            Segment::Fixed("_apis"),
            Segment::Fixed("git"),
            Segment::Fixed("repositories"),
            Segment::Input("repository"),
            Segment::Fixed("pullrequests"),
            Segment::Input("pull_request"),
        ],
        fields: &[
            PROJECT,
            REPOSITORY,
            Field::required(
                "pull_request",
                Kind::Count,
                Place::Path,
                "The pull request's number, such as an earlier step's json.pullRequestId.",
            ),
        ],
        fixed: &[],
        query: API_VERSION,
        shape: Shape::Object,
        outputs: &[
            ("json.status", "Its status: active, completed or abandoned."),
            (
                "json.mergeStatus",
                "Whether it can be merged, such as succeeded or conflicts.",
            ),
        ],
    },
];
