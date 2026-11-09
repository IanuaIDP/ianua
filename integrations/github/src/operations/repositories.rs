//! Repositories: reading one, a file in it and the commit a ref points to,
//! writing a file, publishing a release, deleting a branch, starting a
//! GitHub Actions workflow, and listing the repositories, labels and
//! branches the forms' pickers offer.

use ianua_domain::types::{ActionClass, DeclaredAction};
use ianua_integration::form::Ask;
use ianua_integration::rest::operation::{
    Field, Fixed, Kind, Operation, Place, Segment, Shape, Verb,
};

use crate::operations::{BRANCHES, REPOSITORY};

/// How many a listing gives at most, under GitHub's name.
const LIMIT: Field = Field::optional(
    "limit",
    Kind::Count,
    Place::Query,
    "How many to list, at most 100; 30 when not given.",
)
.sent_as("per_page")
.more_options();

/// Every repository operation.
pub(crate) const OPERATIONS: &[Operation] = &[
    Operation {
        key: "get-repository",
        title: "Get a repository",
        description: "Reads a repository: its description, default branch and whether it is private.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Get,
        path: &[Segment::Fixed("repos"), Segment::Pair("repository")],
        fields: &[REPOSITORY],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            ("json.full_name", "The repository's owner/name."),
            (
                "json.default_branch",
                "The branch new work starts from, such as main.",
            ),
            ("json.private", "Whether only some people may see it."),
            ("status", "The status GitHub answered with."),
        ],
    },
    Operation {
        key: "get-file",
        title: "Read a file",
        description: "Reads one file of a repository, at a branch, tag or commit when one is given.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Get,
        path: &[
            Segment::Fixed("repos"),
            Segment::Pair("repository"),
            Segment::Fixed("contents"),
            Segment::Slashed("path"),
        ],
        fields: &[
            REPOSITORY,
            Field::required(
                "path",
                Kind::Text,
                Place::Path,
                "The file's path in the repository, such as docs/README.md.",
            ),
            Field::optional(
                "ref",
                Kind::Text,
                Place::Query,
                "The branch, tag or commit to read it at; the default branch when not given.",
            ),
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            ("json.content", "The file's contents, in base64."),
            ("json.sha", "The version of the file read."),
            ("json.size", "The file's size in bytes."),
            (
                "status",
                "The status GitHub answered with; 404 when there is no such file.",
            ),
        ],
    },
    Operation {
        key: "get-commit",
        title: "Read a commit",
        description: "Reads the commit a branch, tag or commit points to now: its exact hash and message.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Get,
        path: &[
            Segment::Fixed("repos"),
            Segment::Pair("repository"),
            Segment::Fixed("commits"),
            Segment::Slashed("ref"),
        ],
        fields: &[
            REPOSITORY,
            Field::required(
                "ref",
                Kind::Text,
                Place::Path,
                "The branch, tag or commit, such as main.",
            )
            .asked_with(Ask::Picker(BRANCHES)),
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            ("json.sha", "The commit's full hash."),
            ("json.commit.message", "The commit's message."),
            (
                "status",
                "The status GitHub answered with; 404 or 422 when there is no such ref.",
            ),
        ],
    },
    Operation {
        key: "put-file",
        title: "Write a file",
        description: "Makes or replaces one file on a branch as a commit of its own. Replacing a file needs the version it replaces.",
        effect: DeclaredAction::Declared(ActionClass::Write),
        verb: Verb::Put,
        path: &[
            Segment::Fixed("repos"),
            Segment::Pair("repository"),
            Segment::Fixed("contents"),
            Segment::Slashed("path"),
        ],
        fields: &[
            REPOSITORY,
            Field::required(
                "path",
                Kind::Text,
                Place::Path,
                "The file's path in the repository, such as scripts/tidy.py.",
            ),
            Field::required(
                "message",
                Kind::Text,
                Place::Body,
                "The commit's message.",
            ),
            Field::required(
                "content",
                Kind::Text,
                Place::Body,
                "The file's whole new contents, in base64.",
            ),
            Field::optional(
                "branch",
                Kind::Text,
                Place::Body,
                "The branch it goes on; the default branch when not given.",
            )
            .asked_with(Ask::Picker(BRANCHES)),
            Field::optional(
                "replaces",
                Kind::Text,
                Place::Body,
                "The version of the file it replaces, as Read a file gives it; left out for a new file.",
            )
            .sent_as("sha"),
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            ("json.commit.sha", "The commit the file became."),
            ("json.content.sha", "The file's new version."),
            (
                "status",
                "The status GitHub answered with; 201 for a new file, 200 for a replaced one, 409 when the version it replaces is out of date.",
            ),
        ],
    },
    Operation {
        key: "create-release",
        title: "Publish a release",
        description: "Publishes a release at a tag, made from the default branch when the tag does not exist yet.",
        effect: DeclaredAction::Declared(ActionClass::Write),
        verb: Verb::Post,
        path: &[
            Segment::Fixed("repos"),
            Segment::Pair("repository"),
            Segment::Fixed("releases"),
        ],
        fields: &[
            REPOSITORY,
            Field::required(
                "tag",
                Kind::Text,
                Place::Body,
                "The tag the release is for, such as v1.4.0.",
            )
            .sent_as("tag_name"),
            Field::optional("name", Kind::Text, Place::Body, "The release's title."),
            Field::optional(
                "body",
                Kind::Text,
                Place::Body,
                "The release notes, in Markdown.",
            ),
            Field::optional(
                "draft",
                Kind::Flag,
                Place::Body,
                "Whether it is saved as a draft instead of published.",
            ),
            Field::optional(
                "prerelease",
                Kind::Flag,
                Place::Body,
                "Whether it is marked as not ready for production.",
            ),
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            ("json.id", "The release's id."),
            ("json.html_url", "The address of the release's page."),
            (
                "status",
                "The status GitHub answered with, 201 when it was published.",
            ),
        ],
    },
    Operation {
        key: "delete-branch",
        title: "Delete a branch",
        description: "Deletes a branch for good; commits only on it are no longer reachable.",
        effect: DeclaredAction::Declared(ActionClass::Delete),
        verb: Verb::Delete,
        path: &[
            Segment::Fixed("repos"),
            Segment::Pair("repository"),
            Segment::Fixed("git"),
            Segment::Fixed("refs"),
            Segment::Fixed("heads"),
            Segment::Slashed("branch"),
        ],
        fields: &[
            REPOSITORY,
            Field::required(
                "branch",
                Kind::Text,
                Place::Path,
                "The branch to delete, such as feature/login.",
            )
            .asked_with(Ask::Picker(BRANCHES)),
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[(
            "status",
            "The status GitHub answered with, 204 when the branch was deleted.",
        )],
    },
    Operation {
        key: "run-workflow",
        title: "Start a GitHub Actions workflow",
        description: "Starts a GitHub Actions workflow on a branch or tag. What it then does is up to the workflow, so it counts as an undeclared action.",
        effect: DeclaredAction::Undeclared,
        verb: Verb::Post,
        path: &[
            Segment::Fixed("repos"),
            Segment::Pair("repository"),
            Segment::Fixed("actions"),
            Segment::Fixed("workflows"),
            Segment::Input("workflow"),
            Segment::Fixed("dispatches"),
        ],
        fields: &[
            REPOSITORY,
            Field::required(
                "workflow",
                Kind::Text,
                Place::Path,
                "The workflow's file name, such as deploy.yml, or its id.",
            ),
            Field::required(
                "ref",
                Kind::Text,
                Place::Body,
                "The branch or tag to run it on, such as main.",
            ),
            Field::optional(
                "inputs",
                Kind::Values,
                Place::Body,
                "Named values the workflow takes as its inputs.",
            ),
        ],
        fixed: &[("return_run_details", Fixed::Flag(true))],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            (
                "json.workflow_run_id",
                "The id of the run started, which a later step can read the run by.",
            ),
            ("json.html_url", "The address of the run's page."),
            (
                "status",
                "The status GitHub answered with, 200 when the run was started.",
            ),
        ],
    },
    Operation {
        key: "list-repositories",
        title: "List repositories",
        description: "Lists the repositories the account can reach, most recently changed first.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Get,
        path: &[Segment::Fixed("user"), Segment::Fixed("repos")],
        fields: &[LIMIT],
        fixed: &[],
        query: &[("sort", "updated")],
        shape: Shape::Object,
        outputs: &[
            (
                "json",
                "The repositories, each with its full_name, name, private and default_branch.",
            ),
            ("status", "The status GitHub answered with."),
        ],
    },
    Operation {
        key: "list-labels",
        title: "List labels",
        description: "Lists the labels issues and pull requests in a repository can carry.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Get,
        path: &[
            Segment::Fixed("repos"),
            Segment::Pair("repository"),
            Segment::Fixed("labels"),
        ],
        fields: &[REPOSITORY, LIMIT],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            (
                "json",
                "The labels, each with its name, color and description.",
            ),
            ("status", "The status GitHub answered with."),
        ],
    },
    Operation {
        key: "list-branches",
        title: "List branches",
        description: "Lists a repository's branches.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Get,
        path: &[
            Segment::Fixed("repos"),
            Segment::Pair("repository"),
            Segment::Fixed("branches"),
        ],
        fields: &[REPOSITORY, LIMIT],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            (
                "json",
                "The branches, each with its name and whether it is protected.",
            ),
            ("status", "The status GitHub answered with."),
        ],
    },
];
