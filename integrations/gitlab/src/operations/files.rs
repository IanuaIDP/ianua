//! Repository files: reading the commit a branch, tag or commit points to,
//! reading a file at one, and making or replacing a file on a branch as a
//! commit of its own. A file's path is placed as one part of the address,
//! its slashes escaped, as GitLab asks.

use ianua_domain::types::{ActionClass, DeclaredAction};
use ianua_integration::form::Ask;
use ianua_integration::rest::operation::{
    Field, Fixed, Kind, Operation, Place, Segment, Shape, Verb,
};

use crate::operations::{BRANCHES, PROJECT};

/// The file a step reads or writes.
const FILE: Field = Field::required(
    "path",
    Kind::Text,
    Place::Path,
    "The file's path in the repository, such as scripts/tidy.py.",
);

/// The address of one file of the project.
const ONE_FILE: &[Segment] = &[
    Segment::Fixed("projects"),
    Segment::Input("project"),
    Segment::Fixed("repository"),
    Segment::Fixed("files"),
    Segment::Input("path"),
];

/// What a write sends besides the file: the branch it goes on, its whole
/// contents in base64 and the commit's message.
const WRITTEN: &[Field] = &[
    PROJECT,
    FILE,
    Field::required(
        "branch",
        Kind::Text,
        Place::Body,
        "The branch it goes on, such as main.",
    )
    .asked_with(Ask::Picker(BRANCHES)),
    Field::required(
        "content",
        Kind::Text,
        Place::Body,
        "The file's whole new contents, in base64.",
    ),
    Field::required("message", Kind::Text, Place::Body, "The commit's message.")
        .sent_as("commit_message"),
];

/// What a write gives back.
const WRITE_OUTPUTS: &[(&str, &str)] = &[
    ("json.file_path", "The file's path."),
    ("json.branch", "The branch it went on."),
];

/// Every file operation.
pub(crate) const OPERATIONS: &[Operation] = &[
    Operation {
        key: "get-commit",
        title: "Read a commit",
        description: "Reads the commit a branch, tag or commit points to now: its exact hash and message.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Get,
        path: &[
            Segment::Fixed("projects"),
            Segment::Input("project"),
            Segment::Fixed("repository"),
            Segment::Fixed("commits"),
            Segment::Input("ref"),
        ],
        fields: &[
            PROJECT,
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
            ("json.id", "The commit's full hash."),
            ("json.message", "The commit's message."),
            (
                "status",
                "The status GitLab answered with; 404 when there is no such ref.",
            ),
        ],
    },
    Operation {
        key: "get-file",
        title: "Read a file",
        description: "Reads one file of a project's repository at a branch, tag or commit, with the commit it was read at.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Get,
        path: ONE_FILE,
        fields: &[
            PROJECT,
            FILE,
            Field::required(
                "ref",
                Kind::Text,
                Place::Query,
                "The branch, tag or commit to read it at, such as main.",
            )
            .asked_with(Ask::Picker(BRANCHES)),
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            ("json.content", "The file's contents, in base64."),
            (
                "json.commit_id",
                "The commit the ref pointed to when it was read.",
            ),
            ("json.size", "The file's size in bytes."),
            (
                "status",
                "The status GitLab answered with; 404 when there is no such file.",
            ),
        ],
    },
    Operation {
        key: "create-file",
        title: "Make a file",
        description: "Makes one new file on a branch as a commit of its own. A file already there is refused.",
        effect: DeclaredAction::Declared(ActionClass::Write),
        verb: Verb::Post,
        path: ONE_FILE,
        fields: WRITTEN,
        fixed: &[("encoding", Fixed::Text("base64"))],
        query: &[],
        shape: Shape::Object,
        outputs: WRITE_OUTPUTS,
    },
    Operation {
        key: "update-file",
        title: "Replace a file",
        description: "Replaces one file on a branch as a commit of its own. A file not there is refused.",
        effect: DeclaredAction::Declared(ActionClass::Write),
        verb: Verb::Put,
        path: ONE_FILE,
        fields: WRITTEN,
        fixed: &[("encoding", Fixed::Text("base64"))],
        query: &[],
        shape: Shape::Object,
        outputs: WRITE_OUTPUTS,
    },
];
