//! Projects: starting a pipeline, deleting a branch, and listing the
//! projects, labels and branches the forms' pickers offer.

use ianua_domain::types::{ActionClass, DeclaredAction};
use ianua_integration::form::Ask;
use ianua_integration::rest::operation::{Field, Kind, Operation, Place, Segment, Shape, Verb};

use crate::operations::{BRANCHES, LIMIT, PROJECT};

/// Words a listing's names must hold.
const SEARCH: Field = Field::optional(
    "search",
    Kind::Text,
    Place::Query,
    "Only those whose name holds these words.",
)
.more_options();

/// Every project operation.
pub(crate) const OPERATIONS: &[Operation] = &[
    Operation {
        key: "list-projects",
        title: "List projects",
        description: "Lists the projects the account is a member of, most recently active first.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Get,
        path: &[Segment::Fixed("projects")],
        fields: &[SEARCH, LIMIT],
        fixed: &[],
        query: &[
            ("membership", "true"),
            ("order_by", "last_activity_at"),
            ("simple", "true"),
        ],
        shape: Shape::Object,
        outputs: &[
            (
                "json",
                "The projects, each with its id, path_with_namespace, name_with_namespace and default_branch.",
            ),
            ("status", "The status GitLab answered with."),
        ],
    },
    Operation {
        key: "list-labels",
        title: "List labels",
        description: "Lists the labels issues and merge requests in a project can carry, its groups' labels included.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Get,
        path: &[
            Segment::Fixed("projects"),
            Segment::Input("project"),
            Segment::Fixed("labels"),
        ],
        fields: &[PROJECT, SEARCH, LIMIT],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            (
                "json",
                "The labels, each with its name, color and description.",
            ),
            ("status", "The status GitLab answered with."),
        ],
    },
    Operation {
        key: "list-branches",
        title: "List branches",
        description: "Lists a project's branches.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Get,
        path: &[
            Segment::Fixed("projects"),
            Segment::Input("project"),
            Segment::Fixed("repository"),
            Segment::Fixed("branches"),
        ],
        fields: &[PROJECT, SEARCH, LIMIT],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            (
                "json",
                "The branches, each with its name, whether it is protected and whether it is the default.",
            ),
            ("status", "The status GitLab answered with."),
        ],
    },
    Operation {
        key: "run-pipeline",
        title: "Start a pipeline",
        description: "Starts a CI/CD pipeline on a branch or tag. What it then does is up to the project's pipeline, so it counts as an undeclared action.",
        effect: DeclaredAction::Undeclared,
        verb: Verb::Post,
        path: &[
            Segment::Fixed("projects"),
            Segment::Input("project"),
            Segment::Fixed("pipeline"),
        ],
        fields: &[
            PROJECT,
            Field::required(
                "ref",
                Kind::Text,
                Place::Body,
                "The branch or tag to run it on, such as main.",
            )
            .asked_with(Ask::Picker(BRANCHES)),
            Field::optional(
                "variables",
                Kind::Values,
                Place::Body,
                "Variables for the pipeline, a list of objects each with a key and a value.",
            ),
            Field::optional(
                "inputs",
                Kind::Values,
                Place::Body,
                "Named values the pipeline takes as its inputs.",
            )
            .more_options(),
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            (
                "json.id",
                "The pipeline's id, which a later step can read it by.",
            ),
            ("json.status", "Where the pipeline stands, such as created."),
            ("json.web_url", "The address of the pipeline's page."),
            (
                "status",
                "The status GitLab answered with, 201 when the pipeline was created.",
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
            Segment::Fixed("projects"),
            Segment::Input("project"),
            Segment::Fixed("repository"),
            Segment::Fixed("branches"),
            Segment::Input("branch"),
        ],
        fields: &[
            PROJECT,
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
            "The status GitLab answered with, 204 when the branch was deleted.",
        )],
    },
];
