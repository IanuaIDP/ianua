//! Pipelines: starting a run, and reading how one went.

use ianua_domain::types::{ActionClass, DeclaredAction};
use ianua_integration::rest::operation::{Field, Kind, Operation, Place, Segment, Shape, Verb};

use crate::operations::{API_VERSION, PROJECT};

/// The pipeline a step acts on, in the path.
const PIPELINE: Field = Field::required(
    "pipeline",
    Kind::Count,
    Place::Path,
    "The pipeline's id, as its page's address shows it.",
);

/// Every pipeline operation.
pub(crate) const OPERATIONS: &[Operation] = &[
    Operation {
        key: "run-pipeline",
        title: "Start a pipeline",
        description: "Starts a pipeline run on a branch. What it then does is up to the pipeline, so it counts as an undeclared action.",
        effect: DeclaredAction::Undeclared,
        verb: Verb::Post,
        path: &[
            Segment::Input("project"),
            Segment::Fixed("_apis"),
            Segment::Fixed("pipelines"),
            Segment::Input("pipeline"),
            Segment::Fixed("runs"),
        ],
        fields: &[
            PROJECT,
            PIPELINE,
            Field::optional("branch", Kind::Text, Place::Body, "The branch to run on, such as refs/heads/main; the pipeline's default when not given.")
                .sent_as("resources.repositories.self.refName"),
            Field::optional("parameters", Kind::Values, Place::Body, "Named values for the pipeline's parameters.")
                .sent_as("templateParameters"),
        ],
        fixed: &[],
        query: API_VERSION,
        shape: Shape::Object,
        outputs: &[
            ("json.id", "The run's id, which reading the run names."),
            ("json.state", "Where the run is, such as inProgress."),
            ("json._links.web.href", "The address of the run's page."),
        ],
    },
    Operation {
        key: "get-pipeline-run",
        title: "Get a pipeline run",
        description: "Reads how a pipeline run is going, and how it ended once it has.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Get,
        path: &[
            Segment::Input("project"),
            Segment::Fixed("_apis"),
            Segment::Fixed("pipelines"),
            Segment::Input("pipeline"),
            Segment::Fixed("runs"),
            Segment::Input("run"),
        ],
        fields: &[
            PROJECT,
            PIPELINE,
            Field::required("run", Kind::Count, Place::Path, "The run's id, such as an earlier step's json.id."),
        ],
        fixed: &[],
        query: API_VERSION,
        shape: Shape::Object,
        outputs: &[
            ("json.state", "Where the run is: inProgress, canceling or completed."),
            ("json.result", "How it ended once completed: succeeded, failed or canceled."),
        ],
    },
];
