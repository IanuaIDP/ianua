//! How the Postgres integration explains each of its operations to a
//! workflow's builder: what each input means and how it is asked for, and
//! what a call gives back.

use ianua_domain::domains::workflows::integration::ROUTE_INPUT;
use ianua_domain::domains::workflows::integration::form::{FormGroup, InputStyle};
use ianua_domain::domains::workflows::integration::guide::OperationGuide;
use ianua_domain::shared::errors::DomainError;
use ianua_integration::describe::{GuideText, InputText, guide};
use ianua_integration::form::{Ask, FormText, Suggested};

use crate::query::Kind;

/// What a query gives back.
const QUERY_OUTPUTS: &[(&str, &str)] = &[
    (
        "rows",
        "The rows read, each with its columns by name, at most as many as the row limit.",
    ),
    ("row_count", "How many rows came back."),
    (
        "truncated",
        "True when more rows matched than the row limit let through.",
    ),
];

/// What an execute gives back.
const EXECUTE_OUTPUTS: &[(&str, &str)] =
    &[("rows_affected", "How many rows the statement changed.")];

/// How every operation is explained: one per kind.
pub(super) fn guides_of() -> Result<Vec<OperationGuide>, DomainError> {
    [Kind::Query, Kind::Execute]
        .into_iter()
        .map(guide_for)
        .collect()
}

/// The connection and statement inputs shared by reads and changes.
const INPUTS: [InputText<'static>; 4] = [
    InputText {
        name: ROUTE_INPUT,
        meaning: "The database's stream route, one the company opened to workflows.",
        suggested: Suggested::Text,
        form: FormText {
            label: Some("Database"),
            ask: Ask::DataPicker,
            ..FormText::plain()
        },
    },
    InputText {
        name: "statement",
        meaning: "One SQL statement, its values written as $1, $2 and so on.",
        suggested: Suggested::Text,
        form: FormText {
            label: Some("Statement"),
            example: Some("select id, total from orders where created_at > $1"),
            style: InputStyle::Monospace,
            ..FormText::plain()
        },
    },
    InputText {
        name: "parameters",
        meaning: "The values for $1, $2 and so on, in order, sent apart from the statement.",
        suggested: Suggested::Text,
        form: FormText::plain(),
    },
    InputText {
        name: "database",
        meaning: "The database to connect to; the login's own name when left out.",
        suggested: Suggested::Text,
        form: FormText {
            group: FormGroup::MoreOptions,
            ..FormText::plain()
        },
    },
];

/// Shared inputs, with the row limit appended only for queries.
fn inputs_for(kind: Kind) -> Vec<InputText<'static>> {
    let mut inputs = Vec::from(INPUTS);
    if kind == Kind::Query {
        inputs.push(InputText {
            name: "row_limit",
            meaning: "The most rows to hand back; the deployment's own limit when left out.",
            suggested: Suggested::Text,
            form: FormText {
                group: FormGroup::MoreOptions,
                ..FormText::plain()
            },
        });
    }
    inputs
}

/// How `kind` is explained.
fn guide_for(kind: Kind) -> Result<OperationGuide, DomainError> {
    let (title, description, outputs) = match kind {
        Kind::Query => (
            "Query a protected database",
            "Reads rows from a company's Postgres database as the person the run acts for. It runs in a read-only transaction, so the database refuses any change.",
            QUERY_OUTPUTS,
        ),
        Kind::Execute => (
            "Change a protected database",
            "Runs one statement that changes a company's Postgres database as the person the run acts for, with the login its stream route keeps. What it may change is what that login may.",
            EXECUTE_OUTPUTS,
        ),
    };
    guide(&GuideText {
        operation: kind.name(),
        title,
        description,
        inputs: &inputs_for(kind),
        outputs,
        preview: None,
    })
}
