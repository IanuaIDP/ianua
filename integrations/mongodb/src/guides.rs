//! How the MongoDB integration explains each of its operations to a
//! workflow's builder: what each input means and how it is asked for, and
//! what a call gives back.

use ianua_domain::domains::workflows::integration::ROUTE_INPUT;
use ianua_domain::domains::workflows::integration::form::{FormGroup, InputStyle};
use ianua_domain::domains::workflows::integration::guide::OperationGuide;
use ianua_domain::shared::errors::DomainError;
use ianua_integration::describe::{GuideText, InputText, guide};
use ianua_integration::form::{Ask, FormText, Suggested};

use crate::operation::Kind;

/// What a read gives back.
const READ_OUTPUTS: &[(&str, &str)] = &[
    (
        "documents",
        "The documents read, ids and moments written as text, at most as many as the limit.",
    ),
    ("document_count", "How many documents came back."),
    (
        "truncated",
        "True when more documents matched than the limit let through.",
    ),
];

/// What an insert gives back.
const INSERT_OUTPUTS: &[(&str, &str)] = &[("inserted_count", "How many documents were inserted.")];

/// What an update gives back.
const UPDATE_OUTPUTS: &[(&str, &str)] = &[
    ("matched_count", "How many documents the filter matched."),
    ("modified_count", "How many of them the update changed."),
];

/// What a delete gives back.
const DELETE_OUTPUTS: &[(&str, &str)] = &[("deleted_count", "How many documents were deleted.")];

/// How every operation is explained: one per kind.
pub(super) fn guides_of() -> Result<Vec<OperationGuide>, DomainError> {
    Kind::ALL.into_iter().map(guide_for).collect()
}

/// The route, database and collection named by every MongoDB operation.
const INPUTS: [InputText<'static>; 3] = [
    InputText {
        name: ROUTE_INPUT,
        meaning: "The MongoDB's stream route, one the company opened to workflows.",
        suggested: Suggested::Text,
        form: FormText {
            label: Some("MongoDB"),
            ask: Ask::DataPicker,
            ..FormText::plain()
        },
    },
    InputText {
        name: "database",
        meaning: "The database the collection is in.",
        suggested: Suggested::Text,
        form: FormText {
            label: Some("Database"),
            ..FormText::plain()
        },
    },
    InputText {
        name: "collection",
        meaning: "The collection to work on.",
        suggested: Suggested::Text,
        form: FormText {
            label: Some("Collection"),
            ..FormText::plain()
        },
    },
];

/// How `kind` is explained.
fn guide_for(kind: Kind) -> Result<OperationGuide, DomainError> {
    let (title, description, outputs) = described(kind);
    let mut inputs = Vec::from(INPUTS);
    inputs.extend(kind.own_inputs().iter().map(|(name, _)| own_input(name)));
    guide(&GuideText {
        operation: kind.name(),
        title,
        description,
        inputs: &inputs,
        outputs,
        preview: None,
    })
}

/// The title, description and outputs of `kind`.
fn described(
    kind: Kind,
) -> (
    &'static str,
    &'static str,
    &'static [(&'static str, &'static str)],
) {
    match kind {
        Kind::Find => (
            "Find in a protected MongoDB",
            "Finds documents in a company's MongoDB as the person the run acts for.",
            READ_OUTPUTS,
        ),
        Kind::Aggregate => (
            "Aggregate in a protected MongoDB",
            "Runs a pipeline that only reads on a company's MongoDB as the person the run acts for. Stages that write, $out and $merge, are refused.",
            READ_OUTPUTS,
        ),
        Kind::Insert => (
            "Insert into a protected MongoDB",
            "Inserts documents into a company's MongoDB as the person the run acts for, with the login its stream route keeps.",
            INSERT_OUTPUTS,
        ),
        Kind::Update => (
            "Update a protected MongoDB",
            "Updates the documents a filter matches in a company's MongoDB as the person the run acts for, with the login its stream route keeps.",
            UPDATE_OUTPUTS,
        ),
        Kind::Delete => (
            "Delete from a protected MongoDB",
            "Deletes the documents a filter matches in a company's MongoDB as the person the run acts for, with the login its stream route keeps.",
            DELETE_OUTPUTS,
        ),
    }
}

/// How an operation's own input `name` is explained.
fn own_input(name: &'static str) -> InputText<'static> {
    let meaning = match name {
        "filter" => "Which documents, as a MongoDB query written as JSON text.",
        "projection" => "Which fields to hand back, such as { \"total\": 1 }.",
        "sort" => "The order, such as { \"created_at\": -1 }.",
        "limit" => "The most documents to hand back; the deployment's own limit when left out.",
        "pipeline" => "The stages, in order, written as a JSON list.",
        "documents" => "The documents to insert, written as a JSON list.",
        "update" => "The change, such as { \"$set\": { \"status\": \"done\" } }.",
        _ => "True to reach every matching document; only the first otherwise.",
    };
    InputText {
        name,
        meaning,
        suggested: Suggested::Text,
        form: input_form(name),
    }
}

/// The editor presentation and example for a MongoDB operation's input.
fn input_form(name: &str) -> FormText {
    let example = match name {
        "filter" => Some(r#"{ "status": "open" }"#),
        "pipeline" => Some(r#"[{ "$match": { "status": "open" } }]"#),
        "update" => Some(r#"{ "$set": { "status": "done" } }"#),
        _ => None,
    };
    let group = match name {
        "filter" | "pipeline" | "documents" | "update" => FormGroup::Main,
        _ => FormGroup::MoreOptions,
    };
    FormText {
        example,
        group,
        style: InputStyle::Monospace,
        ..FormText::plain()
    }
}
