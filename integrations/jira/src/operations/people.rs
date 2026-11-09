//! People: finding a Jira user by their email or name.

use ianua_domain::types::{ActionClass, DeclaredAction};
use ianua_integration::rest::operation::{Field, Kind, Operation, Place, Segment, Shape, Verb};

/// Every people operation.
pub(crate) const OPERATIONS: &[Operation] = &[Operation {
    key: "find-user",
    title: "Find a person",
    description: "Finds Jira users by email address or name, for a later step to assign an issue to.",
    effect: DeclaredAction::Declared(ActionClass::Read),
    verb: Verb::Get,
    path: &[Segment::Fixed("user"), Segment::Fixed("search")],
    fields: &[Field::required(
        "query",
        Kind::Text,
        Place::Query,
        "The person's email address or part of their name.",
    )],
    fixed: &[],
    query: &[],
    shape: Shape::Object,
    outputs: &[(
        "json",
        "The people found, each with their accountId and displayName.",
    )],
}];
