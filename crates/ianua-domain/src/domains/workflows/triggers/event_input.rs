//! What a workflow started by an event is handed: the event's details as
//! workflow data, one field per payload field.
//!
//! A scalar becomes text, an entity a map of its `kind`, `id` and `label`,
//! and a transition a map of its `from` and `to`. A field whose name a
//! workflow cannot address, or one that names a secret, is left out, so no
//! step is handed what the audit record itself would never show.

use crate::domains::workflows::data::{FieldName, FlowData};
use crate::shared::errors::DomainError;
use crate::shared::events::data::{Change, EventData, FieldValue, Reference, is_sensitive_key};

/// The workflow data an event with `payload` hands the workflow it starts.
///
/// # Errors
///
/// - [`DomainError::Validation`] when the payload is larger than workflow
///   data may be.
pub fn event_input(payload: &EventData) -> Result<FlowData, DomainError> {
    let mut entries = Vec::with_capacity(payload.len());
    for (key, value) in payload.fields() {
        if is_sensitive_key(key) {
            continue;
        }
        let Ok(name) = FieldName::new(key.as_str()) else {
            continue;
        };
        entries.push((name, value_of(value)?));
    }
    FlowData::map(entries)
}

/// One payload value as workflow data.
fn value_of(value: &FieldValue) -> Result<FlowData, DomainError> {
    match value {
        FieldValue::Text(text) => FlowData::text(text.as_str()),
        FieldValue::Reference(reference) => reference_of(reference),
        FieldValue::Change(change) => change_of(change),
    }
}

/// An entity as a map of its kind, id and label.
fn reference_of(reference: &Reference) -> Result<FlowData, DomainError> {
    FlowData::map(vec![
        (named("kind")?, FlowData::text(reference.kind().as_str())?),
        (named("id")?, FlowData::text(reference.id())?),
        (named("label")?, FlowData::text(reference.label())?),
    ])
}

/// A transition as a map of what it went from and to, each when known.
fn change_of(change: &Change) -> Result<FlowData, DomainError> {
    let mut entries = Vec::with_capacity(2);
    if let Some(from) = change.from() {
        entries.push((named("from")?, FlowData::text(from)?));
    }
    if let Some(to) = change.to() {
        entries.push((named("to")?, FlowData::text(to)?));
    }
    FlowData::map(entries)
}

/// The field name `name`, which is always one.
fn named(name: &str) -> Result<FieldName, DomainError> {
    FieldName::new(name).map_err(DomainError::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::events::data::RefKind;

    /// A user locked: the status change and the user reach the workflow as
    /// a map of `from` and `to` and a map of `kind`, `id` and `label`.
    #[test]
    fn a_payload_becomes_one_field_per_field() {
        let payload = EventData::new()
            .field("reason", "too many failures")
            .reference(
                "user",
                Reference::new(RefKind::USER, "u-1", "ann@acme.test"),
            )
            .change("status", "active", "locked");

        let input = event_input(&payload).unwrap();

        let reason = FieldName::new("reason").unwrap();
        let user = FieldName::new("user").unwrap();
        assert!(input.field(&reason).is_some());
        let label = FieldName::new("label").unwrap();
        assert!(input.field(&user).unwrap().field(&label).is_some());
    }

    /// Converting an event payload to workflow input omits its token field.
    #[test]
    fn a_field_naming_a_secret_is_left_out() {
        let payload = EventData::from_fields(vec![(
            "token".to_owned(),
            FieldValue::Text("abc".to_owned()),
        )]);

        let input = event_input(&payload).unwrap();

        assert!(input.field(&FieldName::new("token").unwrap()).is_none());
    }
}
