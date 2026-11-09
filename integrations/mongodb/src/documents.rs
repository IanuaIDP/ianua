//! Documents in and out of MongoDB: a step's filters, sorts, pipelines,
//! updates and documents read from MongoDB's extended JSON, and the
//! documents a read returns written as plain values a workflow holds.
//!
//! MongoDB's operators begin with `$`, which a workflow's field names never
//! do, so a step gives each as JSON text, such as
//! `{ "total": { "$gt": 100 } }`; one without operators may also be given as
//! workflow data. A document read back writes an id as its hex text, a
//! moment as RFC 3339 text and a decimal as its digits.

use ianua_domain::domains::workflows::data::FlowData;
use ianua_domain::domains::workflows::execution::step::ActionOutcome;
use ianua_integration::answer::failed;
use ianua_integration::arguments::optional_values;
use mongodb::bson::{Bson, Document};
use serde_json::{Map, Number, Value};

/// The document input `name` holds, or none when it is not given.
///
/// # Errors
///
/// A failed outcome when it is not a document.
pub(crate) fn optional_document(
    arguments: &FlowData,
    name: &str,
) -> Result<Option<Document>, ActionOutcome> {
    let Some(value) = given(arguments, name)? else {
        return Ok(None);
    };
    document_of(value, name).map(Some)
}

/// The document input `name` holds.
///
/// # Errors
///
/// A failed outcome when it is missing or not a document.
pub(crate) fn required_document(
    arguments: &FlowData,
    name: &str,
) -> Result<Document, ActionOutcome> {
    optional_document(arguments, name)?.ok_or_else(|| failed(&format!("{name} is required")))
}

/// The list of documents input `name` holds.
///
/// # Errors
///
/// A failed outcome when it is missing, not a list, empty, or holds
/// anything but documents.
pub(crate) fn document_list(
    arguments: &FlowData,
    name: &str,
) -> Result<Vec<Document>, ActionOutcome> {
    let Some(Value::Array(items)) = given(arguments, name)? else {
        return Err(failed(&format!("{name} is a list of documents")));
    };
    if items.is_empty() {
        return Err(failed(&format!("{name} holds no document")));
    }
    items
        .into_iter()
        .map(|item| document_of(item, name))
        .collect()
}

/// Input `name` as JSON: the JSON its text holds, or its workflow data.
fn given(arguments: &FlowData, name: &str) -> Result<Option<Value>, ActionOutcome> {
    match optional_values(arguments, name)? {
        Some(Value::String(text)) => serde_json::from_str(&text)
            .map(Some)
            .map_err(|_| failed(&format!("{name} is not JSON"))),
        other => Ok(other),
    }
}

/// `value`, the input `name`, read as a document from extended JSON.
fn document_of(value: Value, name: &str) -> Result<Document, ActionOutcome> {
    let not_a_document = || failed(&format!("{name} is not a document"));
    match Bson::try_from(value).map_err(|_| not_a_document())? {
        Bson::Document(document) => Ok(document),
        _ => Err(not_a_document()),
    }
}

/// `documents` as plain values.
pub(crate) fn documents_of(documents: Vec<Document>) -> Value {
    Value::Array(
        documents
            .into_iter()
            .map(Bson::Document)
            .map(plain)
            .collect(),
    )
}

/// `value` as a plain value: documents and lists keep their shape, and a
/// value JSON has no kind for becomes its text.
fn plain(value: Bson) -> Value {
    match value {
        Bson::Document(document) => Value::Object(
            document
                .into_iter()
                .map(|(key, value)| (key, plain(value)))
                .collect::<Map<_, _>>(),
        ),
        Bson::Array(items) => Value::Array(items.into_iter().map(plain).collect()),
        Bson::String(text) => Value::String(text),
        Bson::Boolean(flag) => Value::Bool(flag),
        Bson::Int32(number) => Value::from(number),
        Bson::Int64(number) => Value::from(number),
        Bson::Double(number) => Number::from_f64(number).map_or(Value::Null, Value::Number),
        Bson::Null | Bson::Undefined => Value::Null,
        Bson::ObjectId(id) => Value::String(id.to_hex()),
        Bson::DateTime(at) => at
            .try_to_rfc3339_string()
            .map_or_else(|_| Value::from(at.timestamp_millis()), Value::String),
        other => Value::String(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::workflows::data::FieldName;
    use mongodb::bson::doc;
    use mongodb::bson::oid::ObjectId;
    use serde_json::json;

    use super::*;

    /// An id written in extended JSON is read as an id, so a filter by it
    /// matches.
    #[test]
    fn an_extended_json_id_reads_as_an_id() {
        let id = ObjectId::new();

        let document = document_of(json!({ "_id": { "$oid": id.to_hex() } }), "filter").unwrap();

        assert_eq!(document, doc! { "_id": id });
    }

    /// A filter with operators, given as JSON text, reads as the query.
    #[test]
    fn a_filter_given_as_text_reads_with_its_operators() {
        let given = FlowData::map(
            [(
                FieldName::new("filter").unwrap(),
                FlowData::text(r#"{ "total": { "$gt": 100 } }"#).unwrap(),
            )]
            .into_iter()
            .collect(),
        )
        .unwrap();

        let filter = required_document(&given, "filter").unwrap();

        assert_eq!(filter, doc! { "total": { "$gt": 100 } });
    }

    /// A list supplied as a filter fails document conversion.
    #[test]
    fn a_list_is_not_a_document() {
        assert!(document_of(json!([1, 2]), "filter").is_err());
    }

    /// A document read back writes its id as hex text, so a workflow holds
    /// it.
    #[test]
    fn documents_read_back_as_plain_values() {
        let id = ObjectId::new();

        let written = documents_of(vec![doc! { "_id": id, "total": 42 }]);

        assert_eq!(written, json!([{ "_id": id.to_hex(), "total": 42 }]));
    }
}
