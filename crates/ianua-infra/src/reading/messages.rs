//! An agent message held to its topic's JSON Schema and rewritten to one
//! canonical form: object keys sorted, no insignificant whitespace, numbers
//! as parsed. Two messages that mean the same leave as the same bytes, so
//! key order, spacing and number spelling carry nothing.
//!
//! The schema is the tenant's, so it is compiled offline: a reference to
//! anything outside the schema itself fails to compile rather than making
//! the platform reach out to a network or a disk. Its patterns run on a
//! linear-time engine, so a pattern written to backtrack cannot stall the
//! check.
//!
//! A refusal names the schema rule that failed and never the payload: the
//! reason is recorded in the audit trail, and the payload may hold data the
//! trail is not cleared to hold.

use ianua_app::ports::messaging::MessageShape;
use ianua_domain::domains::messaging::schema::SchemaDefinition;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use jsonschema::{PatternOptions, Validator};
use serde_json::{Map, Value};

/// Holds agent messages to a JSON Schema and writes them out canonically.
#[derive(Debug, Default, Clone, Copy)]
pub struct JsonSchemaMessageShape;

impl MessageShape for JsonSchemaMessageShape {
    fn conform(&self, schema: &SchemaDefinition, payload: &[u8]) -> Result<Vec<u8>, DomainError> {
        let validator = compiled(schema)?;
        let message: Value = serde_json::from_slice(payload).map_err(|_| {
            DomainError::invalid(message!(
                "infra-the-message-is-not-json",
                "the message is not JSON"
            ))
        })?;
        if let Err(broken) = validator.validate(&message) {
            return Err(DomainError::invalid(message!(
                "infra-the-message-breaks-the-topic-schema",
                format!(
                    "the message breaks the topic schema at {} ({})",
                    broken.schema_path(),
                    broken.kind().keyword()
                )
            )));
        }
        serde_json::to_vec(&canonical(message)).map_err(DomainError::infra)
    }
}

/// The topic's schema, compiled with nothing fetched.
fn compiled(schema: &SchemaDefinition) -> Result<Validator, DomainError> {
    let schema: Value = serde_json::from_str(schema.as_str()).map_err(DomainError::infra)?;
    jsonschema::options()
        .offline()
        .with_pattern_options(PatternOptions::regex())
        .build(&schema)
        .map_err(DomainError::infra)
}

/// `value` with every object's keys in order, all the way down.
pub(crate) fn canonical(value: Value) -> Value {
    match value {
        Value::Object(object) => Value::Object(sorted(object)),
        Value::Array(items) => Value::Array(items.into_iter().map(canonical).collect()),
        scalar @ (Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_)) => scalar,
    }
}

/// `object` with its keys in order, each value made canonical.
fn sorted(object: Map<String, Value>) -> Map<String, Value> {
    let mut entries: Vec<(String, Value)> = object.into_iter().collect();
    entries.sort_by(|(a, _), (b, _)| a.cmp(b));
    entries
        .into_iter()
        .map(|(key, value)| (key, canonical(value)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const TASK: &str = r#"{
        "type": "object",
        "properties": {
            "task": {"type": "integer"},
            "tags": {"type": "array", "items": {"type": "string"}}
        },
        "required": ["task"],
        "additionalProperties": false
    }"#;

    fn schema(text: &str) -> SchemaDefinition {
        SchemaDefinition::new(text).unwrap()
    }

    fn conform(payload: &str) -> Result<String, DomainError> {
        JsonSchemaMessageShape
            .conform(&schema(TASK), payload.as_bytes())
            .map(|bytes| String::from_utf8(bytes).unwrap())
    }

    /// A matching message leaves sorted and without spaces.
    #[test]
    fn a_matching_message_leaves_in_canonical_form() {
        let canonical = conform(r#"{ "tags": ["b", "a"],   "task": 7 }"#).unwrap();

        assert_eq!(canonical, r#"{"tags":["b","a"],"task":7}"#);
    }

    /// Keys are sorted at every level, inside arrays too.
    #[test]
    fn nested_keys_are_sorted_too() {
        let canonical = JsonSchemaMessageShape
            .conform(
                &schema(r#"{"type":"object"}"#),
                br#"{"z":{"b":1,"a":2},"a":[{"d":1,"c":2}]}"#,
            )
            .unwrap();

        assert_eq!(canonical, br#"{"a":[{"c":2,"d":1}],"z":{"a":2,"b":1}}"#);
    }

    /// Non-JSON input and JSON followed by trailing text fail message validation.
    #[test]
    fn a_message_that_is_not_json_is_refused() {
        assert!(matches!(conform("task=7"), Err(DomainError::Validation(_))));
        assert!(matches!(
            conform(r#"{"task":7} hidden"#),
            Err(DomainError::Validation(_))
        ));
    }

    /// A message containing an undeclared property fails schema validation.
    #[test]
    fn a_field_the_schema_does_not_allow_is_refused() {
        let result = conform(r#"{"task":7,"note":"meet at the usual place"}"#);

        assert!(matches!(result, Err(DomainError::Validation(_))));
    }

    /// An additional-property refusal names the schema rule while omitting the
    /// unexpected key and its secret value.
    #[test]
    fn a_refusal_names_the_rule_and_not_the_content() {
        let Err(refused) = conform(r#"{"task":7,"secret-key-material":"hunter2"}"#) else {
            panic!("the message breaks the schema");
        };
        let reason = refused.to_string();

        assert!(reason.contains("additionalProperties"), "{reason}");
        assert!(!reason.contains("hunter2"), "{reason}");
        assert!(!reason.contains("secret-key-material"), "{reason}");
    }

    /// A stored schema that is not JSON is the store's fault, not the
    /// sender's.
    #[test]
    fn a_schema_that_is_not_json_is_an_infrastructure_fault() {
        let result = JsonSchemaMessageShape.conform(&schema("not a schema"), b"{}");

        assert!(matches!(result, Err(DomainError::Infrastructure(_))));
    }

    /// Schemas referencing remote HTTP or local file resources fail compilation.
    #[test]
    fn a_schema_reaching_outside_itself_does_not_compile() {
        let remote = schema(r#"{"$ref": "http://169.254.169.254/latest/meta-data/"}"#);
        let file = schema(r#"{"$ref": "file:///etc/passwd"}"#);

        for reaching in [remote, file] {
            let result = JsonSchemaMessageShape.conform(&reaching, b"{}");

            assert!(matches!(result, Err(DomainError::Infrastructure(_))));
        }
    }

    /// A reference inside the schema itself resolves.
    #[test]
    fn a_reference_within_the_schema_resolves() {
        let local = schema(
            r##"{"$defs": {"id": {"type": "integer"}},
                "type": "object", "properties": {"id": {"$ref": "#/$defs/id"}}}"##,
        );

        let accepted = JsonSchemaMessageShape.conform(&local, br#"{"id": 3}"#);
        let refused = JsonSchemaMessageShape.conform(&local, br#"{"id": "three"}"#);

        assert!(accepted.is_ok());
        assert!(matches!(refused, Err(DomainError::Validation(_))));
    }

    /// A nested-quantifier pattern rejects a long near-match as a validation
    /// failure.
    #[test]
    fn a_backtracking_pattern_answers_at_once() {
        let catastrophic = schema(r#"{"type": "string", "pattern": "^(a+)+$"}"#);
        let payload = format!("\"{}!\"", "a".repeat(64));

        let result = JsonSchemaMessageShape.conform(&catastrophic, payload.as_bytes());

        assert!(matches!(result, Err(DomainError::Validation(_))));
    }

    /// Conforming the canonical form again changes nothing, and layout never
    /// survives: there is exactly one form.
    #[test]
    fn the_canonical_form_is_a_fixed_point() {
        let any = schema("{}");
        let pretty = br#"{
            "b": [1, {"y": null, "x": true}],
            "a": "text"
        }"#;

        let once = JsonSchemaMessageShape.conform(&any, pretty).unwrap();
        let twice = JsonSchemaMessageShape.conform(&any, &once).unwrap();

        assert_eq!(once, twice);
        assert_eq!(once, br#"{"a":"text","b":[1,{"x":true,"y":null}]}"#);
    }
}
