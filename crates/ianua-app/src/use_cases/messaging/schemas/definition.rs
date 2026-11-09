//! What the app reads out of a schema definition before the domain decides
//! on it: whether the body is well formed for its format, and which
//! required fields a new JSON Schema version adds or drops.
//!
//! The size of a definition, how many versions a schema holds and whether a
//! change breaks the compatibility mode are the domain's to check.

use ianua_domain::domains::messaging::schema::{
    EventSchema, RequiredFields, RequiredFieldsChange, SchemaDefinition, SchemaFormat,
};
use ianua_domain::isolation::scope::TenantScope;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use serde_json::Value;

use crate::error::AppError;

/// Refuses a definition that is not well formed for its format.
///
/// - JSON Schema and Avro: must be valid JSON.
/// - Protobuf: any text, since it is not parsed here.
///
/// # Errors
///
/// `AppError::Domain(Validation)` when the definition is not valid JSON.
pub(in crate::use_cases::messaging) fn ensure_well_formed(
    definition: &SchemaDefinition,
    format: SchemaFormat,
) -> Result<(), AppError> {
    match format {
        SchemaFormat::JsonSchema | SchemaFormat::Avro => parsed(definition).map(drop),
        SchemaFormat::Protobuf => Ok(()),
    }
}

/// How the required fields change from `schema`'s latest version to
/// `definition`, for a JSON Schema. Other formats cannot be compared.
///
/// # Errors
///
/// `AppError::Domain(Validation)` when either definition is not valid JSON.
pub(in crate::use_cases::messaging) fn required_fields_change<T: TenantScope>(
    schema: &EventSchema<T>,
    definition: &SchemaDefinition,
) -> Result<Option<RequiredFieldsChange>, AppError> {
    let comparable = match schema.format() {
        SchemaFormat::JsonSchema => schema.latest_definition(),
        SchemaFormat::Avro | SchemaFormat::Protobuf => None,
    };
    let Some(latest) = comparable else {
        return Ok(None);
    };
    Ok(Some(RequiredFieldsChange {
        before: required_fields(&parsed(latest)?),
        after: required_fields(&parsed(definition)?),
    }))
}

/// `definition` read as JSON.
fn parsed(definition: &SchemaDefinition) -> Result<Value, AppError> {
    serde_json::from_str(definition.as_str()).map_err(|e| {
        AppError::Domain(DomainError::invalid(message!(
            "messaging-invalid-json-in-schema-definition",
            format!("invalid JSON in schema definition: {e}")
        )))
    })
}

/// The `required` array of a JSON Schema object.
fn required_fields(schema: &Value) -> RequiredFields {
    schema
        .get("required")
        .and_then(Value::as_array)
        .map(|fields| {
            fields
                .iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::messaging::schema::CompatibilityMode;

    use super::*;
    use crate::test_support::messaging::{SchemaShape, schema_named};

    const BOTH: &str = r#"{"type":"object","required":["id","name"]}"#;

    fn definition(text: &str) -> SchemaDefinition {
        SchemaDefinition::new(text).unwrap()
    }

    fn fields(names: &[&str]) -> RequiredFields {
        names.iter().map(|name| (*name).to_owned()).collect()
    }

    /// The current version of `order-created` requires `id` and `name`; the
    /// new one requires only `id`. The change shows both, for the domain to
    /// hold to the schema's mode.
    #[test]
    fn a_json_schema_change_names_the_fields_before_and_after() {
        let schema = schema_named("order-created", SchemaShape::FREE_JSON, BOTH);

        let change = required_fields_change(
            &schema,
            &definition(r#"{"type":"object","required":["id"]}"#),
        )
        .unwrap()
        .unwrap();

        assert_eq!(change.before, fields(&["id", "name"]));
        assert_eq!(change.after, fields(&["id"]));
    }

    /// A definition naming no `required` array requires nothing.
    #[test]
    fn a_definition_naming_no_required_fields_requires_none() {
        let schema = schema_named("order-created", SchemaShape::FREE_JSON, BOTH);

        let change = required_fields_change(&schema, &definition(r#"{"type":"object"}"#))
            .unwrap()
            .unwrap();

        assert_eq!(change.after, RequiredFields::default());
    }

    /// `required` is a JSON Schema concept. Reading it out of an Avro
    /// definition would compare fields it knows nothing about, so an Avro
    /// change cannot be compared.
    #[test]
    fn only_json_schema_definitions_are_compared() {
        let avro = SchemaShape {
            format: SchemaFormat::Avro,
            compatibility: CompatibilityMode::Full,
        };
        let schema = schema_named("order-created", avro, BOTH);

        let change = required_fields_change(&schema, &definition(r#"{"type":"record"}"#)).unwrap();

        assert!(change.is_none());
    }

    /// An Avro definition that is not JSON is refused before it is stored.
    #[test]
    fn an_avro_definition_must_be_json() {
        let result = ensure_well_formed(&definition("record {"), SchemaFormat::Avro);

        assert!(matches!(
            result,
            Err(AppError::Domain(DomainError::Validation(_)))
        ));
    }

    /// The Protobuf format bypasses JSON-schema validation and accepts this message declaration.
    #[test]
    fn a_protobuf_definition_is_taken_as_written() {
        let result = ensure_well_formed(&definition("message A {}"), SchemaFormat::Protobuf);

        assert!(result.is_ok());
    }
}
