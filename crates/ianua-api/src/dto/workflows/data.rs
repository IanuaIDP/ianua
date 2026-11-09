//! Workflow data on the wire: a step's input or output as plain JSON, and
//! the people and classes the bodies name.

use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::domains::workflows::data::{FieldName, FlowData, FlowValue};
use ianua_domain::message;
use ianua_domain::types::{ActionClass, ActorRef, DeclaredAction, Human};
use serde_json::{Map, Number, Value};

use crate::error::ApiError;

/// The largest whole number a JSON number carries exactly.
const EXACT_WHOLE: f64 = 9_007_199_254_740_992.0;

/// The workflow data `value` holds.
///
/// # Errors
///
/// - `422` when a number is out of range, a field name is not one a
///   workflow takes, or the data nests too deep or grows too large.
pub(crate) fn flow_data(value: &Value) -> Result<FlowData, ApiError> {
    match value {
        Value::Null => Ok(FlowData::null()),
        Value::Bool(flag) => Ok(FlowData::bool(*flag)),
        Value::Number(number) => number_of(number),
        Value::String(text) => FlowData::text(text.as_str()).map_err(ApiError::validation),
        Value::Array(items) => list_of(items),
        Value::Object(entries) => map_of(entries),
    }
}

/// The workflow number a JSON number holds, refused when it is not finite
/// or out of range.
fn number_of(number: &Number) -> Result<FlowData, ApiError> {
    let Some(value) = number.as_f64() else {
        return Err(ApiError::validation(message!(
            "api-a-workflow-number-must-be-finite",
            "a workflow number must be finite"
        )));
    };
    FlowData::number(value).map_err(ApiError::validation)
}

/// The workflow list a JSON array holds, each item read in turn.
fn list_of(items: &[Value]) -> Result<FlowData, ApiError> {
    let items = items.iter().map(flow_data).collect::<Result<Vec<_>, _>>()?;
    FlowData::list(items).map_err(ApiError::validation)
}

/// The workflow map a JSON object holds, refused when a field name is not
/// one a workflow takes.
fn map_of(entries: &Map<String, Value>) -> Result<FlowData, ApiError> {
    let entries = entries
        .iter()
        .map(|(name, value)| {
            let name = FieldName::new(name.as_str()).map_err(ApiError::validation)?;
            Ok((name, flow_data(value)?))
        })
        .collect::<Result<Vec<_>, ApiError>>()?;
    FlowData::map(entries).map_err(ApiError::validation)
}

/// `data` as plain JSON. A whole number is written without a fraction.
#[must_use]
pub fn json_of(data: &FlowData) -> Value {
    match data.value() {
        FlowValue::Null => Value::Null,
        FlowValue::Bool(flag) => Value::Bool(flag),
        FlowValue::Number(value) => json_number(value),
        FlowValue::Text(text) => Value::String(text.to_owned()),
        FlowValue::List(items) => Value::Array(items.iter().map(json_of).collect()),
        FlowValue::Map(entries) => Value::Object(
            entries
                .iter()
                .map(|(name, value)| (name.as_str().to_owned(), json_of(value)))
                .collect(),
        ),
    }
}

/// The number as JSON: a whole number without a fraction when it fits
/// exactly, otherwise as it is.
fn json_number(value: f64) -> Value {
    if value.fract() == 0.0 && value.abs() < EXACT_WHOLE {
        return Value::from(value as i64);
    }
    Number::from_f64(value).map_or(Value::Null, Value::Number)
}

/// Who `human` is, as `"<kind>:<uuid>"` for the account they acted
/// through.
#[must_use]
pub(crate) fn person_label(human: &Human) -> String {
    ActorRef::from(human.account()).audit_label()
}

/// The action class named `value`, such as `read` or `financial`.
///
/// # Errors
///
/// - `422` for a name that is not an action class.
pub fn action_class(value: &str) -> Result<ActionClass, ApiError> {
    ActionClass::parse(value).map_err(ApiError::validation)
}

/// The kind of action named `value`: `undeclared`, or an action class.
///
/// # Errors
///
/// - `422` for a name that is neither.
pub fn declared_action(value: &str) -> Result<DeclaredAction, ApiError> {
    if value == DeclaredAction::Undeclared.as_str() {
        return Ok(DeclaredAction::Undeclared);
    }
    action_class(value).map(DeclaredAction::Declared)
}

/// The data class named `value`, such as `internal`.
///
/// # Errors
///
/// - `422` for a name that is not a data class.
pub fn data_class(value: &str) -> Result<DataClassLevel, ApiError> {
    DataClassLevel::parse(value).map_err(ApiError::validation)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    /// The workflow data `value` holds, which the test expects to parse.
    fn parsed(value: &Value) -> FlowData {
        let Ok(data) = flow_data(value) else {
            panic!("the data parses");
        };
        data
    }

    /// Nested orders, a null and a note go in and come back out unchanged.
    #[test]
    fn data_comes_back_as_it_was_sent() {
        let sent = json!({"orders": [{"total": 12, "paid": true}, null], "note": "hi"});

        let back = json_of(&parsed(&sent));

        assert_eq!(back, sent);
    }

    /// `1.5` comes back as `1.5`, not rounded to a whole number.
    #[test]
    fn a_fraction_stays_a_fraction() {
        let back = json_of(&parsed(&json!(1.5)));

        assert_eq!(back, json!(1.5));
    }

    /// A field named `a.b` is refused.
    #[test]
    fn a_field_name_with_a_dot_is_refused() {
        assert!(flow_data(&json!({"a.b": 1})).is_err());
    }

    /// `undeclared` names no action class, while `financial` names that
    /// class.
    #[test]
    fn undeclared_reads_as_no_class() {
        assert_eq!(
            declared_action("undeclared").ok(),
            Some(DeclaredAction::Undeclared)
        );
        assert_eq!(
            declared_action("financial").ok(),
            Some(DeclaredAction::Declared(ActionClass::Financial))
        );
    }
}
