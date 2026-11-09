//! Reading a step's arguments: the values a workflow built from the step's
//! input, one per input its operation declares.

use ianua_domain::domains::workflows::data::{FieldName, FlowData, FlowValue};
use ianua_domain::domains::workflows::execution::step::ActionOutcome;

use crate::answer::failed;

/// The argument `name`, when the step gave one that is not null.
#[must_use]
pub fn argument<'a>(arguments: &'a FlowData, name: &str) -> Option<&'a FlowData> {
    let name = FieldName::new(name).ok()?;
    arguments.field(&name).filter(|value| !value.is_null())
}

/// The text argument `name`, which the operation does not run without.
///
/// # Errors
///
/// A failed outcome when the step gave no such text, or empty text.
pub fn required_text<'a>(arguments: &'a FlowData, name: &str) -> Result<&'a str, ActionOutcome> {
    match optional_text(arguments, name)? {
        Some(text) if !text.trim().is_empty() => Ok(text),
        Some(_) | None => Err(failed(&format!("the {name} is missing"))),
    }
}

/// The text argument `name`, when the step gave one.
///
/// # Errors
///
/// A failed outcome when the step gave a value that is not text.
pub fn optional_text<'a>(
    arguments: &'a FlowData,
    name: &str,
) -> Result<Option<&'a str>, ActionOutcome> {
    let Some(given) = argument(arguments, name) else {
        return Ok(None);
    };
    let FlowValue::Text(text) = given.value() else {
        return Err(failed(&format!("the {name} is not text")));
    };
    Ok(Some(text))
}

/// The whole positive number `name`, which the operation does not run
/// without, given as a number or as its digits.
///
/// # Errors
///
/// A failed outcome when the step gave none, or a value that is no whole
/// number above zero.
pub fn required_count(arguments: &FlowData, name: &str) -> Result<u64, ActionOutcome> {
    let Some(given) = argument(arguments, name) else {
        return Err(failed(&format!("the {name} is missing")));
    };
    count_of(given).ok_or_else(|| failed(&format!("the {name} is not a whole number above zero")))
}

/// The list of whole positive numbers `name`, empty when the step gave
/// none, each given as a number or as its digits.
///
/// # Errors
///
/// A failed outcome when the step gave something other than a list of
/// whole numbers above zero.
pub(crate) fn count_list(arguments: &FlowData, name: &str) -> Result<Vec<u64>, ActionOutcome> {
    let Some(given) = argument(arguments, name) else {
        return Ok(Vec::new());
    };
    let FlowValue::List(items) = given.value() else {
        return Err(failed(&format!("the {name} is not a list")));
    };
    items
        .iter()
        .map(|item| {
            count_of(item).ok_or_else(|| {
                failed(&format!(
                    "the {name} holds a value that is no whole number above zero"
                ))
            })
        })
        .collect()
}

/// `given` as a whole number above zero, when it is one.
fn count_of(given: &FlowData) -> Option<u64> {
    let read = match given.value() {
        FlowValue::Number(number) => whole(number),
        FlowValue::Text(digits) => digits.trim().parse::<u64>().ok(),
        FlowValue::Null | FlowValue::Bool(_) | FlowValue::List(_) | FlowValue::Map(_) => None,
    };
    read.filter(|count| *count > 0)
}

/// The text list `name`, empty when the step gave none.
///
/// # Errors
///
/// A failed outcome when the step gave something other than a list of
/// text.
pub(crate) fn text_list<'a>(
    arguments: &'a FlowData,
    name: &str,
) -> Result<Vec<&'a str>, ActionOutcome> {
    let Some(given) = argument(arguments, name) else {
        return Ok(Vec::new());
    };
    let FlowValue::List(items) = given.value() else {
        return Err(failed(&format!("the {name} is not a list")));
    };
    items
        .iter()
        .map(|item| match item.value() {
            FlowValue::Text(text) => Ok(text),
            _ => Err(failed(&format!(
                "the {name} holds a value that is not text"
            ))),
        })
        .collect()
}

/// The yes-or-no argument `name`, when the step gave one.
///
/// # Errors
///
/// A failed outcome when the step gave a value that is not true or false.
pub fn optional_flag(arguments: &FlowData, name: &str) -> Result<Option<bool>, ActionOutcome> {
    let Some(given) = argument(arguments, name) else {
        return Ok(None);
    };
    let FlowValue::Bool(flag) = given.value() else {
        return Err(failed(&format!("the {name} is not true or false")));
    };
    Ok(Some(flag))
}

/// The argument `name` as JSON, whatever values it holds, when the step
/// gave one: such as named inputs handed on to a service as they are.
///
/// # Errors
///
/// A failed outcome when the values cannot be written as JSON.
pub fn optional_values(
    arguments: &FlowData,
    name: &str,
) -> Result<Option<serde_json::Value>, ActionOutcome> {
    let Some(given) = argument(arguments, name) else {
        return Ok(None);
    };
    serde_json::from_str(&given.render())
        .map(Some)
        .map_err(|_| failed(&format!("the {name} cannot be sent as JSON")))
}

/// `number` as a whole count, when it is one: read back from how it is
/// written, so a fraction or a sign never rounds into another count.
fn whole(number: f64) -> Option<u64> {
    number.to_string().parse::<u64>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arguments(entries: Vec<(&str, FlowData)>) -> FlowData {
        FlowData::map(
            entries
                .into_iter()
                .map(|(name, value)| (FieldName::new(name).unwrap(), value))
                .collect(),
        )
        .unwrap()
    }

    /// A required text argument reads as given.
    #[test]
    fn a_required_text_reads_as_given() {
        let given = arguments(vec![("title", FlowData::text("Build broke").unwrap())]);

        assert_eq!(required_text(&given, "title").unwrap(), "Build broke");
    }

    /// Required text rejects both a title containing only spaces and an
    /// absent body argument.
    #[test]
    fn a_blank_or_missing_required_text_fails() {
        let given = arguments(vec![("title", FlowData::text("   ").unwrap())]);

        assert!(matches!(
            required_text(&given, "title"),
            Err(ActionOutcome::Failed(_))
        ));
        assert!(required_text(&given, "body").is_err());
    }

    /// An issue number reads from a number or from its digits, never from
    /// a fraction, zero or a word.
    #[test]
    fn a_count_reads_from_a_number_or_its_digits() {
        let given = arguments(vec![
            ("number", FlowData::number(42.0).unwrap()),
            ("digits", FlowData::text("7").unwrap()),
            ("fraction", FlowData::number(1.5).unwrap()),
            ("zero", FlowData::number(0.0).unwrap()),
            ("word", FlowData::text("seven").unwrap()),
        ]);

        assert_eq!(required_count(&given, "number").unwrap(), 42);
        assert_eq!(required_count(&given, "digits").unwrap(), 7);
        for refused in ["fraction", "zero", "word", "missing"] {
            assert!(required_count(&given, refused).is_err(), "{refused}");
        }
    }

    /// A flag reads as given; a word is refused.
    #[test]
    fn a_flag_reads_true_or_false_only() {
        let given = arguments(vec![
            ("draft", FlowData::bool(true)),
            ("word", FlowData::text("yes").unwrap()),
        ]);

        assert_eq!(optional_flag(&given, "draft").unwrap(), Some(true));
        assert_eq!(optional_flag(&given, "absent").unwrap(), None);
        assert!(optional_flag(&given, "word").is_err());
    }

    /// Named values are handed on as the JSON they are.
    #[test]
    fn values_are_handed_on_as_json() {
        let inputs = FlowData::map(vec![(
            FieldName::new("environment").unwrap(),
            FlowData::text("staging").unwrap(),
        )])
        .unwrap();
        let given = arguments(vec![("inputs", inputs)]);

        let values = optional_values(&given, "inputs").unwrap();

        assert_eq!(
            values,
            Some(serde_json::json!({ "environment": "staging" }))
        );
    }

    /// A text list reads in order; one holding a number is refused.
    #[test]
    fn a_text_list_reads_in_order_and_refuses_other_values() {
        let labels = FlowData::list(vec![
            FlowData::text("bug").unwrap(),
            FlowData::text("urgent").unwrap(),
        ])
        .unwrap();
        let mixed = FlowData::list(vec![
            FlowData::text("bug").unwrap(),
            FlowData::number(1.0).unwrap(),
        ])
        .unwrap();
        let given = arguments(vec![("labels", labels), ("mixed", mixed)]);

        assert_eq!(text_list(&given, "labels").unwrap(), ["bug", "urgent"]);
        assert!(text_list(&given, "absent").unwrap().is_empty());
        assert!(text_list(&given, "mixed").is_err());
    }
}
