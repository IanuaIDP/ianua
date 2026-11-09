//! Values in and out of MySQL: a step's parameters bound in order as typed
//! values, and each row read back as named values a workflow holds.
//!
//! A value is never pasted into a statement: it travels apart from it, as a
//! bound parameter. MySQL's binary protocol says each column's type, so a
//! row reads back as numbers, text and moments, never guessed from text.

use ianua_domain::domains::workflows::execution::step::ActionOutcome;
use ianua_integration::answer::failed;
use mysql_async::{Params, Row};
use serde_json::{Map, Number, Value};

/// `parameters`, a list of values or nothing, bound in order.
///
/// # Errors
///
/// A failed outcome when `parameters` is not a list, or holds a list or an
/// object.
pub(crate) fn bound(parameters: &Value) -> Result<Params, ActionOutcome> {
    let given: &[Value] = match parameters {
        Value::Null => &[],
        Value::Array(values) => values,
        _ => return Err(failed("the parameters are not a list of values")),
    };
    if given.is_empty() {
        return Ok(Params::Empty);
    }
    given
        .iter()
        .enumerate()
        .map(|(index, value)| value_for(value, index + 1))
        .collect::<Result<_, _>>()
        .map(Params::Positional)
}

/// `value` as parameter `position`.
fn value_for(value: &Value, position: usize) -> Result<mysql_async::Value, ActionOutcome> {
    match value {
        Value::Null => Ok(mysql_async::Value::NULL),
        Value::Bool(flag) => Ok(mysql_async::Value::Int(i64::from(*flag))),
        Value::Number(number) => Ok(number_of(number)),
        Value::String(text) => Ok(mysql_async::Value::Bytes(text.as_bytes().to_vec())),
        Value::Array(_) | Value::Object(_) => Err(failed(&format!(
            "value {position} is a list or an object; send it as text, such as JSON"
        ))),
    }
}

/// `number` as MySQL's whole or fractional number.
fn number_of(number: &Number) -> mysql_async::Value {
    if let Some(whole) = number.as_i64() {
        return mysql_async::Value::Int(whole);
    }
    if let Some(whole) = number.as_u64() {
        return mysql_async::Value::UInt(whole);
    }
    mysql_async::Value::Double(number.as_f64().unwrap_or(f64::NAN))
}

/// `row`'s columns as named values.
///
/// # Errors
///
/// A failed outcome naming a column holding bytes that are not text.
pub(crate) fn row_values(row: &Row) -> Result<Map<String, Value>, ActionOutcome> {
    row.columns_ref()
        .iter()
        .enumerate()
        .map(|(index, column)| {
            let name = column.name_str().into_owned();
            let value = row
                .as_ref(index)
                .map_or(Ok(Value::Null), |value| read(value, &name))?;
            Ok((name, value))
        })
        .collect()
}

/// One column's `value` as a value a workflow holds.
fn read(value: &mysql_async::Value, column: &str) -> Result<Value, ActionOutcome> {
    match value {
        mysql_async::Value::NULL => Ok(Value::Null),
        mysql_async::Value::Int(number) => Ok(Value::from(*number)),
        mysql_async::Value::UInt(number) => Ok(Value::from(*number)),
        mysql_async::Value::Float(number) => Ok(fraction(f64::from(*number))),
        mysql_async::Value::Double(number) => Ok(fraction(*number)),
        mysql_async::Value::Bytes(bytes) => String::from_utf8(bytes.clone())
            .map(Value::String)
            .map_err(|_| {
                failed(&format!(
                    "the column {column} holds bytes that are not text; convert it, such as HEX({column})"
                ))
            }),
        mysql_async::Value::Date(year, month, day, hour, minute, second, micros) => {
            Ok(Value::String(format!(
                "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{micros:06}"
            )))
        }
        mysql_async::Value::Time(negative, days, hours, minutes, seconds, micros) => {
            let sign = if *negative { "-" } else { "" };
            let hours = u64::from(*days) * 24 + u64::from(*hours);
            Ok(Value::String(format!(
                "{sign}{hours:02}:{minutes:02}:{seconds:02}.{micros:06}"
            )))
        }
    }
}

/// `number` as a value, or null when it is not a finite number.
fn fraction(number: f64) -> Value {
    Number::from_f64(number).map_or(Value::Null, Value::Number)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    /// A step's values are bound in order with their own types.
    #[test]
    fn parameters_are_bound_in_order() {
        let Params::Positional(values) = bound(&json!([7, "open", true, null])).unwrap() else {
            panic!("values are bound by position");
        };

        assert_eq!(
            values,
            [
                mysql_async::Value::Int(7),
                mysql_async::Value::Bytes(b"open".to_vec()),
                mysql_async::Value::Int(1),
                mysql_async::Value::NULL,
            ]
        );
    }

    /// A parameter list containing an object fails MySQL value binding.
    #[test]
    fn an_object_value_is_refused() {
        assert!(bound(&json!([{ "a": 1 }])).is_err());
    }

    /// A moment reads back as one text.
    #[test]
    fn a_moment_reads_as_text() {
        let read = read(&mysql_async::Value::Date(2026, 11, 5, 9, 30, 0, 0), "at").unwrap();

        assert_eq!(read, json!("2026-11-05T09:30:00.000000"));
    }

    /// Invalid UTF-8 in a byte column fails conversion to workflow data.
    #[test]
    fn bytes_that_are_not_text_are_refused() {
        assert!(read(&mysql_async::Value::Bytes(vec![0xff]), "photo").is_err());
    }
}
