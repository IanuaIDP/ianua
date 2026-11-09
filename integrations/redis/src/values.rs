//! Values in and out of Redis: a step's arguments sent as the words of the
//! command, and Redis's answer read back as values a workflow holds.

use ianua_domain::domains::workflows::execution::step::ActionOutcome;
use ianua_integration::answer::failed;
use serde_json::{Map, Number, Value};

/// `arguments`, a list of texts, numbers and flags or nothing, as the
/// command's words.
///
/// # Errors
///
/// A failed outcome when `arguments` is not a list, or holds a list or an
/// object.
pub(crate) fn words_of(arguments: &Value) -> Result<Vec<Vec<u8>>, ActionOutcome> {
    let given: &[Value] = match arguments {
        Value::Null => &[],
        Value::Array(values) => values,
        _ => return Err(failed("the arguments are not a list of values")),
    };
    given.iter().map(word_of).collect()
}

/// One argument as a word of the command.
fn word_of(value: &Value) -> Result<Vec<u8>, ActionOutcome> {
    match value {
        Value::String(text) => Ok(text.as_bytes().to_vec()),
        Value::Number(number) => Ok(number.to_string().into_bytes()),
        Value::Bool(flag) => Ok(u8::from(*flag).to_string().into_bytes()),
        Value::Null | Value::Array(_) | Value::Object(_) => Err(failed(
            "each argument is a text, a number or a flag, never a list, an object or nothing",
        )),
    }
}

/// Redis's `answer` as a value a workflow holds.
///
/// # Errors
///
/// A failed outcome when the answer holds bytes that are not text, or a
/// kind of answer a step cannot read.
pub(crate) fn answer_of(answer: &redis::Value) -> Result<Value, ActionOutcome> {
    match answer {
        redis::Value::Nil => Ok(Value::Null),
        redis::Value::Int(number) => Ok(Value::from(*number)),
        redis::Value::BulkString(bytes) => text_of(bytes),
        redis::Value::SimpleString(text) => Ok(Value::String(text.clone())),
        redis::Value::Okay => Ok(Value::String("OK".to_owned())),
        redis::Value::Boolean(flag) => Ok(Value::Bool(*flag)),
        redis::Value::Double(number) => Number::from_f64(*number)
            .map(Value::Number)
            .ok_or_else(|| failed("the answer is a number a workflow cannot hold")),
        redis::Value::VerbatimString { text, .. } => Ok(Value::String(text.clone())),
        redis::Value::Array(items) | redis::Value::Set(items) => items
            .iter()
            .map(answer_of)
            .collect::<Result<_, _>>()
            .map(Value::Array),
        redis::Value::Map(pairs) => map_of(pairs),
        _ => Err(failed("the answer is of a kind a step cannot read")),
    }
}

/// A map answer as an object, its keys read as text.
fn map_of(pairs: &[(redis::Value, redis::Value)]) -> Result<Value, ActionOutcome> {
    let mut object = Map::with_capacity(pairs.len());
    for (key, value) in pairs {
        let Value::String(key) = answer_of(key)? else {
            return Err(failed("the answer is a map whose keys are not text"));
        };
        object.insert(key, answer_of(value)?);
    }
    Ok(Value::Object(object))
}

/// `bytes` as text.
fn text_of(bytes: &[u8]) -> Result<Value, ActionOutcome> {
    String::from_utf8(bytes.to_vec())
        .map(Value::String)
        .map_err(|_| failed("the answer holds bytes that are not text"))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    /// Texts, numbers and flags become the command's words.
    #[test]
    fn arguments_become_words() {
        let words = words_of(&json!(["orders:1", 30, true])).unwrap();

        assert_eq!(words, [b"orders:1".to_vec(), b"30".to_vec(), b"1".to_vec()]);
    }

    /// An object in the argument list fails conversion to Redis command words.
    #[test]
    fn an_object_argument_is_refused() {
        assert!(words_of(&json!([{ "a": 1 }])).is_err());
    }

    /// A hash read with RESP2 comes back as a list of texts, and nested
    /// answers keep their shape.
    #[test]
    fn answers_keep_their_shape() {
        let answer = redis::Value::Array(vec![
            redis::Value::BulkString(b"total".to_vec()),
            redis::Value::Int(42),
            redis::Value::Nil,
        ]);

        assert_eq!(answer_of(&answer).unwrap(), json!(["total", 42, null]));
    }

    /// A Redis bulk string containing invalid UTF-8 fails answer conversion.
    #[test]
    fn bytes_that_are_not_text_are_refused() {
        let answer = redis::Value::BulkString(vec![0xff, 0xfe]);

        assert!(answer_of(&answer).is_err());
    }
}
