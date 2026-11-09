//! A model's answer read back, whole or streamed, in either provider's
//! shape: its text, the tools it called, and why it stopped.

use serde_json::{Map, Value};

use super::ToolUse;
use crate::agent::model::Format;

/// Why the model stopped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum StopReason {
    /// It finished: `end_turn` or `stop`.
    EndTurn,
    /// It called tools and waits for their results: `tool_use` or
    /// `tool_calls`.
    ToolUse,
    /// It ran into the token cap: `max_tokens` or `length`.
    MaxTokens,
    /// Anything else, as the provider named it.
    Other(String),
}

impl StopReason {
    /// The reason a provider named `reason`.
    fn named(reason: &str) -> Self {
        match reason {
            "end_turn" | "stop" | "stop_sequence" => Self::EndTurn,
            "tool_use" | "tool_calls" => Self::ToolUse,
            "max_tokens" | "length" => Self::MaxTokens,
            other => Self::Other(other.to_owned()),
        }
    }
}

/// One answer: what the model said, the calls it made, why it stopped.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ModelTurn {
    /// Prose emitted by the model, concatenated across streamed chunks.
    pub text: String,
    /// Its calls, in order.
    pub calls: Vec<ToolUse>,
    /// Why it stopped.
    pub stop: StopReason,
}

/// Why an answer could not be read.
#[derive(Debug, thiserror::Error)]
#[error("the model's answer is not in its provider's shape: {0}")]
pub struct UnreadableAnswer(String);

/// The answer `body` holds, in `format`, streamed or whole.
///
/// # Errors
///
/// [`UnreadableAnswer`] when it is not in the provider's shape.
pub(super) fn read(
    format: Format,
    streamed: bool,
    body: &str,
) -> Result<ModelTurn, UnreadableAnswer> {
    match (format, streamed) {
        (Format::Anthropic, false) => anthropic_message(&parsed(body)?),
        (Format::Anthropic, true) => anthropic_events(body),
        (Format::OpenAi, false) => openai_completion(&parsed(body)?),
        (Format::OpenAi, true) => openai_chunks(body),
    }
}

/// `body` as JSON.
fn parsed(body: &str) -> Result<Value, UnreadableAnswer> {
    serde_json::from_str(body).map_err(|error| UnreadableAnswer(error.to_string()))
}

/// A Messages answer.
fn anthropic_message(message: &Value) -> Result<ModelTurn, UnreadableAnswer> {
    let blocks = message
        .get("content")
        .and_then(Value::as_array)
        .ok_or_else(|| UnreadableAnswer("no content".to_owned()))?;
    let mut text = String::new();
    let mut calls = Vec::new();
    for block in blocks {
        match block.get("type").and_then(Value::as_str) {
            Some("text") => text.push_str(block.get("text").and_then(Value::as_str).unwrap_or("")),
            Some("tool_use") => calls.push(tool_use_of(block)?),
            _ => {}
        }
    }
    let stop = stop_of(message.get("stop_reason"))?;
    Ok(ModelTurn { text, calls, stop })
}

/// The call a `tool_use` block makes.
fn tool_use_of(block: &Value) -> Result<ToolUse, UnreadableAnswer> {
    let field = |name: &str| {
        block
            .get(name)
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| UnreadableAnswer(format!("a tool_use without {name}")))
    };
    Ok(ToolUse {
        id: field("id")?,
        name: field("name")?,
        input: block
            .get("input")
            .cloned()
            .unwrap_or(Value::Object(Map::new())),
    })
}

/// The stop reason a provider named in `reason`.
fn stop_of(reason: Option<&Value>) -> Result<StopReason, UnreadableAnswer> {
    reason
        .and_then(Value::as_str)
        .map(StopReason::named)
        .ok_or_else(|| UnreadableAnswer("no stop reason".to_owned()))
}

/// A block a stream is writing out.
enum Writing {
    /// Text, so far.
    Text(String),
    /// A call, its input JSON so far.
    Call {
        /// The call's id.
        id: String,
        /// The tool.
        name: String,
        /// The input's JSON text so far.
        partial: String,
    },
}

/// A Messages answer streamed as server-sent events.
fn anthropic_events(body: &str) -> Result<ModelTurn, UnreadableAnswer> {
    let mut blocks: Vec<Writing> = Vec::new();
    let mut stop = None;
    for data in data_lines(body) {
        let event = parsed(data)?;
        match event.get("type").and_then(Value::as_str) {
            Some("content_block_start") => blocks.push(opened(&event)?),
            Some("content_block_delta") => append_delta(&mut blocks, &event),
            Some("message_delta") => {
                stop = event
                    .get("delta")
                    .and_then(|delta| delta.get("stop_reason"))
                    .cloned();
            }
            _ => {}
        }
    }
    finished(blocks, stop.as_ref())
}

/// The block a `content_block_start` opens.
fn opened(event: &Value) -> Result<Writing, UnreadableAnswer> {
    let block = event
        .get("content_block")
        .ok_or_else(|| UnreadableAnswer("a block start without its block".to_owned()))?;
    match block.get("type").and_then(Value::as_str) {
        Some("tool_use") => {
            let call = tool_use_of(block)?;
            Ok(Writing::Call {
                id: call.id,
                name: call.name,
                partial: String::new(),
            })
        }
        _ => Ok(Writing::Text(String::new())),
    }
}

/// Adds a `content_block_delta` to the block it writes, the last opened.
fn append_delta(blocks: &mut [Writing], event: &Value) {
    let Some(delta) = event.get("delta") else {
        return;
    };
    let Some(block) = blocks.last_mut() else {
        return;
    };
    match block {
        Writing::Text(text) => {
            text.push_str(delta.get("text").and_then(Value::as_str).unwrap_or(""));
        }
        Writing::Call { partial, .. } => {
            partial.push_str(
                delta
                    .get("partial_json")
                    .and_then(Value::as_str)
                    .unwrap_or(""),
            );
        }
    }
}

/// The answer the streamed `blocks` and `stop` make.
fn finished(blocks: Vec<Writing>, stop: Option<&Value>) -> Result<ModelTurn, UnreadableAnswer> {
    let mut text = String::new();
    let mut calls = Vec::new();
    for block in blocks {
        match block {
            Writing::Text(written) => text.push_str(&written),
            Writing::Call { id, name, partial } => calls.push(ToolUse {
                id,
                name,
                input: input_of(&partial)?,
            }),
        }
    }
    Ok(ModelTurn {
        text,
        calls,
        stop: stop_of(stop)?,
    })
}

/// A call's input from its JSON text, an empty one read as no arguments.
fn input_of(json: &str) -> Result<Value, UnreadableAnswer> {
    if json.trim().is_empty() {
        return Ok(Value::Object(Map::new()));
    }
    parsed(json)
}

/// A Chat Completions answer.
fn openai_completion(completion: &Value) -> Result<ModelTurn, UnreadableAnswer> {
    let choice = completion
        .get("choices")
        .and_then(|choices| choices.get(0))
        .ok_or_else(|| UnreadableAnswer("no choice".to_owned()))?;
    let message = choice.get("message").cloned().unwrap_or(Value::Null);
    let text = message
        .get("content")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
    let calls = message
        .get("tool_calls")
        .and_then(Value::as_array)
        .map(|calls| calls.iter().map(openai_call).collect::<Result<Vec<_>, _>>())
        .transpose()?
        .unwrap_or_default();
    let stop = stop_of(choice.get("finish_reason"))?;
    Ok(ModelTurn { text, calls, stop })
}

/// The call one `tool_calls` entry makes.
fn openai_call(call: &Value) -> Result<ToolUse, UnreadableAnswer> {
    let id = call
        .get("id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
    let function = call.get("function").cloned().unwrap_or(Value::Null);
    let name = function
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| UnreadableAnswer("a tool call without its name".to_owned()))?
        .to_owned();
    let arguments = function
        .get("arguments")
        .and_then(Value::as_str)
        .unwrap_or("");
    Ok(ToolUse {
        id,
        name,
        input: input_of(arguments)?,
    })
}

/// A Chat Completions answer streamed as chunks, ending with `[DONE]`.
fn openai_chunks(body: &str) -> Result<ModelTurn, UnreadableAnswer> {
    let mut text = String::new();
    let mut calls: Vec<Writing> = Vec::new();
    let mut stop = None;
    for data in data_lines(body).filter(|data| *data != "[DONE]") {
        let chunk = parsed(data)?;
        let Some(choice) = chunk.get("choices").and_then(|choices| choices.get(0)) else {
            continue;
        };
        if let Some(delta) = choice.get("delta") {
            text.push_str(delta.get("content").and_then(Value::as_str).unwrap_or(""));
            append_calls(&mut calls, delta);
        }
        if let Some(reason) = choice
            .get("finish_reason")
            .filter(|reason| !reason.is_null())
        {
            stop = Some(reason.clone());
        }
    }
    let turn = finished(calls, stop.as_ref())?;
    Ok(ModelTurn { text, ..turn })
}

/// Adds the `tool_calls` of a chunk's `delta` to the calls being written:
/// one carrying an id opens a call, the rest add to its arguments.
fn append_calls(calls: &mut Vec<Writing>, delta: &Value) {
    let Some(parts) = delta.get("tool_calls").and_then(Value::as_array) else {
        return;
    };
    for part in parts {
        let function = part.get("function");
        let arguments = function
            .and_then(|function| function.get("arguments"))
            .and_then(Value::as_str)
            .unwrap_or("");
        if let Some(id) = part.get("id").and_then(Value::as_str) {
            let name = function
                .and_then(|function| function.get("name"))
                .and_then(Value::as_str)
                .unwrap_or("");
            calls.push(Writing::Call {
                id: id.to_owned(),
                name: name.to_owned(),
                partial: arguments.to_owned(),
            });
            continue;
        }
        if let Some(Writing::Call { partial, .. }) = calls.last_mut() {
            partial.push_str(arguments);
        }
    }
}

/// The `data:` payloads of a server-sent event stream, in order.
fn data_lines(body: &str) -> impl Iterator<Item = &str> {
    body.lines()
        .filter_map(|line| line.strip_prefix("data:"))
        .map(str::trim)
        .filter(|data| !data.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A streamed tool call is put back together from its partial JSON.
    #[test]
    fn a_streamed_tool_call_is_put_together() {
        let stream = concat!(
            "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{}}\n\n",
            "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"tool_use\",\"id\":\"t1\",\"name\":\"publish_report\",\"input\":{}}}\n\n",
            "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"summary\\\":\"}}\n\n",
            "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"\\\"down\\\"}\"}}\n\n",
            "event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"tool_use\"}}\n\n",
            "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
        );

        let turn = read(Format::Anthropic, true, stream).unwrap();

        assert_eq!(turn.stop, StopReason::ToolUse);
        assert_eq!(turn.calls[0].name, "publish_report");
        assert_eq!(turn.calls[0].input["summary"], "down");
    }

    /// OpenAI's chunks put the text back together, and finish as asked.
    #[test]
    fn openai_chunks_put_the_text_together() {
        let stream = concat!(
            "data: {\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"\"},\"finish_reason\":null}]}\n\n",
            "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"all \"},\"finish_reason\":null}]}\n\n",
            "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"done\"},\"finish_reason\":null}]}\n\n",
            "data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n",
            "data: [DONE]\n\n",
        );

        let turn = read(Format::OpenAi, true, stream).unwrap();

        assert_eq!(turn.text, "all done");
        assert_eq!(turn.stop, StopReason::EndTurn);
        assert!(turn.calls.is_empty());
    }
}
