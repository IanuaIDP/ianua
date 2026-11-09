//! Anthropic's Messages API, as the scripted model answers it: a
//! `message` with `content` blocks, a `stop_reason` and `usage`, or the
//! same as server-sent events when `stream` is set.

use serde_json::{Value, json};

use super::script::Reply;
use super::{Received, Usage, pieces};
use crate::stack::secrets;

/// Where a message is asked for.
pub(super) const PATH: &str = "/v1/messages";

/// The header the key travels in.
pub(super) const KEY_HEADER: &str = "x-api-key";

/// The header every request names its API version in.
pub(super) const VERSION_HEADER: &str = "anthropic-version";

/// One block of an answer's content.
enum Block {
    /// Text the model wrote.
    Text(String),
    /// A call of a tool offered in `tools`.
    ToolUse {
        /// The call's id, which its result names.
        id: String,
        /// The tool.
        name: String,
        /// Arguments encoded into the scripted tool-use response.
        input: Value,
    },
}

impl Block {
    /// The block as the answer's `content` holds it.
    fn whole(&self) -> Value {
        match self {
            Self::Text(text) => json!({"type": "text", "text": text}),
            Self::ToolUse { id, name, input } => {
                json!({"type": "tool_use", "id": id, "name": name, "input": input})
            }
        }
    }

    /// The block as `content_block_start` opens it, before its deltas.
    fn opened(&self) -> Value {
        match self {
            Self::Text(_) => json!({"type": "text", "text": ""}),
            Self::ToolUse { id, name, .. } => {
                json!({"type": "tool_use", "id": id, "name": name, "input": {}})
            }
        }
    }

    /// The deltas that write the block out.
    fn deltas(&self) -> Vec<Value> {
        match self {
            Self::Text(text) => pieces(text)
                .into_iter()
                .map(|piece| json!({"type": "text_delta", "text": piece}))
                .collect(),
            Self::ToolUse { input, .. } => pieces(&input.to_string())
                .into_iter()
                .map(|piece| json!({"type": "input_json_delta", "partial_json": piece}))
                .collect(),
        }
    }
}

/// The blocks `reply` is written as, and the `stop_reason` it ends with,
/// as a native call when tools were offered natively.
fn written(reply: &Reply, received: &Received) -> (Vec<Block>, &'static str) {
    match reply {
        Reply::Text(text) => (vec![Block::Text(text.clone())], "end_turn"),
        Reply::Call { name, input } if received.offers_natively() => (
            vec![Block::ToolUse {
                id: format!("toolu_{}", secrets::hex(12)),
                name: name.clone(),
                input: input.clone(),
            }],
            "tool_use",
        ),
        Reply::Call { name, input } => (
            vec![Block::Text(Reply::call_as_text(name, input))],
            "end_turn",
        ),
        Reply::EndTurn => (Vec::new(), "end_turn"),
        Reply::MaxTokens(text) => (vec![Block::Text(text.clone())], "max_tokens"),
    }
}

/// The usage block, the cache counts as Anthropic reports them.
fn usage_of(usage: Usage) -> Value {
    json!({
        "input_tokens": usage.input,
        "output_tokens": usage.output,
        "cache_creation_input_tokens": 0,
        "cache_read_input_tokens": 0
    })
}

/// The whole answer to `received`: `reply` as a `message`.
pub(super) fn message(reply: &Reply, received: &Received, usage: Usage) -> Value {
    let (blocks, stop_reason) = written(reply, received);
    json!({
        "id": format!("msg_{}", secrets::hex(12)),
        "type": "message",
        "role": "assistant",
        "model": received.model().unwrap_or_default(),
        "content": blocks.iter().map(Block::whole).collect::<Vec<_>>(),
        "stop_reason": stop_reason,
        "stop_sequence": null,
        "usage": usage_of(usage)
    })
}

/// The answer to `received` as server-sent events: `message_start`, each
/// block opened, written in deltas and closed, `message_delta` with the
/// stop reason, `message_stop`.
pub(super) fn events(reply: &Reply, received: &Received, usage: Usage) -> String {
    let (blocks, stop_reason) = written(reply, received);
    let mut stream = event(
        "message_start",
        &json!({
            "type": "message_start",
            "message": {
                "id": format!("msg_{}", secrets::hex(12)),
                "type": "message",
                "role": "assistant",
                "model": received.model().unwrap_or_default(),
                "content": [],
                "stop_reason": null,
                "stop_sequence": null,
                "usage": {"input_tokens": usage.input, "output_tokens": 1}
            }
        }),
    );
    for (index, block) in blocks.iter().enumerate() {
        stream.push_str(&block_events(index, block));
    }
    stream.push_str(&event(
        "message_delta",
        &json!({
            "type": "message_delta",
            "delta": {"stop_reason": stop_reason, "stop_sequence": null},
            "usage": {"output_tokens": usage.output}
        }),
    ));
    stream.push_str(&event("message_stop", &json!({"type": "message_stop"})));
    stream
}

/// The events that write out `block` at `index`.
fn block_events(index: usize, block: &Block) -> String {
    let mut written = event(
        "content_block_start",
        &json!({"type": "content_block_start", "index": index, "content_block": block.opened()}),
    );
    for delta in block.deltas() {
        written.push_str(&event(
            "content_block_delta",
            &json!({"type": "content_block_delta", "index": index, "delta": delta}),
        ));
    }
    written.push_str(&event(
        "content_block_stop",
        &json!({"type": "content_block_stop", "index": index}),
    ));
    written
}

/// One server-sent event.
fn event(name: &str, data: &Value) -> String {
    format!("event: {name}\ndata: {data}\n\n")
}

/// Anthropic's error envelope.
pub(super) fn error(kind: &str, message: &str) -> Value {
    json!({"type": "error", "error": {"type": kind, "message": message}})
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::model::Format;

    fn asked(body: Value) -> Received {
        Received::new(Format::Anthropic, PATH.to_owned(), Vec::new(), body)
    }

    /// A call answers as a `tool_use` block when tools were offered.
    #[test]
    fn a_call_is_a_tool_use_block_when_tools_were_offered() {
        let received =
            asked(json!({"model": "m", "tools": [{"name": "publish_report"}], "messages": []}));

        let answer = message(
            &Reply::call("publish_report", json!({"summary": "ok"})),
            &received,
            Usage {
                input: 3,
                output: 2,
            },
        );

        assert_eq!(answer["stop_reason"], "tool_use");
        assert_eq!(answer["content"][0]["type"], "tool_use");
        assert_eq!(answer["content"][0]["input"]["summary"], "ok");
    }

    /// With no tools offered natively, a call is the JSON a platform run's
    /// prompt asks for, ending the turn.
    #[test]
    fn a_call_is_text_when_no_tools_were_offered() {
        let received = asked(json!({"model": "m", "messages": []}));

        let answer = message(
            &Reply::call("read_ticket", json!({"id": "4821"})),
            &received,
            Usage {
                input: 1,
                output: 1,
            },
        );

        assert_eq!(answer["stop_reason"], "end_turn");
        let text = answer["content"][0]["text"].as_str().unwrap();
        let call: Value = serde_json::from_str(text).unwrap();
        assert_eq!(
            call,
            json!({"tool": "read_ticket", "arguments": {"id": "4821"}})
        );
    }

    /// The streamed answer ends with the stop reason and `message_stop`.
    #[test]
    fn a_streamed_answer_ends_with_its_stop_reason() {
        let received = asked(json!({"model": "m", "stream": true, "messages": []}));

        let stream = events(
            &Reply::MaxTokens("cut".to_owned()),
            &received,
            Usage {
                input: 1,
                output: 1,
            },
        );

        assert!(stream.starts_with("event: message_start\n"));
        assert!(stream.contains(r#""stop_reason":"max_tokens""#));
        assert!(stream.ends_with("event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"));
    }
}
