//! OpenAI's Chat Completions, as the scripted model answers it: a
//! `chat.completion` with one choice, its `finish_reason` and `usage`, or
//! `chat.completion.chunk`s as server-sent events when `stream` is set,
//! ending with `[DONE]`.

use serde_json::{Value, json};

use super::script::Reply;
use super::{Received, Usage, pieces};
use crate::stack::secrets;

/// Where a completion is asked for, under the API base `…/v1`.
pub(super) const PATH: &str = "/v1/chat/completions";

/// What the assistant's message says: its text, or a native call.
enum Said {
    /// Text, or nothing.
    Text(String),
    /// A call of a tool offered in `tools`.
    Call {
        /// The call's id, which its result names.
        id: String,
        /// The tool.
        name: String,
        /// Its arguments, as the JSON text OpenAI sends them in.
        arguments: String,
    },
}

/// What `reply` says, and the `finish_reason` it ends with, as a native
/// call when tools were offered natively.
fn said(reply: &Reply, received: &Received) -> (Said, &'static str) {
    match reply {
        Reply::Text(text) => (Said::Text(text.clone()), "stop"),
        Reply::Call { name, input } if received.offers_natively() => (
            Said::Call {
                id: format!("call_{}", secrets::hex(12)),
                name: name.clone(),
                arguments: input.to_string(),
            },
            "tool_calls",
        ),
        Reply::Call { name, input } => (Said::Text(Reply::call_as_text(name, input)), "stop"),
        Reply::EndTurn => (Said::Text(String::new()), "stop"),
        Reply::MaxTokens(text) => (Said::Text(text.clone()), "length"),
    }
}

/// The usage block.
fn usage_of(usage: Usage) -> Value {
    json!({
        "prompt_tokens": usage.input,
        "completion_tokens": usage.output,
        "total_tokens": usage.input.saturating_add(usage.output)
    })
}

/// The whole answer to `received`: `reply` as a `chat.completion`.
pub(super) fn completion(reply: &Reply, received: &Received, usage: Usage) -> Value {
    let (said, finish_reason) = said(reply, received);
    let message = match said {
        Said::Text(text) => json!({"role": "assistant", "content": text, "refusal": null}),
        Said::Call {
            id,
            name,
            arguments,
        } => json!({
            "role": "assistant",
            "content": null,
            "refusal": null,
            "tool_calls": [{"id": id, "type": "function", "function": {"name": name, "arguments": arguments}}]
        }),
    };
    json!({
        "id": format!("chatcmpl-{}", secrets::hex(12)),
        "object": "chat.completion",
        "created": now(),
        "model": received.model().unwrap_or_default(),
        "choices": [{"index": 0, "message": message, "finish_reason": finish_reason}],
        "usage": usage_of(usage)
    })
}

/// The answer to `received` as server-sent chunks: the role, the text or
/// the call in pieces, the finish, the usage when `stream_options` asks
/// for it, and `[DONE]`.
pub(super) fn chunks(reply: &Reply, received: &Received, usage: Usage) -> String {
    let id = format!("chatcmpl-{}", secrets::hex(12));
    let model = received.model().unwrap_or_default().to_owned();
    let chunk = |delta: Value, finish: Value| {
        data(&json!({
            "id": id,
            "object": "chat.completion.chunk",
            "created": now(),
            "model": model,
            "choices": [{"index": 0, "delta": delta, "finish_reason": finish}]
        }))
    };
    let (said, finish_reason) = said(reply, received);
    let mut stream = chunk(json!({"role": "assistant", "content": ""}), Value::Null);
    for delta in deltas(&said) {
        stream.push_str(&chunk(delta, Value::Null));
    }
    stream.push_str(&chunk(json!({}), json!(finish_reason)));
    if wants_usage(received) {
        stream.push_str(&data(&json!({
            "id": id,
            "object": "chat.completion.chunk",
            "created": now(),
            "model": model,
            "choices": [],
            "usage": usage_of(usage)
        })));
    }
    stream.push_str("data: [DONE]\n\n");
    stream
}

/// The deltas that write out what was said.
fn deltas(said: &Said) -> Vec<Value> {
    match said {
        Said::Text(text) => pieces(text)
            .into_iter()
            .map(|piece| json!({"content": piece}))
            .collect(),
        Said::Call {
            id,
            name,
            arguments,
        } => {
            let opened = json!({"tool_calls": [{
                "index": 0, "id": id, "type": "function",
                "function": {"name": name, "arguments": ""}
            }]});
            let parts = pieces(arguments).into_iter().map(
                |piece| json!({"tool_calls": [{"index": 0, "function": {"arguments": piece}}]}),
            );
            std::iter::once(opened).chain(parts).collect()
        }
    }
}

/// Whether the request asked for a usage chunk at the end of the stream.
fn wants_usage(received: &Received) -> bool {
    received
        .body()
        .get("stream_options")
        .and_then(|options| options.get("include_usage"))
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

/// One server-sent chunk.
fn data(chunk: &Value) -> String {
    format!("data: {chunk}\n\n")
}

/// The time now, in seconds since the epoch, as `created` carries it.
fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

/// OpenAI's error envelope.
pub(super) fn error(kind: &str, code: &str, message: &str) -> Value {
    json!({"error": {"message": message, "type": kind, "param": null, "code": code}})
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::model::Format;

    fn asked(body: Value) -> Received {
        Received::new(Format::OpenAi, PATH.to_owned(), Vec::new(), body)
    }

    /// A call answers as `tool_calls` with its arguments as JSON text when
    /// tools were offered.
    #[test]
    fn a_call_is_tool_calls_when_tools_were_offered() {
        let received = asked(json!({
            "model": "m",
            "tools": [{"type": "function", "function": {"name": "publish_report"}}],
            "messages": []
        }));

        let answer = completion(
            &Reply::call("publish_report", json!({"summary": "ok"})),
            &received,
            Usage {
                input: 2,
                output: 2,
            },
        );

        let choice = &answer["choices"][0];
        assert_eq!(choice["finish_reason"], "tool_calls");
        let arguments = choice["message"]["tool_calls"][0]["function"]["arguments"]
            .as_str()
            .unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(arguments).unwrap(),
            json!({"summary": "ok"})
        );
    }

    /// A cut-off answer finishes with `length`.
    #[test]
    fn a_cut_off_answer_finishes_with_length() {
        let answer = completion(
            &Reply::MaxTokens("half".to_owned()),
            &asked(json!({"messages": []})),
            Usage {
                input: 1,
                output: 1,
            },
        );

        assert_eq!(answer["choices"][0]["finish_reason"], "length");
    }

    /// A stream ends with `[DONE]`, the usage chunk before it when asked.
    #[test]
    fn a_stream_ends_with_done_and_its_usage_when_asked() {
        let received = asked(
            json!({"stream": true, "stream_options": {"include_usage": true}, "messages": []}),
        );

        let stream = chunks(
            &Reply::text("hello there"),
            &received,
            Usage {
                input: 4,
                output: 3,
            },
        );

        assert!(stream.ends_with("data: [DONE]\n\n"));
        assert!(stream.contains(r#""completion_tokens":3"#));
        assert!(stream.contains(r#""finish_reason":"stop""#));
    }
}
