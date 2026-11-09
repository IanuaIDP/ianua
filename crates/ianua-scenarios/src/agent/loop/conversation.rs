//! A conversation with a model, kept the way a tool-using SDK keeps it,
//! and written out in either provider's request shape.

use serde_json::{Value, json};

use super::llm::Sampling;
use super::{ToolSpec, ToolUse};
use crate::agent::model::Format;

/// The most tokens one answer may take.
const ANSWER_TOKENS: u32 = 1024;

/// The API version every Anthropic request names.
pub(super) const ANTHROPIC_VERSION: &str = "2023-06-01";

/// One turn of the conversation.
#[derive(Debug, Clone, PartialEq)]
pub(super) enum Entry {
    /// What the user said.
    User(String),
    /// What the model said, and the tools it called.
    Assistant {
        /// Prose the model emitted alongside any tool requests.
        text: String,
        /// Ordered tool requests whose results must enter the conversation next.
        calls: Vec<ToolUse>,
    },
    /// The results of the model's calls, one for each.
    Results(Vec<ToolResult>),
}

/// The result of one call, fed back to the model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ToolResult {
    /// The call it answers.
    pub(super) call_id: String,
    /// What the tool said.
    pub(super) content: String,
    /// Whether the tool failed or was refused.
    pub(super) is_error: bool,
}

/// What one request asks: the system prompt, the tools offered, the
/// conversation so far, and whether to stream.
pub(super) struct Asking<'a> {
    /// The model asked for.
    pub(super) model: &'a str,
    /// The system prompt.
    pub(super) system: &'a str,
    /// The tools offered.
    pub(super) tools: &'a [ToolSpec],
    /// The conversation so far.
    pub(super) history: &'a [Entry],
    /// Whether the answer comes as server-sent events.
    pub(super) streaming: bool,
    /// How the model is asked to sample.
    pub(super) sampling: Sampling,
}

/// `body` asked to sample as `sampling`: at temperature zero, with the
/// seed where the format takes one, or as the provider likes.
fn sampled(mut body: Value, format: Format, sampling: Sampling) -> Value {
    let Sampling::Fixed { seed } = sampling else {
        return body;
    };
    body["temperature"] = json!(0);
    if let (Format::OpenAi, Some(seed)) = (format, seed) {
        body["seed"] = json!(seed);
    }
    body
}

/// The body asking for the next turn in `format`.
pub(super) fn body(format: Format, asking: &Asking<'_>) -> Value {
    let body = match format {
        Format::Anthropic => anthropic_body(asking),
        Format::OpenAi => openai_body(asking),
    };
    sampled(body, format, asking.sampling)
}

/// A Messages request.
fn anthropic_body(asking: &Asking<'_>) -> Value {
    let tools: Vec<Value> = asking
        .tools
        .iter()
        .map(|tool| {
            json!({"name": tool.name, "description": tool.description, "input_schema": tool.input_schema})
        })
        .collect();
    let messages: Vec<Value> = asking.history.iter().map(anthropic_message).collect();
    let mut body = json!({
        "model": asking.model,
        "max_tokens": ANSWER_TOKENS,
        "system": asking.system,
        "messages": messages,
        "stream": asking.streaming
    });
    if !tools.is_empty() {
        body["tools"] = Value::Array(tools);
    }
    body
}

/// One entry as a Messages turn.
fn anthropic_message(entry: &Entry) -> Value {
    match entry {
        Entry::User(text) => json!({"role": "user", "content": text}),
        Entry::Assistant { text, calls } => {
            let written = (!text.is_empty()).then(|| json!({"type": "text", "text": text}));
            let used = calls.iter().map(|call| {
                json!({"type": "tool_use", "id": call.id, "name": call.name, "input": call.input})
            });
            let content: Vec<Value> = written.into_iter().chain(used).collect();
            json!({"role": "assistant", "content": content})
        }
        Entry::Results(results) => {
            let content: Vec<Value> = results
                .iter()
                .map(|result| {
                    json!({
                        "type": "tool_result",
                        "tool_use_id": result.call_id,
                        "content": result.content,
                        "is_error": result.is_error
                    })
                })
                .collect();
            json!({"role": "user", "content": content})
        }
    }
}

/// A Chat Completions request, the usage asked for at the end of a
/// stream.
fn openai_body(asking: &Asking<'_>) -> Value {
    let tools: Vec<Value> = asking
        .tools
        .iter()
        .map(|tool| {
            json!({"type": "function", "function": {
                "name": tool.name, "description": tool.description, "parameters": tool.input_schema
            }})
        })
        .collect();
    let system = json!({"role": "system", "content": asking.system});
    let messages: Vec<Value> = std::iter::once(system)
        .chain(asking.history.iter().flat_map(openai_messages))
        .collect();
    let mut body = json!({
        "model": asking.model,
        "max_completion_tokens": ANSWER_TOKENS,
        "messages": messages,
        "stream": asking.streaming
    });
    if asking.streaming {
        body["stream_options"] = json!({"include_usage": true});
    }
    if !tools.is_empty() {
        body["tools"] = Value::Array(tools);
    }
    body
}

/// One entry as Chat Completions messages: a tool result is one `tool`
/// message for each call.
fn openai_messages(entry: &Entry) -> Vec<Value> {
    match entry {
        Entry::User(text) => vec![json!({"role": "user", "content": text})],
        Entry::Assistant { text, calls } if calls.is_empty() => {
            vec![json!({"role": "assistant", "content": text})]
        }
        Entry::Assistant { text, calls } => {
            let tool_calls: Vec<Value> = calls
                .iter()
                .map(|call| {
                    json!({"id": call.id, "type": "function", "function": {
                        "name": call.name, "arguments": call.input.to_string()
                    }})
                })
                .collect();
            let content = (!text.is_empty()).then(|| text.clone());
            vec![json!({"role": "assistant", "content": content, "tool_calls": tool_calls})]
        }
        Entry::Results(results) => results
            .iter()
            .map(|result| {
                json!({"role": "tool", "tool_call_id": result.call_id, "content": result.content})
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tools() -> Vec<ToolSpec> {
        vec![ToolSpec {
            name: "publish_report".to_owned(),
            description: "Publish the incident report.".to_owned(),
            input_schema: json!({"type": "object"}),
        }]
    }

    fn history() -> Vec<Entry> {
        vec![
            Entry::User("Report the outage.".to_owned()),
            Entry::Assistant {
                text: String::new(),
                calls: vec![ToolUse {
                    id: "call-1".to_owned(),
                    name: "publish_report".to_owned(),
                    input: json!({"summary": "down"}),
                }],
            },
            Entry::Results(vec![ToolResult {
                call_id: "call-1".to_owned(),
                content: "published".to_owned(),
                is_error: false,
            }]),
        ]
    }

    /// Anthropic is sent the system prompt on top, the tools with their
    /// input schema, and the result as a `tool_result` block.
    #[test]
    fn anthropic_is_asked_in_its_shape() {
        let tools = tools();
        let history = history();
        let asking = Asking {
            model: "claude",
            system: "Be brief.",
            tools: &tools,
            history: &history,
            streaming: false,
            sampling: Sampling::ProviderDefault,
        };

        let body = body(Format::Anthropic, &asking);

        assert_eq!(body["system"], "Be brief.");
        assert_eq!(body["tools"][0]["input_schema"]["type"], "object");
        assert_eq!(body["messages"][1]["content"][0]["type"], "tool_use");
        assert_eq!(body["messages"][2]["content"][0]["tool_use_id"], "call-1");
    }

    /// OpenAI is sent the system prompt as the first message, the call's
    /// arguments as JSON text, and the result as a `tool` message.
    #[test]
    fn openai_is_asked_in_its_shape() {
        let tools = tools();
        let history = history();
        let asking = Asking {
            model: "gpt",
            system: "Be brief.",
            tools: &tools,
            history: &history,
            streaming: true,
            sampling: Sampling::Fixed { seed: Some(7) },
        };

        let body = body(Format::OpenAi, &asking);

        assert_eq!(body["temperature"], 0);
        assert_eq!(body["seed"], 7);

        assert_eq!(body["messages"][0]["role"], "system");
        let arguments = body["messages"][2]["tool_calls"][0]["function"]["arguments"]
            .as_str()
            .unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(arguments).unwrap()["summary"],
            "down"
        );
        assert_eq!(body["messages"][3]["role"], "tool");
        assert_eq!(body["stream_options"]["include_usage"], true);
    }
}
