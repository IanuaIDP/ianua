//! A request the scripted model received, read the same way whichever
//! provider's format it came in.

use std::fmt;

use serde_json::Value;

use super::Format;

/// One request as it arrived: its format, path, headers and JSON body.
///
/// The headers are kept as sent, the provider key among them, so a test
/// can check the key travelled where its provider documents and nowhere
/// else. `Debug` shows only the headers' names.
#[derive(Clone)]
pub struct Received {
    format: Format,
    path: String,
    headers: Vec<(String, String)>,
    body: Value,
}

impl fmt::Debug for Received {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let names: Vec<&str> = self.headers.iter().map(|(name, _)| name.as_str()).collect();
        f.debug_struct("Received")
            .field("format", &self.format)
            .field("path", &self.path)
            .field("headers", &names)
            .finish_non_exhaustive()
    }
}

impl Received {
    /// The request of `format` to `path` with `headers`, their names in
    /// lowercase, and `body`.
    pub(super) fn new(
        format: Format,
        path: String,
        headers: Vec<(String, String)>,
        body: Value,
    ) -> Self {
        Self {
            format,
            path,
            headers,
            body,
        }
    }

    /// The format it came in.
    #[must_use]
    pub fn format(&self) -> Format {
        self.format
    }

    /// The path it was sent to.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// The header `name`, as sent.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        let name = name.to_ascii_lowercase();
        self.headers
            .iter()
            .find(|(sent, _)| *sent == name)
            .map(|(_, value)| value.as_str())
    }

    /// The JSON body.
    #[must_use]
    pub fn body(&self) -> &Value {
        &self.body
    }

    /// The model asked for.
    #[must_use]
    pub fn model(&self) -> Option<&str> {
        self.body.get("model").and_then(Value::as_str)
    }

    /// Whether it asked for the answer as server-sent events.
    #[must_use]
    pub fn is_streaming(&self) -> bool {
        self.body
            .get("stream")
            .and_then(Value::as_bool)
            .unwrap_or(false)
    }

    /// The system prompt: Anthropic's top-level `system`, or every
    /// OpenAI `system` message, joined.
    #[must_use]
    pub fn system(&self) -> String {
        match self.format {
            Format::Anthropic => self.body.get("system").map(text_of).unwrap_or_default(),
            Format::OpenAi => self
                .messages()
                .iter()
                .filter(|message| role_of(message) == "system")
                .map(|message| message.get("content").map(text_of).unwrap_or_default())
                .collect::<Vec<_>>()
                .join("\n\n"),
        }
    }

    /// The names of the tools offered natively, in `tools`.
    #[must_use]
    pub fn tools_offered(&self) -> Vec<String> {
        let tools = self.body.get("tools").and_then(Value::as_array);
        let Some(tools) = tools else {
            return Vec::new();
        };
        tools
            .iter()
            .filter_map(|tool| match self.format {
                Format::Anthropic => tool.get("name"),
                Format::OpenAi => tool
                    .get("function")
                    .and_then(|function| function.get("name")),
            })
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect()
    }

    /// Whether a tool named `name` is offered, natively or in the system
    /// prompt, as a platform run lists its tools.
    #[must_use]
    pub fn offers(&self, name: &str) -> bool {
        self.tools_offered().iter().any(|offered| offered == name) || self.system().contains(name)
    }

    /// Whether any tool is offered natively, so a call is answered as a
    /// native call.
    pub(super) fn offers_natively(&self) -> bool {
        !self.tools_offered().is_empty()
    }

    /// The text of every turn after the model's last one: the user's
    /// words, and every tool result's.
    #[must_use]
    pub fn last_user_text(&self) -> String {
        let messages = self.messages();
        let start = messages
            .iter()
            .rposition(|message| role_of(message) == "assistant")
            .map_or(0, |at| at.saturating_add(1));
        messages[start..]
            .iter()
            .filter(|message| role_of(message) != "system")
            .map(|message| message.get("content").map(text_of).unwrap_or_default())
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// The whole body as text, to search for what must not be there.
    #[must_use]
    pub fn text(&self) -> String {
        self.body.to_string()
    }

    /// The conversation's messages.
    fn messages(&self) -> &[Value] {
        self.body
            .get("messages")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or_default()
    }
}

/// A message's role.
fn role_of(message: &Value) -> &str {
    message.get("role").and_then(Value::as_str).unwrap_or("")
}

/// The text a content value carries: a string, or the text of every
/// block, a tool result's content included.
fn text_of(content: &Value) -> String {
    match content {
        Value::String(text) => text.clone(),
        Value::Array(blocks) => blocks.iter().map(block_text).collect::<Vec<_>>().join("\n"),
        _ => String::new(),
    }
}

/// The text one content block carries.
fn block_text(block: &Value) -> String {
    if let Some(text) = block.get("text").and_then(Value::as_str) {
        return text.to_owned();
    }
    block.get("content").map(text_of).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn anthropic(body: Value) -> Received {
        Received::new(
            Format::Anthropic,
            "/v1/messages".to_owned(),
            Vec::new(),
            body,
        )
    }

    /// A tool's result in Anthropic's blocks is read as the newest words.
    #[test]
    fn a_tool_result_block_is_the_newest_text() {
        let received = anthropic(json!({
            "system": [{"type": "text", "text": "Use the tools."}],
            "tools": [{"name": "publish_report", "input_schema": {}}],
            "messages": [
                {"role": "user", "content": "Report the outage."},
                {"role": "assistant", "content": [{"type": "tool_use", "id": "t1", "name": "publish_report", "input": {}}]},
                {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "t1", "content": [{"type": "text", "text": "published"}]}]}
            ]
        }));

        assert_eq!(received.last_user_text(), "published");
        assert_eq!(received.system(), "Use the tools.");
        assert!(received.offers("publish_report"));
        assert!(!received.offers("delete_everything"));
    }

    /// OpenAI's tool messages after the model's turn are read together,
    /// and the system message is the prompt.
    #[test]
    fn openai_tool_messages_are_the_newest_text() {
        let received = Received::new(
            Format::OpenAi,
            "/v1/chat/completions".to_owned(),
            Vec::new(),
            json!({
                "messages": [
                    {"role": "system", "content": "Only these tools: read_ticket"},
                    {"role": "user", "content": "Triage 4821."},
                    {"role": "assistant", "content": null, "tool_calls": []},
                    {"role": "tool", "tool_call_id": "c1", "content": "printer jam"}
                ]
            }),
        );

        assert_eq!(received.last_user_text(), "printer jam");
        assert!(received.offers("read_ticket"));
        assert!(!received.offers_natively());
    }
}
