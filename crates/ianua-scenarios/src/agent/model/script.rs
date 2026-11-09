//! What the scripted model says: a [`Script`] of [`Turn`]s, each answering
//! a request that matches [`When`] with a [`Reply`].

use serde_json::Value;

use super::Received;

/// When a turn answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum When {
    /// Whatever was asked.
    Always,
    /// The newest user turn, a tool's result included, holds this text.
    /// For a platform run, which feeds a tool's result back as text, that
    /// is the result.
    Heard(String),
    /// A tool of this name is offered, natively or in the system prompt.
    Offered(String),
    /// No tool of this name is offered anywhere.
    NotOffered(String),
}

impl When {
    /// The newest user turn holds `text`.
    #[must_use]
    pub fn heard(text: &str) -> Self {
        Self::Heard(text.to_owned())
    }

    /// A tool named `name` is offered.
    #[must_use]
    pub fn offered(name: &str) -> Self {
        Self::Offered(name.to_owned())
    }

    /// No tool named `name` is offered.
    #[must_use]
    pub fn not_offered(name: &str) -> Self {
        Self::NotOffered(name.to_owned())
    }

    /// Whether `received` is a request this answers.
    pub(super) fn matches(&self, received: &Received) -> bool {
        match self {
            Self::Always => true,
            Self::Heard(text) => received.last_user_text().contains(text.as_str()),
            Self::Offered(name) => received.offers(name),
            Self::NotOffered(name) => !received.offers(name),
        }
    }
}

/// What the model answers.
#[derive(Debug, Clone, PartialEq)]
pub enum Reply {
    /// Text, ending the turn.
    Text(String),
    /// A call of the tool `name` with `input`: a `tool_use` block or a
    /// `tool_calls` entry when tools were offered natively, and otherwise
    /// the JSON a prompt-described tool is called with,
    /// `{"tool": name, "arguments": input}`, ending the turn.
    Call {
        /// The tool.
        name: String,
        /// Its arguments.
        input: Value,
    },
    /// Nothing at all, ending the turn.
    EndTurn,
    /// Text cut off at the token cap: `max_tokens`, or `length`.
    MaxTokens(String),
}

impl Reply {
    /// `text`, ending the turn.
    #[must_use]
    pub fn text(text: &str) -> Self {
        Self::Text(text.to_owned())
    }

    /// A call of `name` with `input`.
    #[must_use]
    pub fn call(name: &str, input: Value) -> Self {
        Self::Call {
            name: name.to_owned(),
            input,
        }
    }

    /// The text a prompt-described call is written as.
    pub(super) fn call_as_text(name: &str, input: &Value) -> String {
        serde_json::json!({ "tool": name, "arguments": input }).to_string()
    }
}

/// One answer the model may give, and when.
#[derive(Debug, Clone, PartialEq)]
pub struct Turn {
    when: When,
    reply: Reply,
}

impl Turn {
    /// `reply`, to whatever is asked next.
    #[must_use]
    pub fn answer(reply: Reply) -> Self {
        Self::when(When::Always, reply)
    }

    /// `reply`, to a request matching `when`.
    #[must_use]
    pub fn when(when: When, reply: Reply) -> Self {
        Self { when, reply }
    }

    /// Whether it answers `received`.
    pub(super) fn answers(&self, received: &Received) -> bool {
        self.when.matches(received)
    }

    /// What it answers with.
    pub(super) fn reply(&self) -> &Reply {
        &self.reply
    }
}

/// The turns the model has to give. Each request is answered by the first
/// turn not yet given whose [`When`] it matches, so a script can run in
/// order and still react to what it hears. A request no turn matches is
/// refused as the provider refuses a bad request, and counted.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Script {
    turns: Vec<Turn>,
}

impl Script {
    /// A script with no turns yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// This script with `turn` after the others.
    #[must_use]
    pub fn then(mut self, turn: Turn) -> Self {
        self.turns.push(turn);
        self
    }

    /// The turns, in order.
    pub(super) fn into_turns(self) -> Vec<Turn> {
        self.turns
    }
}
