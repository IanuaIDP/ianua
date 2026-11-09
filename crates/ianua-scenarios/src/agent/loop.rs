//! The agent loop, as a tool-using SDK runs it: give the model a goal and
//! the tools it may use, carry out every call it makes, feed each result
//! back, and stop when it ends its turn.
//!
//! The tools are behind [`ToolBelt`]. Today the belt is what an agent
//! reaches through the API, such as the message relay
//! ([`RelayTools`](crate::agent::external::RelayTools)). The belt over MCP
//! through the gateway, listing the tools there and calling each with the
//! agent's key-bound token, waits for the gateway's start-up (gateway wave
//! 3); this trait is where it plugs in.

mod answer;
mod conversation;
mod llm;

use std::future::Future;

pub use answer::UnreadableAnswer;
pub(crate) use answer::{ModelTurn, StopReason};
use conversation::{Asking, Entry, ToolResult};
use llm::{Answered, ModelClient};
pub use llm::{ModelAccess, ModelError, Sampling, Streaming};
use serde_json::Value;

/// The most turns a loop takes before it gives up, as an SDK's turn limit.
const DEFAULT_TURNS: u32 = 8;

/// A tool the model may call: its name, what it does, and its input's
/// JSON schema.
#[derive(Debug, Clone, PartialEq)]
pub struct ToolSpec {
    /// The name the model calls it by.
    pub name: String,
    /// What it does, for the model.
    pub description: String,
    /// The JSON schema of its input.
    pub input_schema: Value,
}

/// One call the model made.
#[derive(Debug, Clone, PartialEq)]
pub struct ToolUse {
    /// Its id, which its result names.
    pub id: String,
    /// The tool.
    pub name: String,
    /// Arguments decoded from the model's tool request.
    pub input: Value,
}

/// What a tool gave back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolOutcome {
    /// It did its work and says this.
    Done(String),
    /// It failed or was refused, for this reason, which goes back to the
    /// model as an error result.
    Failed(String),
}

impl ToolOutcome {
    /// What goes back to the model, and whether it is an error.
    fn fed_back(&self) -> (String, bool) {
        match self {
            Self::Done(said) => (said.clone(), false),
            Self::Failed(why) => (why.clone(), true),
        }
    }
}

/// The tools an agent may use, and how each call is carried out.
pub trait ToolBelt {
    /// The tools offered to the model.
    fn tools(&self) -> Vec<ToolSpec>;

    /// Carries out the call of `name` with `input`.
    fn call(&self, name: &str, input: &Value) -> impl Future<Output = ToolOutcome> + Send;
}

/// One call the loop carried out, and what came of it.
#[derive(Debug, Clone, PartialEq)]
pub struct CarriedOut {
    /// Requested tool and arguments paired with the execution outcome.
    pub call: ToolUse,
    /// What came of it.
    pub outcome: ToolOutcome,
}

/// Why the loop stopped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stop {
    /// The model ended its turn with an answer.
    Answered,
    /// The model's answer was cut off at its token cap.
    CutOff,
    /// The model called tools on every turn the loop allows.
    TurnLimit,
    /// The model stopped for a reason the loop does not act on.
    Other(String),
}

/// What a loop came to.
#[derive(Debug)]
pub struct Outcome {
    /// Why it stopped.
    pub stop: Stop,
    /// The model's last text.
    pub answer: String,
    /// Every call carried out, in order.
    pub carried_out: Vec<CarriedOut>,
    /// How many times the model was asked.
    pub turns: u32,
    /// Every request body the model was sent, in order: what a scenario
    /// searches for what must never reach a model.
    pub sent: Vec<Value>,
}

/// An agent working toward a goal with a model and a belt of tools.
pub struct AgentLoop<'b, B: ToolBelt> {
    model: ModelClient,
    belt: &'b B,
    system: String,
    max_turns: u32,
}

impl<'b, B: ToolBelt> AgentLoop<'b, B> {
    /// A loop reasoning with the model `access` names, told `system`, using
    /// the tools on `belt`.
    ///
    /// # Errors
    ///
    /// [`ModelError::Unreachable`] when the model's client cannot be built.
    pub fn new(access: ModelAccess, system: &str, belt: &'b B) -> Result<Self, ModelError> {
        Ok(Self {
            model: ModelClient::new(access)?,
            belt,
            system: system.to_owned(),
            max_turns: DEFAULT_TURNS,
        })
    }

    /// This loop, giving up after `max_turns` turns.
    #[must_use]
    pub fn at_most(mut self, max_turns: u32) -> Self {
        self.max_turns = max_turns;
        self
    }

    /// Works toward `goal` until the model ends its turn, is cut off, or
    /// the turns run out.
    ///
    /// # Errors
    ///
    /// [`ModelError`] when a model call gives no answer that can be read.
    pub async fn run(&self, goal: &str) -> Result<Outcome, ModelError> {
        let tools = self.belt.tools();
        let mut history = vec![Entry::User(goal.to_owned())];
        let mut record = Record::default();
        for turn in 1..=self.max_turns {
            let Answered {
                turn: answered,
                sent,
            } = self.ask(&tools, &history).await?;
            record.sent.push(sent);
            history.push(Entry::Assistant {
                text: answered.text.clone(),
                calls: answered.calls.clone(),
            });
            if answered.calls.is_empty() {
                return Ok(ended(answered, record, turn));
            }
            let results = self
                .carried_out(&answered.calls, &mut record.carried_out)
                .await;
            history.push(Entry::Results(results));
        }
        Ok(Outcome {
            stop: Stop::TurnLimit,
            answer: String::new(),
            carried_out: record.carried_out,
            turns: self.max_turns,
            sent: record.sent,
        })
    }

    /// The model's next turn, offered `tools`, after `history`.
    async fn ask(&self, tools: &[ToolSpec], history: &[Entry]) -> Result<Answered, ModelError> {
        let asking = Asking {
            model: self.model.model(),
            system: &self.system,
            tools,
            history,
            streaming: self.model.streams(),
            sampling: self.model.sampling(),
        };
        self.model.next_turn(&asking).await
    }

    /// Carries out every one of `calls`, a call of a tool not on the belt
    /// refused as an SDK refuses it, keeping each in `record`.
    async fn carried_out(
        &self,
        calls: &[ToolUse],
        record: &mut Vec<CarriedOut>,
    ) -> Vec<ToolResult> {
        let offered: Vec<String> = self
            .belt
            .tools()
            .into_iter()
            .map(|tool| tool.name)
            .collect();
        let mut results = Vec::with_capacity(calls.len());
        for call in calls {
            let outcome = match offered.contains(&call.name) {
                true => self.belt.call(&call.name, &call.input).await,
                false => ToolOutcome::Failed(format!("no tool named {} is available", call.name)),
            };
            let (content, is_error) = outcome.fed_back();
            results.push(ToolResult {
                call_id: call.id.clone(),
                content,
                is_error,
            });
            record.push(CarriedOut {
                call: call.clone(),
                outcome,
            });
        }
        results
    }
}

/// What a loop has done so far: the calls carried out and the bodies
/// sent.
#[derive(Default)]
struct Record {
    carried_out: Vec<CarriedOut>,
    sent: Vec<Value>,
}

/// What a loop came to when the model's turn made no call.
fn ended(answered: ModelTurn, record: Record, turns: u32) -> Outcome {
    let stop = match answered.stop {
        StopReason::EndTurn | StopReason::ToolUse => Stop::Answered,
        StopReason::MaxTokens => Stop::CutOff,
        StopReason::Other(reason) => Stop::Other(reason),
    };
    Outcome {
        stop,
        answer: answered.text,
        carried_out: record.carried_out,
        turns,
        sent: record.sent,
    }
}
