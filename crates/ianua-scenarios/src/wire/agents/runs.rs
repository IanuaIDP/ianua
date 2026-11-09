//! A run: an agent the platform drives toward a goal with a model, calling
//! only the tools it was given.

use serde::{Deserialize, Serialize};

/// `POST …/agents/{id}/runs`: the goal, the model provider, the purpose
/// and the tools.
#[derive(Debug, Clone, Default, Serialize)]
pub struct StartRun {
    /// What to reach.
    pub goal: String,
    /// The model provider to reason with.
    pub provider_id: String,
    /// The action classes it may exercise, such as `read`.
    pub purpose: Vec<String>,
    /// The tools it is given, by name.
    pub tool_names: Vec<String>,
    /// The most steps it may take; zero takes the deployment's default.
    pub max_steps: u32,
    /// The most it may spend on its model, in millionths of the tenant's
    /// billing currency, or none for no limit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spend_limit_micros: Option<u64>,
    /// What it may spend before it pauses for a person, in the same
    /// millionths, or none for no pause.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ask_past_micros: Option<u64>,
}

/// A run and the steps it took.
#[derive(Debug, Clone, Deserialize)]
pub struct Run {
    /// Handle used to poll, pause or cancel the agent's work.
    pub id: String,
    /// The acting agent.
    pub agent_id: String,
    /// `running`, `awaiting_approval`, `paused`, `completed`, `failed`,
    /// `cancelled`, `halted` or `over_budget`.
    pub status: String,
    /// The final answer, once it completed.
    #[serde(default)]
    pub answer: Option<String>,
    /// The tokens its model calls used.
    pub usage: RunUsage,
    /// Every step it took, in order.
    #[serde(default)]
    pub steps: Vec<RunStep>,
    /// What its model calls cost, in millionths.
    pub spent_micros: u64,
    /// Where it waits for a person before spending more, if it does.
    #[serde(default)]
    pub spend_check: Option<SpendCheck>,
}

/// Where a run waits for a person before spending more.
#[derive(Debug, Clone, Deserialize)]
pub struct SpendCheck {
    /// What it may spend before it asks, in millionths.
    pub asks_at_micros: u64,
    /// `ahead`, `due` or `asked`.
    pub state: String,
}

impl Run {
    /// Whether it has stopped, one way or another.
    #[must_use]
    pub fn has_ended(&self) -> bool {
        matches!(
            self.status.as_str(),
            "completed" | "failed" | "cancelled" | "halted" | "over_budget"
        )
    }

    /// The steps that called `tool`.
    #[must_use]
    pub fn steps_calling(&self, tool: &str) -> Vec<&RunStep> {
        self.steps
            .iter()
            .filter(|step| step.tool.as_deref() == Some(tool))
            .collect()
    }
}

/// The tokens a run's model calls used.
#[derive(Debug, Clone, Copy, Deserialize)]
pub struct RunUsage {
    /// Sent to the model.
    pub input_tokens: u64,
    /// Written by the model.
    pub output_tokens: u64,
}

/// Recorded tool call, refusal or model answer in execution order.
#[derive(Debug, Clone, Deserialize)]
pub struct RunStep {
    /// Its place, from one.
    pub seq: u32,
    /// The tool it called, for a tool call.
    #[serde(default)]
    pub tool: Option<String>,
    /// The arguments it was called with.
    #[serde(default)]
    pub arguments: Option<String>,
    /// `allowed`, `denied`, `answered` or `replied`.
    pub outcome: String,
    /// The tool's result, the refusal's reason, or the answer.
    pub detail: String,
}
