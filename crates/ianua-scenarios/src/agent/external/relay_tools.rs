//! The tools an external agent reaches through the API today: publishing
//! a report to a topic through the message relay, with its task token.
//! Whether a topic is the agent's to publish to is the relay's to say; a
//! belt may offer the model tools the agent's grant does not cover, and
//! the relay's refusal goes back to the model as an error.

use std::future::Future;

use serde_json::{Value, json};

use super::ExternalAgent;
use crate::agent::r#loop::{ToolBelt, ToolOutcome, ToolSpec};
use crate::wire::Status;

/// The name of the tool that publishes to the agent's own topic.
pub const PUBLISH_REPORT: &str = "publish_report";

/// One tool on the belt, and the topic it publishes to.
#[derive(Debug, Clone)]
struct RelayTool {
    spec: ToolSpec,
    topic: String,
}

/// The relay as a belt of tools, each publishing the `summary` it is
/// called with to its own topic.
#[derive(Debug)]
pub struct RelayTools<'a> {
    agent: &'a ExternalAgent,
    tools: Vec<RelayTool>,
}

impl<'a> RelayTools<'a> {
    /// A belt of `agent` holding no tool yet.
    #[must_use]
    pub fn new(agent: &'a ExternalAgent) -> Self {
        Self {
            agent,
            tools: Vec::new(),
        }
    }

    /// The belt of `agent` holding [`PUBLISH_REPORT`], publishing to
    /// `topic`.
    #[must_use]
    pub fn reporting(agent: &'a ExternalAgent, topic: &str) -> Self {
        Self::new(agent).with(
            PUBLISH_REPORT,
            "Publish a short report to the team's topic.",
            topic,
        )
    }

    /// This belt with the tool `name`, described to the model as
    /// `description`, publishing to `topic`.
    #[must_use]
    pub fn with(mut self, name: &str, description: &str, topic: &str) -> Self {
        self.tools.push(RelayTool {
            spec: ToolSpec {
                name: name.to_owned(),
                description: description.to_owned(),
                input_schema: json!({
                    "type": "object",
                    "properties": {"summary": {"type": "string"}},
                    "required": ["summary"]
                }),
            },
            topic: topic.to_owned(),
        });
        self
    }

    /// The topic the tool `name` publishes to, if the belt holds it.
    #[must_use]
    pub fn topic_of(&self, name: &str) -> Option<&str> {
        self.tools
            .iter()
            .find(|tool| tool.spec.name == name)
            .map(|tool| tool.topic.as_str())
    }
}

impl ToolBelt for RelayTools<'_> {
    fn tools(&self) -> Vec<ToolSpec> {
        self.tools.iter().map(|tool| tool.spec.clone()).collect()
    }

    fn call(&self, name: &str, input: &Value) -> impl Future<Output = ToolOutcome> + Send {
        let topic = self.topic_of(name).map(str::to_owned);
        let message = json!({"summary": input.get("summary").cloned().unwrap_or(Value::Null)});
        let agent = self.agent;
        let name = name.to_owned();
        async move {
            let Some(topic) = topic else {
                return ToolOutcome::Failed(format!("the belt holds no tool named {name}"));
            };
            let answer = agent.publish(&topic, &message).await;
            match answer.status() {
                Status::NO_CONTENT => ToolOutcome::Done(format!("published to {topic}")),
                _ => ToolOutcome::Failed(answer.summary()),
            }
        }
    }
}
