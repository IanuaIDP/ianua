//! The topics agents publish to through the relay, each in the area of the
//! agent that owns it.

use serde::Serialize;

/// `POST …/messaging/topics`: a topic with the schema every agent message
/// on it must match.
#[derive(Debug, Clone, Serialize)]
pub struct NewTopic {
    /// A name people know it by.
    pub name: String,
    /// The name it is addressed by, such as `agents.<id>.reports`.
    pub topic_name: String,
    /// The JSON schema messages must match, as text.
    pub schema: String,
    /// How long messages are kept.
    pub retention: Retention,
}

/// How long a topic keeps its messages.
#[derive(Debug, Clone, Copy, Serialize)]
pub enum Retention {
    /// So many seconds.
    Duration(u32),
    /// The last so many messages.
    MessageCount(u64),
}

/// The topic `agent_id` owns under `rest`: its own area, where only it may
/// publish.
#[must_use]
pub fn area_topic(agent_id: &str, rest: &str) -> String {
    let simple: String = agent_id.chars().filter(|c| *c != '-').collect();
    format!("agents.{simple}.{rest}")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An agent's area names it by its id as 32 hex digits, no hyphens.
    #[test]
    fn an_area_names_its_agent_without_hyphens() {
        let agent = uuid::Uuid::now_v7();

        let topic = area_topic(&agent.to_string(), "reports");

        assert_eq!(topic, format!("agents.{}.reports", agent.simple()));
    }

    /// A duration serializes with the externally tagged variant the API accepts.
    #[test]
    fn retention_reads_as_the_api_takes_it() {
        let written = serde_json::to_string(&Retention::Duration(3600)).unwrap();

        assert_eq!(written, r#"{"Duration":3600}"#);
    }
}
