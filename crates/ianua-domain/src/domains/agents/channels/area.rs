//! An agent's own topic area. It is the only place the agent may publish.
//!
//! Every agent owns the topics under `agents.<agent id>.…`, with the id
//! written as 32 lowercase hex digits. It publishes there and nowhere else.
//! So the address of every agent message names its author. Another agent
//! reads it only through a channel a person opened.

use crate::domains::agents::authority::capability::TopicPattern;
use crate::domains::messaging::topic_name::TopicName;
use crate::types::AgentId;

/// The first segment of every agent area.
const AREA_ROOT: &str = "agents";

/// The topics one agent owns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AgentArea(AgentId);

impl AgentArea {
    /// The area `agent` owns.
    #[must_use]
    pub fn of(agent: AgentId) -> Self {
        Self(agent)
    }

    /// The agent whose area `topic` is in, if it is in one.
    ///
    /// A topic is in an area only when it sits below it. `agents.<id>` itself
    /// is in no area. Nor is a topic with a malformed id, or with the id
    /// written another way, such as with hyphens.
    #[must_use]
    pub fn owner_of(topic: &TopicName) -> Option<AgentId> {
        let mut segments = topic.as_str().splitn(3, '.');
        let (Some(AREA_ROOT), Some(id), Some(_rest)) =
            (segments.next(), segments.next(), segments.next())
        else {
            return None;
        };
        let uuid = uuid::Uuid::try_parse(id).ok()?;
        let canonical = uuid.as_simple().to_string() == id;
        canonical.then(|| AgentId::from_uuid(uuid))
    }

    /// The agent that owns this area.
    #[must_use]
    pub fn owner(&self) -> AgentId {
        self.0
    }

    /// Whether `topic` is in this area.
    #[must_use]
    pub fn contains(&self, topic: &TopicName) -> bool {
        Self::owner_of(topic) == Some(self.0)
    }

    /// Whether every topic `pattern` matches is in this area.
    ///
    /// The first two segments must name this area literally, with no
    /// wildcard. At least one more segment must follow them.
    #[must_use]
    pub fn covers(&self, pattern: &TopicPattern) -> bool {
        let mut segments = pattern.as_str().splitn(3, '.');
        let id = self.0.as_uuid().as_simple().to_string();
        matches!(
            (segments.next(), segments.next(), segments.next()),
            (Some(AREA_ROOT), Some(owner), Some(_)) if owner == id
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn topic(name: &str) -> TopicName {
        TopicName::new(name).unwrap()
    }

    fn in_area(agent: AgentId, rest: &str) -> TopicName {
        topic(&format!("agents.{}.{rest}", agent.as_uuid().as_simple()))
    }

    /// An agent's id is followed by `tasks` or `tasks.done`. Both topics map
    /// back to that agent, so a message there names its author.
    #[test]
    fn a_topic_below_an_agents_id_belongs_to_that_agent() {
        let agent = AgentId::new();

        assert_eq!(AgentArea::owner_of(&in_area(agent, "tasks")), Some(agent));
        assert!(AgentArea::of(agent).contains(&in_area(agent, "tasks.done")));
    }

    /// A topic bearing another agent's id falls outside this agent's area.
    #[test]
    fn another_agents_topic_is_not_in_the_area() {
        let agent = AgentId::new();

        assert!(!AgentArea::of(agent).contains(&in_area(AgentId::new(), "tasks")));
    }

    /// A plain topic, the bare `agents.<id>`, a malformed id, a hyphenated id
    /// and a wrong root all have no owner. Only the one canonical spelling
    /// counts as an agent's area.
    #[test]
    fn topics_outside_any_area_have_no_owner() {
        let agent = AgentId::new();
        let id = agent.as_uuid().as_simple().to_string();

        for name in [
            "orders.created".to_owned(),
            format!("agents.{id}"),
            "agents.not-an-id.tasks".to_owned(),
            format!("agents.{}.tasks", agent.as_uuid().hyphenated()),
            format!("other.{id}.tasks"),
        ] {
            assert_eq!(AgentArea::owner_of(&topic(&name)), None, "{name}");
        }
    }

    /// Patterns naming the agent's own topics are covered, including a final
    /// wildcard. Wildcards spanning agents and the bare area root are not.
    #[test]
    fn the_area_pattern_covers_its_own_topics_only() {
        let agent = AgentId::new();
        let area = AgentArea::of(agent);
        let id = agent.as_uuid().as_simple();

        assert!(area.covers(&TopicPattern::new(format!("agents.{id}.tasks")).unwrap()));
        assert!(area.covers(&TopicPattern::new(format!("agents.{id}.*")).unwrap()));
        assert!(!area.covers(&TopicPattern::new("agents.>").unwrap()));
        assert!(!area.covers(&TopicPattern::new(">").unwrap()));
        assert!(!area.covers(&TopicPattern::new("agents.*.tasks").unwrap()));
        assert!(!area.covers(&TopicPattern::new(format!("agents.{id}")).unwrap()));
    }
}
