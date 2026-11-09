//! What an agent may do: the capabilities a delegation grants, the limits
//! it is held to, a person granting one, an agent passing part of one on,
//! and the task token that comes of each.

use std::fmt;

use serde::{Deserialize, Serialize};

use super::Principal;

/// What a delegation or a token may do: HTTP permissions such as
/// `users:view`, messaging topics, resources and MCP tools.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capabilities {
    /// Permissions as `domain:action`.
    #[serde(default)]
    pub http: Vec<String>,
    /// Topics and the rights on each.
    #[serde(default)]
    pub messaging: Vec<TopicRight>,
    /// MCP tool name patterns.
    #[serde(default)]
    pub tools: Vec<String>,
    /// Relations on named objects, such as `reader` on `calendar:rota`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resources: Vec<ResourceRight>,
}

/// A relation on one named object, as a delegation holds it and the
/// resource graph records it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceRight {
    /// The relation, such as `reader`.
    pub relation: String,
    /// The object, its type before the colon, such as `calendar:rota`.
    pub resource: String,
}

impl Capabilities {
    /// The HTTP permissions `permissions`, and nothing else.
    #[must_use]
    pub fn http(permissions: &[&str]) -> Self {
        Self {
            http: permissions
                .iter()
                .map(|&permission| permission.to_owned())
                .collect(),
            ..Self::default()
        }
    }

    /// These capabilities with the right to publish to `topic` too.
    #[must_use]
    pub fn publishing_to(mut self, topic: &str) -> Self {
        self.messaging.push(TopicRight {
            topic: topic.to_owned(),
            rights: Rights::Publish,
        });
        self
    }

    /// These capabilities with the MCP tools `tools` too.
    #[must_use]
    pub fn with_tools(mut self, tools: &[&str]) -> Self {
        self.tools.extend(tools.iter().map(|&tool| tool.to_owned()));
        self
    }
}

/// A topic pattern and the rights on it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TopicRight {
    /// The topic, such as `agents.<id>.reports`.
    pub topic: String,
    /// What may be done on it.
    pub rights: Rights,
}

/// What may be done on a topic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Rights {
    /// Send messages matching the topic pattern.
    Publish,
    /// Read from it.
    Subscribe,
    /// Send and receive messages matching the topic pattern.
    Both,
}

/// A request budget: so many requests per window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Budget {
    /// The most requests in a window.
    pub max_requests: u32,
    /// Duration over which the request allowance is counted.
    pub window_seconds: u32,
    /// How many of them were used, where the answer says.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub used_requests: Option<u32>,
}

impl Budget {
    /// `max_requests` per `window_seconds`.
    #[must_use]
    pub fn of(max_requests: u32, window_seconds: u32) -> Self {
        Self {
            max_requests,
            window_seconds,
            used_requests: None,
        }
    }
}

/// The limits a delegation is held to.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Limits {
    /// Its lifetime, in seconds.
    pub ttl_seconds: u32,
    /// How deep it may be passed on.
    pub max_depth: u8,
    /// Whether each action waits for a person's approval.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub requires_approval: bool,
    /// Its request budget.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub budget: Option<Budget>,
    /// Whether its tokens are bound to the agent's key.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub sender_constrained: bool,
    /// The apps, by service id, the agent may call through the gateway; its
    /// tokens name each one's audience.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub apps: Vec<String>,
}

/// `POST …/agents/{id}/grant`: a person hands an agent part of their
/// authority.
#[derive(Debug, Clone, Serialize)]
pub struct Grant {
    /// What the agent may do, held to what the person holds.
    pub granted: Capabilities,
    /// The limits it is held to.
    #[serde(flatten)]
    pub limits: Limits,
    /// The title people see.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// `POST …/agents/{id}/delegations/{delegation}/attenuate`: the agent
/// holding a delegation passes part of it on to another agent.
#[derive(Debug, Clone, Serialize)]
pub struct Attenuation {
    /// The agent receiving the part.
    pub delegate: String,
    /// What it may do, all of it granted by the parent.
    pub granted: Capabilities,
    /// The limits it is held to, inside the parent's.
    #[serde(flatten)]
    pub limits: Limits,
}

/// A delegation granted, passed on or minted, and the task token signed
/// for it. Holds the token, so `Debug` leaves it out.
#[derive(Clone, Deserialize)]
pub struct Granted {
    /// The delegation's id.
    pub delegation_id: String,
    /// The signed task token.
    pub task_token: String,
    /// What it grants after every cap.
    pub granted: Capabilities,
    /// Who it acts for, nearest first.
    #[serde(default)]
    pub on_behalf_of: Vec<Principal>,
}

impl fmt::Debug for Granted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Granted")
            .field("delegation_id", &self.delegation_id)
            .field("granted", &self.granted)
            .field("on_behalf_of", &self.on_behalf_of)
            .finish_non_exhaustive()
    }
}

/// A delegation as its readers see it.
#[derive(Debug, Clone, Deserialize)]
pub struct Delegation {
    /// Handle used to inspect, attenuate or revoke this grant.
    pub delegation_id: String,
    /// Who granted it.
    pub delegator: Principal,
    /// The agent holding it.
    pub delegate: String,
    /// The delegation it was cut from, for a passed-on one.
    #[serde(default)]
    pub parent: Option<String>,
    /// How many hops it sits below the person at its chain's root: none
    /// for a root delegation.
    #[serde(default)]
    pub depth: u8,
    /// What it grants.
    pub granted: Capabilities,
    /// How deep it may still be passed on.
    pub max_depth: u8,
    /// Whether each action waits for a person.
    pub requires_approval: bool,
    /// Its request budget, with what was used where the platform counts.
    #[serde(default)]
    pub budget: Option<Budget>,
    /// Whether its tokens are bound to the agent's key.
    pub sender_constrained: bool,
    /// Whether it was revoked.
    pub revoked: bool,
}

/// `PUT …/resource-grants`: the resource graph records that `subject`
/// holds a relation on an object, which only then may be handed to an
/// agent's task.
#[derive(Debug, Clone, Serialize)]
pub struct ResourceGrant {
    /// Who holds it: a person, a member or an agent.
    pub subject: Principal,
    /// The relation and the object.
    #[serde(flatten)]
    pub right: ResourceRight,
}

/// `POST …/agents/{id}/authorize-resource`'s answer: whether the agent may
/// use a relation on an object, nothing happening either way.
#[derive(Debug, Clone, Deserialize)]
pub struct ResourceDecision {
    /// `allow` or `deny`.
    pub decision: String,
    /// Why, as the platform words it.
    pub reason: String,
}
