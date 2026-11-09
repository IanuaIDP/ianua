//! What a delegation, a token or a template may do, on the wire: HTTP
//! permissions, messaging topics, resources and MCP tools, and the request
//! budget that caps it.

use ianua_domain::domains::agents::authority::capability::{
    AgentBudget, CapabilitySet, McpGrant, McpResourcePattern, McpTool, McpToolPattern, PubSub,
    Relation, ResourceCapability, ResourceRef, TopicCapability, TopicPattern,
};
use ianua_domain::domains::authorization::permission::SystemPermission;
use ianua_domain::message;
use ianua_domain::types::{ActionClass, Seconds};
use serde::{Deserialize, Serialize};

use crate::error::ApiError;

/// Publish and subscribe rights on a topic.
#[derive(Clone, Copy, Deserialize, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PubSubDto {
    /// May publish only.
    Publish,
    /// May subscribe only.
    Subscribe,
    /// May publish and subscribe.
    Both,
}

impl From<PubSubDto> for PubSub {
    fn from(rights: PubSubDto) -> Self {
        match rights {
            PubSubDto::Publish => Self::Publish,
            PubSubDto::Subscribe => Self::Subscribe,
            PubSubDto::Both => Self::Both,
        }
    }
}

impl From<PubSub> for PubSubDto {
    fn from(rights: PubSub) -> Self {
        match rights {
            PubSub::Publish => Self::Publish,
            PubSub::Subscribe => Self::Subscribe,
            PubSub::Both => Self::Both,
        }
    }
}

/// A messaging capability: a topic pattern and pub/sub rights.
#[derive(Deserialize, Serialize, utoipa::ToSchema)]
pub(crate) struct TopicCapabilityDto {
    /// Tenant-relative topic pattern, such as `agents.*` or `agents.>`.
    pub topic: String,
    /// Publish and subscribe rights.
    pub rights: PubSubDto,
}

impl TopicCapabilityDto {
    /// The topic pattern and rights named, refused when the pattern is not
    /// a valid one.
    fn to_domain(&self) -> Result<TopicCapability, ApiError> {
        let pattern = TopicPattern::new(self.topic.as_str()).map_err(|e| {
            ApiError::validation(message!(
                "api-invalid-topic",
                format!("invalid topic '{}': {e}", self.topic)
            ))
        })?;
        Ok(TopicCapability::new(pattern, self.rights.into()))
    }
}

impl From<&TopicCapability> for TopicCapabilityDto {
    fn from(capability: &TopicCapability) -> Self {
        Self {
            topic: capability.pattern().as_str().to_owned(),
            rights: capability.rights().into(),
        }
    }
}

/// A resource-scoped capability: a relation on an object.
#[derive(Deserialize, Serialize, utoipa::ToSchema)]
pub(crate) struct ResourceCapabilityDto {
    /// The relation held on the object, such as `reader` or `owner`.
    pub relation: String,
    /// The object reference, such as `calendar:abc123`.
    pub resource: String,
}

impl ResourceCapabilityDto {
    /// The relation and object named.
    ///
    /// # Errors
    ///
    /// - A validation error when the relation or the object reference is
    ///   not valid.
    pub(crate) fn parts(&self) -> Result<(Relation, ResourceRef), ApiError> {
        Ok((
            Relation::new(self.relation.as_str()).map_err(ApiError::validation)?,
            ResourceRef::new(self.resource.as_str()).map_err(ApiError::validation)?,
        ))
    }

    /// The capability named.
    ///
    /// # Errors
    ///
    /// - A validation error when the relation or the object reference is
    ///   not valid.
    pub(crate) fn to_domain(&self) -> Result<ResourceCapability, ApiError> {
        let (relation, resource) = self.parts()?;
        Ok(ResourceCapability::new(relation, resource))
    }
}

impl From<&ResourceCapability> for ResourceCapabilityDto {
    fn from(capability: &ResourceCapability) -> Self {
        Self {
            relation: capability.relation().as_str().to_owned(),
            resource: capability.resource_ref().as_str().to_owned(),
        }
    }
}

/// A set of capabilities: HTTP permissions, messaging topics, resources and
/// what an MCP server offers.
#[derive(Default, Deserialize, Serialize, utoipa::ToSchema)]
pub(crate) struct CapabilitySetDto {
    /// HTTP permissions as `domain:action` strings, such as `routing:view`.
    #[serde(default)]
    pub http: Vec<String>,
    /// Messaging capabilities.
    #[serde(default)]
    pub messaging: Vec<TopicCapabilityDto>,
    /// Resource-scoped capabilities.
    #[serde(default)]
    pub resources: Vec<ResourceCapabilityDto>,
    /// MCP tools this set may call, as names or `prefix_*` patterns.
    ///
    /// Empty grants none: under MCP every tool call is one method on one
    /// path, so a delegation that names no tool can call no tool. A tool
    /// granted from what someone holds takes the classes of action it is
    /// held with there.
    #[serde(default)]
    pub tools: Vec<String>,
    /// MCP resources this set may read, as URIs or `prefix*` patterns.
    ///
    /// Separate from `tools` because reading content is a separate
    /// authority from acting, and it is the surface a prompt injection
    /// arrives on.
    #[serde(default)]
    pub mcp_resources: Vec<String>,
    /// MCP prompts this set may fetch, as names or `prefix_*` patterns.
    #[serde(default)]
    pub mcp_prompts: Vec<String>,
}

impl CapabilitySetDto {
    /// The capability set named.
    ///
    /// An asked-for MCP tool is labelled a read: a grant cut from what
    /// someone holds takes on every class the holder's entry carries, so
    /// the label can only add to them, never hide one.
    ///
    /// # Errors
    ///
    /// - A validation error naming the first permission, topic, resource or
    ///   pattern that is not valid.
    pub(crate) fn to_domain(&self) -> Result<CapabilitySet, ApiError> {
        let http = self
            .http
            .iter()
            .map(|p| {
                SystemPermission::parse(p).ok_or_else(|| {
                    ApiError::validation(message!(
                        "api-unknown-permission",
                        format!("unknown permission: {p}")
                    ))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let messaging = self
            .messaging
            .iter()
            .map(TopicCapabilityDto::to_domain)
            .collect::<Result<Vec<_>, _>>()?;
        let resources = self
            .resources
            .iter()
            .map(ResourceCapabilityDto::to_domain)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(CapabilitySet::new(http, messaging)
            .with_resources(resources)
            .with_mcp(self.mcp()?))
    }

    /// The MCP part of the set.
    fn mcp(&self) -> Result<McpGrant, ApiError> {
        let tools = name_patterns(&self.tools, "tool")?
            .into_iter()
            .map(|pattern| McpTool::new(pattern, ActionClass::Read))
            .collect();
        let resources = self
            .mcp_resources
            .iter()
            .map(|uri| {
                McpResourcePattern::new(uri.as_str()).map_err(|e| {
                    ApiError::validation(message!(
                        "api-invalid-resource-pattern",
                        format!("invalid resource pattern '{uri}': {e}")
                    ))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let prompts = name_patterns(&self.mcp_prompts, "prompt")?;
        Ok(McpGrant::new(tools, resources, prompts))
    }
}

impl From<&CapabilitySet> for CapabilitySetDto {
    fn from(caps: &CapabilitySet) -> Self {
        Self {
            http: caps
                .http()
                .iter()
                .map(|p| p.to_string().trim_start_matches("idp:").to_owned())
                .collect(),
            messaging: caps
                .messaging()
                .iter()
                .map(TopicCapabilityDto::from)
                .collect(),
            resources: caps
                .resources()
                .iter()
                .map(ResourceCapabilityDto::from)
                .collect(),
            tools: tool_patterns(caps.mcp().tools()),
            mcp_resources: caps
                .mcp()
                .resources()
                .iter()
                .map(|pattern| pattern.as_str().to_owned())
                .collect(),
            mcp_prompts: caps
                .mcp()
                .prompts()
                .iter()
                .map(|pattern| pattern.as_str().to_owned())
                .collect(),
        }
    }
}

/// Tool patterns once each, preserving the order of their first grant.
fn tool_patterns(granted: &[McpTool]) -> Vec<String> {
    let mut tools: Vec<String> = Vec::new();
    for tool in granted {
        let pattern = tool.pattern().as_str();
        if !tools.iter().any(|seen| seen == pattern) {
            tools.push(pattern.to_owned());
        }
    }
    tools
}

/// Parses tool or prompt name patterns, naming the kind on failure.
fn name_patterns(values: &[String], kind: &str) -> Result<Vec<McpToolPattern>, ApiError> {
    values
        .iter()
        .map(|name| {
            McpToolPattern::new(name.as_str()).map_err(|e| {
                ApiError::validation(message!(
                    "api-invalid-pattern",
                    format!("invalid {kind} pattern '{name}': {e}")
                ))
            })
        })
        .collect()
}

/// A request budget: how many requests a token may make per window.
#[derive(Deserialize, Serialize, utoipa::ToSchema)]
pub(crate) struct BudgetDto {
    /// Maximum number of requests per window.
    pub max_requests: u32,
    /// Rolling window length, in seconds.
    pub window_seconds: u32,
    /// Requests counted in the current window, when the proxy's live
    /// counter could be read. Left out when the delegation was never used,
    /// or the counter did not answer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub used_requests: Option<u32>,
}

impl BudgetDto {
    /// The budget named.
    ///
    /// # Errors
    ///
    /// - A validation error when the window is zero.
    pub(crate) fn to_domain(&self) -> Result<AgentBudget, ApiError> {
        AgentBudget::new(Seconds::new(self.window_seconds))
            .map(|budget| budget.with_max_requests(self.max_requests))
            .map_err(ApiError::validation)
    }

    /// `budget` on the wire, when it caps requests; its use not read.
    #[must_use]
    pub(crate) fn of(budget: &AgentBudget) -> Option<Self> {
        budget.max_requests().limit().map(|max_requests| Self {
            max_requests: *max_requests,
            window_seconds: budget.window_seconds().get(),
            used_requests: None,
        })
    }

    /// This budget with `used_requests` counted against it.
    #[must_use]
    pub(crate) fn used(mut self, used_requests: Option<u32>) -> Self {
        self.used_requests = used_requests;
        self
    }
}
