//! Dry-run check bodies: whether an agent may take an action, make a
//! request, or exercise a relation on an object.

use ianua_app::use_cases::agents::access::{
    AgentAuthorizeOutcome, AuthorizeAgentRequest, AuthorizeCheckTarget, AuthorizeResourceRequest,
};
use ianua_domain::domains::authorization::permission::SystemPermission;
use ianua_domain::message;
use ianua_domain::types::{AgentId, CanonicalPath, HttpMethod};
use serde::{Deserialize, Serialize};

use crate::dto::agents::capabilities::ResourceCapabilityDto;
use crate::error::ApiError;

/// Request body for a dry-run authorization check.
///
/// Give either `action` (a bare `domain:action` permission the agent's
/// delegations must grant) or `method` and `path` together (a specific
/// request: the tenant's routes are resolved to find the governing policy,
/// then checked against the agent's delegated authority the way the proxy
/// would). The two forms exclude each other.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct AuthorizeCheckBody {
    /// The action to check, as a `domain:action` string.
    #[serde(default)]
    pub action: Option<String>,
    /// The HTTP method of the request to check, such as `Post`. Given
    /// together with `path`.
    #[serde(default)]
    #[schema(schema_with = crate::dto::schemas::http_method)]
    pub method: Option<HttpMethod>,
    /// The request path to check, such as `/api/support`. Given together
    /// with `method`.
    #[serde(default)]
    pub path: Option<String>,
}

impl AuthorizeCheckBody {
    /// The check of agent `agent_id` this body asks for.
    ///
    /// # Errors
    ///
    /// - A validation error when neither or both forms are given, only one
    ///   of `method` and `path` is, `action` names no permission, or `path`
    ///   is not a path.
    pub(crate) fn into_request(self, agent_id: AgentId) -> Result<AuthorizeAgentRequest, ApiError> {
        Ok(AuthorizeAgentRequest {
            agent_id,
            target: self.target()?,
        })
    }

    /// What the check asks about: a permission by name, or a method and
    /// path, but never both and never neither.
    fn target(self) -> Result<AuthorizeCheckTarget, ApiError> {
        match (self.action, self.method, self.path) {
            (Some(action), None, None) => SystemPermission::parse(&action)
                .map(AuthorizeCheckTarget::Action)
                .ok_or_else(|| {
                    ApiError::validation(message!(
                        "api-unknown-permission-2",
                        format!("unknown permission: {action}")
                    ))
                }),
            (None, Some(method), Some(path)) => Ok(AuthorizeCheckTarget::Request {
                method,
                path: CanonicalPath::new(path).map_err(ApiError::validation)?,
            }),
            (None, None, None) => Err(ApiError::validation(message!(
                "api-provide-either-action-or-method-and",
                "provide either `action`, or `method` and `path`"
            ))),
            _ => Err(ApiError::validation(message!(
                "api-action-excludes-method-and-path-and",
                "`action` excludes `method` and `path`, and `method` and `path` are given \
                 together"
            ))),
        }
    }
}

/// Request body for a dry-run resource-scoped check.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct AuthorizeResourceBody {
    /// The relation the agent wants on the object, such as `reader`.
    pub relation: String,
    /// The object reference, such as `calendar:abc123`.
    pub resource: String,
}

impl AuthorizeResourceBody {
    /// The check of agent `agent_id` this body asks for.
    ///
    /// # Errors
    ///
    /// - A validation error when the relation or the object is not valid.
    pub(crate) fn into_request(
        self,
        agent_id: AgentId,
    ) -> Result<AuthorizeResourceRequest, ApiError> {
        let required = ResourceCapabilityDto {
            relation: self.relation,
            resource: self.resource,
        }
        .to_domain()?;
        Ok(AuthorizeResourceRequest { agent_id, required })
    }
}

/// Result of a dry-run check.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct AuthorizeCheckResponse {
    /// `allow` or `deny`.
    pub decision: String,
    /// Why.
    pub reason: String,
}

impl From<AgentAuthorizeOutcome> for AuthorizeCheckResponse {
    fn from(outcome: AgentAuthorizeOutcome) -> Self {
        let (decision, reason) = match outcome {
            AgentAuthorizeOutcome::Allowed { reason } => ("allow", reason),
            AgentAuthorizeOutcome::Denied { reason } => ("deny", reason),
        };
        Self {
            decision: decision.to_owned(),
            reason,
        }
    }
}
