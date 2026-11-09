//! Tool bodies: the APIs an agent may call.

use ianua_app::use_cases::agents::tools::{EditRequest, RegisterRequest, UpdateStatusRequest};
use ianua_domain::domains::agents::execution::tool::{
    AgentTool, ToolDescription, ToolMethod, ToolName, ToolPath, ToolSchema, ToolStatus,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::{AgentToolId, RouteId};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::ApiError;

/// Request body for registering a tool.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct RegisterToolBody {
    /// The name the model calls, such as `get_order`.
    pub name: String,
    /// What the tool does, shown to the model.
    pub description: String,
    /// JSON schema for the tool's input parameters.
    #[schema(value_type = Object)]
    pub schema: serde_json::Value,
    /// HTTP method: `GET`, `POST`, `PUT`, `PATCH`, or `DELETE`.
    pub method: String,
    /// URL path template the tool calls, such as `/orders/{id}`.
    pub path: String,
    /// The route that serves the call. The tool takes its action class and
    /// data class from the route.
    pub route_id: Uuid,
}

impl TryFrom<RegisterToolBody> for RegisterRequest {
    type Error = ApiError;

    fn try_from(body: RegisterToolBody) -> Result<Self, Self::Error> {
        let definition = body.definition()?;
        Ok(Self {
            name: definition.name,
            description: definition.description,
            schema: definition.schema,
            method: definition.method,
            path: definition.path,
            route_id: definition.route_id,
        })
    }
}

impl RegisterToolBody {
    /// The new definition of `tool_id` this body names, replacing the
    /// whole of the old one.
    ///
    /// # Errors
    ///
    /// - A validation error for a name, description, schema, method or path
    ///   that is not valid.
    pub(crate) fn into_edit(self, tool_id: AgentToolId) -> Result<EditRequest, ApiError> {
        let definition = self.definition()?;
        Ok(EditRequest {
            tool_id,
            name: definition.name,
            description: definition.description,
            schema: definition.schema,
            method: definition.method,
            path: definition.path,
            route_id: definition.route_id,
        })
    }

    /// The definition this body names, each part checked.
    fn definition(self) -> Result<ToolDefinition, ApiError> {
        Ok(ToolDefinition {
            name: ToolName::new(self.name).map_err(ApiError::validation)?,
            description: ToolDescription::new(self.description).map_err(ApiError::validation)?,
            schema: ToolSchema::new(self.schema.to_string()).map_err(ApiError::validation)?,
            method: ToolMethod::parse(&self.method).map_err(ApiError::validation)?,
            path: ToolPath::new(self.path).map_err(ApiError::validation)?,
            route_id: RouteId::from_uuid(self.route_id),
        })
    }
}

/// A tool's definition, read from a body.
struct ToolDefinition {
    name: ToolName,
    description: ToolDescription,
    schema: ToolSchema,
    method: ToolMethod,
    path: ToolPath,
    route_id: RouteId,
}

/// Request body for enabling or disabling a tool.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct UpdateToolStatusBody {
    /// The status wanted: `active` or `disabled`.
    pub status: String,
}

impl UpdateToolStatusBody {
    /// The change of `tool_id` to the status named.
    ///
    /// # Errors
    ///
    /// - A validation error when `status` names no status.
    pub(crate) fn into_request(
        self,
        tool_id: AgentToolId,
    ) -> Result<UpdateStatusRequest, ApiError> {
        Ok(UpdateStatusRequest {
            tool_id,
            status: ToolStatus::parse(&self.status).map_err(ApiError::validation)?,
        })
    }
}

/// Identifies a newly registered tool.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct RegisterToolResponse {
    /// The tool's unique identifier.
    pub id: Uuid,
}

impl From<AgentToolId> for RegisterToolResponse {
    fn from(id: AgentToolId) -> Self {
        Self { id: *id.as_uuid() }
    }
}

/// A registered tool.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct ToolResponse {
    /// Unique identifier.
    pub id: Uuid,
    /// Tool name.
    pub name: String,
    /// Explains what the tool does to callers choosing an action.
    pub description: String,
    /// Input JSON schema.
    #[schema(value_type = Object)]
    pub schema: serde_json::Value,
    /// HTTP method.
    pub method: String,
    /// URL path template.
    pub path: String,
    /// The route that serves the call.
    pub route_id: Uuid,
    /// The action class this tool exercises, for the purpose check.
    pub action_class: String,
    /// The tool's data class (`public`, `internal`, `confidential`,
    /// `restricted`).
    pub classification: String,
    /// Lifecycle status (`active` or `disabled`).
    pub status: String,
}

impl From<AgentTool<ResolvedTenant>> for ToolResponse {
    fn from(tool: AgentTool<ResolvedTenant>) -> Self {
        let schema = serde_json::from_str(tool.schema().as_str())
            .unwrap_or_else(|_| serde_json::Value::String(tool.schema().as_str().to_owned()));
        Self {
            id: *tool.id().as_uuid(),
            name: tool.name().as_str().to_owned(),
            description: tool.description().as_str().to_owned(),
            schema,
            method: tool.method().as_str().to_owned(),
            path: tool.path().as_str().to_owned(),
            route_id: *tool.route_id().as_uuid(),
            action_class: tool.action_class().as_str().to_owned(),
            classification: tool.classification().as_str().to_owned(),
            status: tool.status().as_str().to_owned(),
        }
    }
}
