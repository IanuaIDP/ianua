//! A tool as its row holds it: read back into the aggregate, and written
//! out from it.

use ianua_domain::domains::agents::execution::tool::{
    AgentTool, AgentToolRow, ToolDescription, ToolName, ToolPath, ToolSchema,
};
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::model::aggregate::Aggregate as _;
use ianua_domain::types::{ActionClass, AgentToolId, DeclaredAction, RouteId};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::foundation::stored::{Stored, StoredWord as _};

const TOOL: Stored = Stored("agent tool");

/// A tool as it is read. The store's checked queries fill it.
pub(super) struct ToolRecord {
    pub(super) id: Uuid,
    pub(super) name: String,
    pub(super) description: String,
    pub(super) input_schema: String,
    pub(super) method: String,
    pub(super) path: String,
    pub(super) route_id: Uuid,
    pub(super) declared_action: Option<String>,
    pub(super) action_class: String,
    pub(super) data_class: String,
    pub(super) status: String,
    pub(super) created_at: OffsetDateTime,
    pub(super) updated_at: OffsetDateTime,
}

impl ToolRecord {
    /// The tool the record holds, rebuilt through the domain's checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a value no longer passes
    /// its rules, a word is unknown, or the row breaks a rule the tool
    /// keeps.
    pub(super) fn into_tool(self) -> Result<AgentTool<ResolvedTenant>, DomainError> {
        let declared = self
            .declared_action
            .as_deref()
            .map(ActionClass::from_stored)
            .transpose()?;
        AgentTool::reconstitute(AgentToolRow {
            id: AgentToolId::from_uuid(self.id),
            name: TOOL.value("name", ToolName::new(self.name))?,
            description: TOOL.value("description", ToolDescription::new(self.description))?,
            schema: TOOL.value("input schema", ToolSchema::new(self.input_schema))?,
            method: TOOL.choice(&self.method)?,
            path: TOOL.value("path", ToolPath::new(self.path))?,
            route_id: RouteId::from_uuid(self.route_id),
            declared_action: DeclaredAction::from_stored(declared),
            action_class: ActionClass::from_stored(&self.action_class)?,
            classification: DataClassLevel::from_stored(&self.data_class)?,
            status: TOOL.choice(&self.status)?,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

/// A tool's columns, as they are written.
pub(super) struct ToolColumns<'a> {
    pub(super) id: &'a Uuid,
    pub(super) name: &'a str,
    pub(super) description: &'a str,
    pub(super) input_schema: &'a str,
    pub(super) method: &'static str,
    pub(super) path: &'a str,
    pub(super) route_id: &'a Uuid,
    pub(super) declared_action: Option<&'static str>,
    pub(super) action_class: &'static str,
    pub(super) data_class: &'static str,
    pub(super) status: &'static str,
    pub(super) created_at: OffsetDateTime,
    pub(super) updated_at: OffsetDateTime,
}

impl<'a> ToolColumns<'a> {
    /// The columns `tool` is written to.
    pub(super) fn of(tool: &'a AgentTool<ResolvedTenant>) -> Self {
        Self {
            id: tool.id().as_uuid(),
            name: tool.name().as_str(),
            description: tool.description().as_str(),
            input_schema: tool.schema().as_str(),
            method: tool.method().word(),
            path: tool.path().as_str(),
            route_id: tool.route_id().as_uuid(),
            declared_action: tool.declared_action().stored().map(ActionClass::as_str),
            action_class: tool.action_class().as_str(),
            data_class: tool.classification().as_str(),
            status: tool.status().word(),
            created_at: tool.created_at(),
            updated_at: tool.updated_at(),
        }
    }
}
