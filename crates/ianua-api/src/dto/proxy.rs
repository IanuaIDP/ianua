//! Proxy bodies: a tenant's request pipelines and their stages, canary
//! tokens and WASM stage modules; the request records the gateway kept and
//! the places they are shipped to, by area.

pub mod log_targets;
pub mod requests;

use base64::Engine as _;
use ianua_app::use_cases::proxy::pipelines::{RenameRequest, WithUsage};
use ianua_app::use_cases::proxy::stages::{AddRequest, ReconfigureRequest, ReorderRequest};
use ianua_domain::domains::proxy::pipeline::Pipeline;
use ianua_domain::domains::proxy::pipeline_status::PipelineStatus;
use ianua_domain::domains::proxy::stages::stage::{ModuleRef, StageConfig, StageKind};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::types::{Label, PipelineId, StageId};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::ApiError;
use crate::extractors::paths::proxy::StagePath;

/// Request body for creating a pipeline.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct CreatePipelineBody {
    /// What routes will name it by. Unique within the tenant.
    pub name: String,
}

impl TryFrom<CreatePipelineBody> for Label {
    type Error = ApiError;

    fn try_from(body: CreatePipelineBody) -> Result<Self, Self::Error> {
        pipeline_name(body.name)
    }
}

/// Request body for renaming a pipeline.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct RenamePipelineBody {
    /// The name it is to carry. Unique within the tenant.
    pub name: String,
}

impl RenamePipelineBody {
    /// The rename this body asks of `pipeline`.
    ///
    /// # Errors
    ///
    /// Returns [`ApiError::validation`] for a name that is not a valid one.
    pub(crate) fn into_request(self, pipeline: PipelineId) -> Result<RenameRequest, ApiError> {
        Ok(RenameRequest {
            pipeline_id: pipeline,
            name: pipeline_name(self.name)?,
        })
    }
}

/// Reads a pipeline's name.
fn pipeline_name(name: String) -> Result<Label, ApiError> {
    Label::new("pipeline_name", name).map_err(ApiError::validation)
}

/// Request body for adding a stage.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct AddStageBody {
    /// What the stage does, with its configuration, such as
    /// `{"RateLimit": {...}}`.
    ///
    /// Carries no position. A new stage always goes on the end, and is moved
    /// with `PUT .../stages/order`. This used to take one, and a client
    /// choosing a number without knowing the ones already in use would put
    /// its stage ahead of Identity, filtering traffic before anything had
    /// worked out who sent it.
    #[schema(value_type = Object)]
    pub kind: StageKind,
}

impl AddStageBody {
    /// The stage this body appends to `pipeline`.
    #[must_use]
    pub(crate) fn into_request(self, pipeline: PipelineId) -> AddRequest {
        AddRequest {
            pipeline_id: pipeline,
            kind: self.kind,
        }
    }
}

/// Request body for changing a stage's settings in place.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct ReconfigureStageBody {
    /// The stage's new settings, of its own kind, such as
    /// `{"RateLimit": {...}}`. A kind other than the stage's is refused.
    #[schema(value_type = Object)]
    pub kind: StageKind,
}

impl ReconfigureStageBody {
    /// The new settings this body gives the stage `path` names.
    #[must_use]
    pub(crate) fn into_request(self, path: &StagePath) -> ReconfigureRequest {
        ReconfigureRequest {
            pipeline_id: path.pipeline(),
            stage_id: path.stage(),
            kind: self.kind,
        }
    }
}

/// Request body for setting a pipeline's evaluation order.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct ReorderStagesBody {
    /// Every stage id, in the order they should run.
    ///
    /// The whole order, not one stage's new index: a drag-and-drop sends the
    /// list it ended up with and the pipeline is rewritten to match, in one
    /// request. The list must name every stage exactly once: a partial list
    /// is refused, since the stages it left out would collect at the front of
    /// the pipeline.
    pub stage_ids: Vec<Uuid>,
}

impl ReorderStagesBody {
    /// The order this body sets on `pipeline`.
    #[must_use]
    pub(crate) fn into_request(self, pipeline: PipelineId) -> ReorderRequest {
        ReorderRequest {
            pipeline_id: pipeline,
            order: self.stage_ids.into_iter().map(StageId::from_uuid).collect(),
        }
    }
}

/// Request body for uploading a WASM stage module.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct UploadWasmModuleBody {
    /// Base64-encoded (standard, padded) WASM module bytecode.
    pub bytecode_base64: String,
}

impl UploadWasmModuleBody {
    /// The module's bytecode.
    ///
    /// # Errors
    ///
    /// Returns [`ApiError::validation`] when `bytecode_base64` is not valid
    /// base64.
    pub(crate) fn bytecode(&self) -> Result<Vec<u8>, ApiError> {
        base64::engine::general_purpose::STANDARD
            .decode(&self.bytecode_base64)
            .map_err(|e| {
                ApiError::validation(message!(
                    "api-invalid-base64-bytecode",
                    format!("invalid base64 bytecode: {e}")
                ))
            })
    }
}

/// One stage of a pipeline.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct StageResponse {
    /// Unique identifier.
    pub id: Uuid,
    /// What the stage does, with its configuration.
    #[schema(value_type = Object)]
    pub kind: StageKind,
    /// Evaluation order. Lower runs first.
    pub position: u16,
    /// Whether it runs.
    pub enabled: bool,
    /// Whether it may be removed or disabled. Only `Identity` and `Policy`
    /// are.
    pub mandatory: bool,
}

impl From<&StageConfig> for StageResponse {
    fn from(s: &StageConfig) -> Self {
        Self {
            id: *s.id().as_uuid(),
            kind: s.kind().clone(),
            position: s.position(),
            enabled: s.enabled(),
            mandatory: s.mandatory(),
        }
    }
}

/// The ordered proxy stages and lifecycle state attached to a named pipeline.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct PipelineResponse {
    /// Unique identifier.
    pub id: Uuid,
    /// What a route names it by, unique within the tenant.
    pub name: String,
    /// `Draft`, `Active` or `Disabled`.
    #[schema(schema_with = crate::dto::schemas::pipeline_status)]
    pub status: PipelineStatus,
    /// Every stage, enabled or not, in the order they run.
    ///
    /// Ordered here so a caller can render the pipeline as it arrives and
    /// hand the same list back to `PUT .../stages/order`. Disabled stages
    /// keep their place: they are skipped, not removed.
    pub stages: Vec<StageResponse>,
    /// When the pipeline was created.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// When it last changed.
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

impl From<Pipeline<ResolvedTenant>> for PipelineResponse {
    fn from(p: Pipeline<ResolvedTenant>) -> Self {
        Self {
            id: *p.id().as_uuid(),
            name: p.name().as_str().to_owned(),
            status: p.status(),
            stages: p
                .stages_in_order()
                .into_iter()
                .map(StageResponse::from)
                .collect(),
            created_at: p.created_at(),
            updated_at: p.updated_at(),
        }
    }
}

/// The id of a newly created pipeline: what a route is pointed at.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct CreatePipelineResponse {
    /// The new pipeline.
    pub id: Uuid,
}

impl From<PipelineId> for CreatePipelineResponse {
    fn from(id: PipelineId) -> Self {
        Self { id: *id.as_uuid() }
    }
}

/// One pipeline in a listing, with what it would cost to delete.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct PipelineSummaryResponse {
    /// Unique identifier.
    pub id: Uuid,
    /// What a route names it by.
    pub name: String,
    /// `Draft`, `Active` or `Disabled`.
    #[schema(schema_with = crate::dto::schemas::pipeline_status)]
    pub status: PipelineStatus,
    /// How many stages it runs.
    pub stage_count: u32,
    /// How many routes name it. Non-zero means deleting it is refused.
    pub route_count: u64,
    /// When the pipeline was created.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// When it last changed.
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

impl From<WithUsage> for PipelineSummaryResponse {
    fn from(entry: WithUsage) -> Self {
        let p = entry.pipeline;
        Self {
            id: *p.id().as_uuid(),
            name: p.name().as_str().to_owned(),
            status: p.status(),
            stage_count: u32::try_from(p.stages().len()).unwrap_or(u32::MAX),
            route_count: entry.route_count,
            created_at: p.created_at(),
            updated_at: p.updated_at(),
        }
    }
}

/// A freshly generated canary token.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct GeneratedCanaryTokenResponse {
    /// The generated decoy credential. Not stored anywhere: add it to a
    /// `CanaryToken` stage's `tokens` list yourself, with
    /// `PATCH .../stages/{id}`.
    pub token: String,
}

/// An uploaded WASM module.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct WasmModuleResponse {
    /// Content-addressed reference (`sha256:<hex>`). Assign this to a
    /// `Custom` stage's `module_ref` yourself: uploading does not create or
    /// change any stage.
    pub module_ref: String,
}

impl From<ModuleRef> for WasmModuleResponse {
    fn from(module_ref: ModuleRef) -> Self {
        Self {
            module_ref: module_ref.as_str().to_owned(),
        }
    }
}
