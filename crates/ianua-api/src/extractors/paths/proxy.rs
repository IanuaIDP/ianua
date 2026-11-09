//! The pipeline, the stage of it, or the log shipping target a tenant
//! request names.

use ianua_domain::types::{LogShippingTargetId, PipelineId, StageId};
use serde::Deserialize;
use uuid::Uuid;

/// `.../pipelines/{pipeline_id}/...`.
#[derive(Deserialize)]
pub(crate) struct PipelinePath {
    pipeline_id: Uuid,
}

impl PipelinePath {
    /// The pipeline named.
    #[must_use]
    pub(crate) fn pipeline(&self) -> PipelineId {
        PipelineId::from_uuid(self.pipeline_id)
    }
}

/// `.../pipelines/{pipeline_id}/stages/{id}/...`.
#[derive(Deserialize)]
pub(crate) struct StagePath {
    pipeline_id: Uuid,
    id: Uuid,
}

impl StagePath {
    /// The pipeline holding the stage.
    #[must_use]
    pub(crate) fn pipeline(&self) -> PipelineId {
        PipelineId::from_uuid(self.pipeline_id)
    }

    /// The stage named.
    #[must_use]
    pub(crate) fn stage(&self) -> StageId {
        StageId::from_uuid(self.id)
    }
}

/// `.../gateway/log-targets/{id}/...`.
#[derive(Deserialize)]
pub(crate) struct LogTargetPath {
    id: Uuid,
}

impl LogTargetPath {
    /// The log shipping target named.
    #[must_use]
    pub(crate) fn target(&self) -> LogShippingTargetId {
        LogShippingTargetId::from_uuid(self.id)
    }
}
