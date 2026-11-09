//! A pipeline as its row holds it: read back into the aggregate, and
//! written out from it. Its stages are one JSON list, each stage checked
//! by the domain as it is read.

use ianua_domain::domains::proxy::pipeline::{Pipeline, PipelineRow};
use ianua_domain::domains::proxy::stages::stage::StageConfig;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{Label, PipelineId};
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::foundation::envelope::Kept;
use crate::postgres::foundation::stored::{Stored, StoredWord as _};

const PIPELINE: Stored = Stored("pipeline");

/// The route count for one requested pipeline.
pub(super) struct RouteCountRecord {
    pub(super) pipeline_id: Uuid,
    pub(super) count: i64,
}

impl RouteCountRecord {
    /// Keeps the pipeline identity and refuses a negative stored count.
    pub(super) fn into_count(self) -> Result<(PipelineId, u64), DomainError> {
        let count = u64::try_from(self.count).map_err(DomainError::infra)?;
        Ok((PipelineId::from_uuid(self.pipeline_id), count))
    }
}

const STAGES: Kept = Kept {
    entity: PIPELINE.0,
    column: "stages",
    shape: 1,
};

/// A pipeline as it is read. The store's checked queries fill it.
pub(super) struct PipelineRecord {
    pub(super) id: Uuid,
    pub(super) name: String,
    pub(super) status: String,
    pub(super) stages: Value,
    pub(super) created_at: OffsetDateTime,
    pub(super) updated_at: OffsetDateTime,
}

impl PipelineRecord {
    /// The pipeline the record holds, rebuilt through the domain's checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a value no longer passes
    /// its rules, the status is unknown, a stage does not read, or the row
    /// breaks a rule the pipeline keeps, such as running without Identity.
    pub(super) fn into_pipeline(self) -> Result<Pipeline<ResolvedTenant>, DomainError> {
        let stages: Vec<StageConfig> = STAGES.open(self.stages)?;
        Pipeline::reconstitute(PipelineRow {
            id: PipelineId::from_uuid(self.id),
            name: PIPELINE.value("name", Label::new("name", self.name))?,
            status: PIPELINE.choice(&self.status)?,
            stages,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

/// A pipeline's columns, as they are written.
pub(super) struct PipelineColumns<'a> {
    pub(super) id: &'a Uuid,
    pub(super) name: &'a str,
    pub(super) status: &'static str,
    pub(super) stages: Value,
    pub(super) created_at: OffsetDateTime,
    pub(super) updated_at: OffsetDateTime,
}

impl<'a> PipelineColumns<'a> {
    /// The columns `pipeline` is written to.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when its stages cannot be
    /// written out.
    pub(super) fn of(pipeline: &'a Pipeline<ResolvedTenant>) -> Result<Self, DomainError> {
        Ok(Self {
            id: pipeline.id().as_uuid(),
            name: pipeline.name().as_str(),
            status: pipeline.status().word(),
            stages: STAGES.seal(pipeline.stages())?,
            created_at: pipeline.created_at(),
            updated_at: pipeline.updated_at(),
        })
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    /// The two stages every pipeline holds, in the shape the column keeps.
    fn stored_stages() -> Value {
        json!({"v": 1, "value": [
            {
                "id": "00000000-0000-0000-0000-000000000001",
                "kind": "Identity",
                "position": 100,
                "enabled": true,
                "mandatory": true
            },
            {
                "id": "00000000-0000-0000-0000-000000000002",
                "kind": "Policy",
                "position": 200,
                "enabled": true,
                "mandatory": true
            }
        ]})
    }

    /// Stages stored in the shape pinned here read back, and are written
    /// again in the same shape.
    #[test]
    fn the_stages_are_stored_in_their_pinned_shape() {
        let read: Vec<StageConfig> = STAGES.open(stored_stages()).unwrap();

        assert_eq!(read.len(), 2);
        assert_eq!(STAGES.seal(&read).unwrap(), stored_stages());
    }

    /// Decoding a stored Identity stage with `mandatory` set to false fails.
    #[test]
    fn an_identity_stage_stored_as_removable_is_refused() {
        let removable = json!({"v": 1, "value": [{
            "id": "00000000-0000-0000-0000-000000000001",
            "kind": "Identity",
            "position": 100,
            "enabled": true,
            "mandatory": false
        }]});

        assert!(STAGES.open::<Vec<StageConfig>>(removable).is_err());
    }
}
