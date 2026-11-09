//! Pipelines as a gateway holds them, for the tests of what a pipeline
//! answers about a request.

use time::OffsetDateTime;

use crate::domains::proxy::pipeline::{Pipeline, PipelineRow};
use crate::domains::proxy::pipeline_status::PipelineStatus;
use crate::domains::proxy::stages::stage::{
    MandatoryStage, StageConfig, StageConfigRow, StageKind, StageRemoval,
};
use crate::isolation::scope::ResolvedTenant;
use crate::types::{Enablement, Label, PipelineId, StageId};

/// A stage of `kind` the tenant added, switched on.
pub(crate) fn stage(kind: StageKind) -> StageConfigRow {
    StageConfigRow {
        id: StageId::new(),
        kind,
        position: 0,
        enabled: Enablement::Enabled,
        removal: StageRemoval::Allowed,
    }
}

/// A stage of `kind` the tenant added, switched off.
pub(crate) fn switched_off(kind: StageKind) -> StageConfigRow {
    StageConfigRow {
        enabled: Enablement::Disabled,
        ..stage(kind)
    }
}

/// A stored pipeline in `status` running Identity, Policy, then `added` in
/// the order given.
pub(crate) fn with_status(
    status: PipelineStatus,
    added: Vec<StageConfigRow>,
) -> Pipeline<ResolvedTenant> {
    let mandatory = [MandatoryStage::Identity, MandatoryStage::Policy]
        .into_iter()
        .map(StageConfig::locked);
    let added = added.into_iter().zip(300u16..).map(|(row, position)| {
        StageConfig::reconstitute(StageConfigRow { position, ..row }).unwrap()
    });
    let at = OffsetDateTime::UNIX_EPOCH;
    Pipeline::reconstitute(PipelineRow {
        id: PipelineId::new(),
        name: Label::new("pipeline_name", "edge").unwrap(),
        status,
        stages: mandatory.chain(added).collect(),
        created_at: at,
        updated_at: at,
    })
    .unwrap()
}

/// A running pipeline with Identity, Policy, then `added`.
pub(crate) fn running(added: Vec<StageConfigRow>) -> Pipeline<ResolvedTenant> {
    with_status(PipelineStatus::Active, added)
}
