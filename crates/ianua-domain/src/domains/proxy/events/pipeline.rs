//! Events about a tenant's pipelines and their stages.

use time::OffsetDateTime;

use crate::shared::events::data::{EventData, RefKind, Reference};
use crate::shared::events::event::tenant_event;
use crate::types::{Label, PipelineId, StageId};

const PIPELINE: RefKind = RefKind::new("pipeline");

/// References the pipeline a proxy event acted on.
///
/// The pipeline's id serves as its label.
fn pipeline_reference(pipeline_id: &PipelineId) -> Reference {
    let id = pipeline_id.to_string();
    Reference::new(PIPELINE, id.clone(), id)
}

/// A pipeline was deleted.
#[derive(Debug)]
pub struct PipelineDeleted {
    /// The deleted pipeline.
    pub(crate) pipeline_id: PipelineId,
    /// When the pipeline was deleted.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    PipelineDeleted => crate::types::event_type::ProxyEvent::PipelineDeleted,
    fn payload(&self) -> EventData {
        EventData::new().reference("pipeline", pipeline_reference(&self.pipeline_id))
    }
}

/// A pipeline was renamed. Routes run it by id, so nothing they do
/// changes; the record keeps both names for whoever reads the audit trail.
#[derive(Debug)]
pub struct PipelineRenamed {
    /// The renamed pipeline.
    pub(crate) pipeline_id: PipelineId,
    /// The name before the change.
    pub(crate) previous_name: Label,
    /// The name now.
    pub(crate) current_name: Label,
    /// When it was renamed.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    PipelineRenamed => crate::types::event_type::ProxyEvent::PipelineRenamed,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference("pipeline", pipeline_reference(&self.pipeline_id))
            .change(
                "name",
                self.previous_name.as_str(),
                self.current_name.as_str(),
            )
    }
}

/// A pipeline was created for a tenant.
#[derive(Debug)]
pub struct PipelineCreated {
    /// The new pipeline.
    pub(crate) pipeline_id: PipelineId,
    /// When the pipeline was created.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    PipelineCreated => crate::types::event_type::ProxyEvent::PipelineCreated,
    fn payload(&self) -> EventData {
        EventData::new().reference("pipeline", pipeline_reference(&self.pipeline_id))
    }
}

/// A pipeline started running on live traffic.
///
/// Published so every proxy reloads it. Until a proxy hears of it, that proxy
/// keeps refusing the routes that run it, as if the pipeline were not active.
#[derive(Debug)]
pub struct PipelineActivated {
    /// The pipeline now running on live traffic.
    pub(crate) pipeline_id: PipelineId,
    /// When the pipeline was activated.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    PipelineActivated => crate::types::event_type::ProxyEvent::PipelineActivated,
    fn payload(&self) -> EventData {
        EventData::new().reference("pipeline", pipeline_reference(&self.pipeline_id))
    }
}

/// A pipeline stopped running on live traffic.
///
/// Published so every proxy reloads it. Until a proxy hears of it, that proxy
/// keeps running a pipeline its tenant has switched off.
#[derive(Debug)]
pub struct PipelineDisabled {
    /// The pipeline taken off live traffic.
    pub(crate) pipeline_id: PipelineId,
    /// When the pipeline was disabled.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    PipelineDisabled => crate::types::event_type::ProxyEvent::PipelineDisabled,
    fn payload(&self) -> EventData {
        EventData::new().reference("pipeline", pipeline_reference(&self.pipeline_id))
    }
}

/// A stage was added to a pipeline.
#[derive(Debug)]
pub struct StageAdded {
    /// The pipeline the stage was added to.
    pub(crate) pipeline_id: PipelineId,
    /// The new stage.
    pub(crate) stage_id: StageId,
    /// The stage's kind, as text.
    pub(crate) stage_kind: &'static str,
    /// Where the stage runs in the pipeline's order.
    pub(crate) position: u16,
    /// When the stage was added.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    StageAdded => crate::types::event_type::ProxyEvent::StageAdded,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference("pipeline", pipeline_reference(&self.pipeline_id))
            .field("stage_id", self.stage_id.to_string())
            .field("stage_kind", self.stage_kind)
            .field("position", self.position.to_string())
    }
}

/// A stage was removed from a pipeline.
#[derive(Debug)]
pub struct StageRemoved {
    /// The pipeline the stage was removed from.
    pub(crate) pipeline_id: PipelineId,
    /// The removed stage.
    pub(crate) stage_id: StageId,
    /// When the stage was removed.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    StageRemoved => crate::types::event_type::ProxyEvent::StageRemoved,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference("pipeline", pipeline_reference(&self.pipeline_id))
            .field("stage_id", self.stage_id.to_string())
    }
}

/// A stage's settings were changed in place.
///
/// It names the stage and its kind, never the settings, which may hold
/// decoys and secret references.
#[derive(Debug)]
pub struct StageReconfigured {
    /// The pipeline the stage belongs to.
    pub(crate) pipeline_id: PipelineId,
    /// The stage whose settings changed.
    pub(crate) stage_id: StageId,
    /// The stage's kind, as text.
    pub(crate) stage_kind: &'static str,
    /// When the settings changed.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    StageReconfigured => crate::types::event_type::ProxyEvent::StageReconfigured,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference("pipeline", pipeline_reference(&self.pipeline_id))
            .field("stage_id", self.stage_id.to_string())
            .field("stage_kind", self.stage_kind)
    }
}

/// A stage was enabled.
#[derive(Debug)]
pub struct StageEnabled {
    /// The pipeline the stage belongs to.
    pub(crate) pipeline_id: PipelineId,
    /// The enabled stage.
    pub(crate) stage_id: StageId,
    /// When the stage was enabled.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    StageEnabled => crate::types::event_type::ProxyEvent::StageEnabled,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference("pipeline", pipeline_reference(&self.pipeline_id))
            .field("stage_id", self.stage_id.to_string())
    }
}

/// A stage was disabled.
#[derive(Debug)]
pub struct StageDisabled {
    /// The pipeline the stage belongs to.
    pub(crate) pipeline_id: PipelineId,
    /// The disabled stage.
    pub(crate) stage_id: StageId,
    /// When the stage was disabled.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    StageDisabled => crate::types::event_type::ProxyEvent::StageDisabled,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference("pipeline", pipeline_reference(&self.pipeline_id))
            .field("stage_id", self.stage_id.to_string())
    }
}

/// The order a pipeline runs its stages in was changed.
#[derive(Debug)]
pub struct PipelineReordered {
    /// The reordered pipeline.
    pub(crate) pipeline_id: PipelineId,
    /// Every stage, in the order they now run.
    ///
    /// The whole order, not one stage's new position. A reorder moves the
    /// pipeline from one order to another. With a single stage, the audit
    /// log could not say what the pipeline became.
    pub(crate) order: Vec<StageId>,
    /// When the pipeline was reordered.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    PipelineReordered => crate::types::event_type::ProxyEvent::PipelineReordered,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference("pipeline", pipeline_reference(&self.pipeline_id))
            .field("stage_count", self.order.len().to_string())
            .field(
                "stage_order",
                self.order
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", "),
            )
    }
}
