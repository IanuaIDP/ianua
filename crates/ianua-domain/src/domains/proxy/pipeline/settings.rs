//! Changing a stage's settings in place.
//!
//! A tenant tunes a rate limit or adds a country to a geofence without
//! taking the stage out and adding it again. The stage keeps its id, its
//! place and whether it is on, so the audit trail shows one change to one
//! stage.

use crate::domains::proxy::events::StageReconfigured;
use crate::domains::proxy::pipeline::{Pipeline, PipelineError};
use crate::domains::proxy::stages::stage::StageKind;
use crate::domains::routing::control::RoutingControl;
use crate::isolation::scope::TenantScope;
use crate::shared::errors::Refusal;
use crate::types::StageId;

impl<T: TenantScope> Pipeline<T> {
    /// Gives the stage `stage_id` the settings `kind` carries. Raises
    /// `proxy.stage_reconfigured`, naming the stage and its kind but never
    /// its settings, which may hold decoys and secret references.
    ///
    /// # Errors
    ///
    /// Returns [`PipelineError::NotAllowed`] without pipeline-change rights,
    /// [`PipelineError::ActivePipelineImmutable`] if active, or [`PipelineError::StageNotFound`] if absent.
    /// Returns [`PipelineError::CannotReconfigureMandatory`] for Identity or Policy,
    /// [`PipelineError::OtherKind`] for a different stage kind, or
    /// [`PipelineError::SettingsRefused`] for settings that prevent the stage working.
    pub fn reconfigure_stage(
        &mut self,
        stage_id: &StageId,
        kind: StageKind,
        by: &RoutingControl<'_>,
    ) -> Result<(), PipelineError> {
        self.require_mutable(by)?;
        let stage = self
            .stages
            .iter_mut()
            .find(|s| s.id() == stage_id)
            .ok_or(PipelineError::StageNotFound)?;
        if stage.mandatory() {
            return Err(PipelineError::CannotReconfigureMandatory);
        }
        if stage.kind().name() != kind.name() {
            return Err(PipelineError::OtherKind);
        }
        let stage_kind = kind.name();
        stage
            .reconfigure(kind)
            .map_err(|refused| PipelineError::SettingsRefused(Refusal::new(refused.to_string())))?;
        self.touch();
        self.raised.raise(StageReconfigured {
            pipeline_id: self.id,
            stage_id: *stage_id,
            stage_kind,
            occurred_at: self.updated_at,
        });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::domains::authorization::permission::{PipelineAction, SystemPermission};
    use crate::domains::proxy::pipeline::{Pipeline, PipelineError};
    use crate::domains::proxy::stages::stage::{
        RateLimitConfig, RateLimitKey, StageConfig, StageKind, StageRemoval,
    };
    use crate::domains::routing::control::RoutingControl;
    use crate::domains::routing::fixtures::holding;
    use crate::isolation::scope::ResolvedTenant;
    use crate::test_support::events::raised_names;
    use crate::types::{Label, Seconds, StageId};

    /// Ann, who may manage pipelines.
    fn person() -> RoutingControl<'static> {
        holding(&[SystemPermission::Pipeline(PipelineAction::Manage)])
    }

    /// Sam, who holds no pipeline right.
    fn viewer() -> RoutingControl<'static> {
        holding(&[])
    }

    /// A rate limit of `max_requests` a minute per user.
    fn rate_limit(max_requests: u32) -> StageKind {
        StageKind::RateLimit(RateLimitConfig {
            max_requests,
            window_seconds: Seconds::new(60),
            key_by: RateLimitKey::UserId,
        })
    }

    /// A draft pipeline with a rate limit of 100, and the rate limit's id.
    fn with_rate_limit() -> (Pipeline<ResolvedTenant>, StageId) {
        let mut pipeline =
            Pipeline::with_defaults(Label::new("name", "edge").unwrap(), &person()).unwrap();
        let stage = StageConfig::new(rate_limit(100), 0, StageRemoval::Allowed).unwrap();
        let id = *stage.id();
        pipeline.add_stage(stage, &person()).unwrap();
        raised_names(&mut pipeline);
        (pipeline, id)
    }

    /// What the stage `id` of `pipeline` is set up as now.
    fn kind_of(pipeline: &Pipeline<ResolvedTenant>, id: &StageId) -> StageKind {
        pipeline
            .stages()
            .iter()
            .find(|stage| stage.id() == id)
            .unwrap()
            .kind()
            .clone()
    }

    /// Ann raises the rate limit to 500 requests a minute. The stage carries
    /// the new limit and one `proxy.stage_reconfigured` is raised.
    #[test]
    fn a_stages_settings_change_in_place() {
        let (mut pipeline, id) = with_rate_limit();

        pipeline
            .reconfigure_stage(&id, rate_limit(500), &person())
            .unwrap();

        assert_eq!(kind_of(&pipeline, &id), rate_limit(500));
        assert_eq!(raised_names(&mut pipeline), ["proxy.stage_reconfigured"]);
    }

    /// A caller with no pipeline-management permission cannot raise a stage's
    /// rate limit. The refusal preserves its original limit.
    #[test]
    fn changing_a_stages_settings_needs_the_pipeline_right() {
        let (mut pipeline, id) = with_rate_limit();

        let changed = pipeline.reconfigure_stage(&id, rate_limit(1_000_000), &viewer());

        assert_eq!(changed, Err(PipelineError::NotAllowed));
        assert_eq!(kind_of(&pipeline, &id), rate_limit(100));
    }

    /// Reconfiguring a rate-limit stage as MCP is refused because the new
    /// settings name a different stage kind.
    #[test]
    fn a_stage_keeps_its_kind() {
        let (mut pipeline, id) = with_rate_limit();

        let changed = pipeline.reconfigure_stage(&id, StageKind::Mcp, &person());

        assert_eq!(changed, Err(PipelineError::OtherKind));
    }

    /// Ann sets the rate limit to zero requests, which would block every
    /// caller. It is refused.
    #[test]
    fn settings_a_stage_could_not_work_with_are_refused() {
        let (mut pipeline, id) = with_rate_limit();

        let changed = pipeline.reconfigure_stage(&id, rate_limit(0), &person());

        assert!(matches!(changed, Err(PipelineError::SettingsRefused(_))));
        assert_eq!(kind_of(&pipeline, &id), rate_limit(100));
    }

    /// Identity has no settings to change. Reconfiguring it is refused.
    #[test]
    fn the_identity_stage_is_not_reconfigured() {
        let (mut pipeline, _) = with_rate_limit();
        let identity = *pipeline.stages_in_order()[0].id();

        let changed = pipeline.reconfigure_stage(&identity, StageKind::Identity, &person());

        assert_eq!(changed, Err(PipelineError::CannotReconfigureMandatory));
    }

    /// The pipeline is on. Changing a stage is refused until it is off.
    #[test]
    fn a_running_pipeline_is_not_reconfigured() {
        let (mut pipeline, id) = with_rate_limit();
        pipeline.activate(&[], &person()).unwrap();

        let changed = pipeline.reconfigure_stage(&id, rate_limit(500), &person());

        assert_eq!(changed, Err(PipelineError::ActivePipelineImmutable));
    }

    /// A stage id the pipeline does not hold is not found.
    #[test]
    fn an_unknown_stage_is_not_found() {
        let (mut pipeline, _) = with_rate_limit();

        let changed = pipeline.reconfigure_stage(&StageId::new(), rate_limit(500), &person());

        assert_eq!(changed, Err(PipelineError::StageNotFound));
    }
}
