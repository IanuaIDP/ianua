//! The pipeline aggregate: a tenant's proxy pipeline, built from stages.
//!
//! A tenant holds named pipelines. Each one is the ordered list of stages a
//! request passes through on the routes that name it. The mandatory stages,
//! Identity and Policy, cannot be removed. Tenants add, remove and reorder
//! the others.

use std::marker::PhantomData;

use time::OffsetDateTime;

use crate::domains::proxy::events::{
    PipelineActivated, PipelineCreated, PipelineDeleted, PipelineDisabled, PipelineRenamed,
    StageAdded, StageDisabled, StageEnabled, StageRemoved,
};
use crate::domains::proxy::pipeline_status::PipelineStatus;
use crate::domains::proxy::stages::stage::{MandatoryStage, StageConfig};
use crate::domains::routing::control::{RoutingControl, RoutingRight};
use crate::domains::routing::route::{ResponseSharing, Route, RoutePipeline};
use crate::isolation::scope::TenantScope;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{Raised, Raises, SavedFor};
use crate::shared::model::row_check::RowCheck;
use crate::shared::validation::distinct::first_repeat;
use crate::types::{Label, PipelineId, StageId};

mod body;
mod error;
mod order;
mod preflight;
mod response;
mod settings;
mod watch;

pub use error::*;
pub use preflight::PreflightRule;
pub use response::{UpgradeRefusal, UpgradeRule};

/// A stored pipeline, as [`Pipeline::reconstitute`] reads it.
pub struct PipelineRow {
    /// The pipeline's id.
    pub id: PipelineId,
    /// What a route names it by, unique within the tenant.
    pub name: Label,
    /// Current pipeline status.
    pub status: PipelineStatus,
    /// Every stage as stored, in no particular order.
    pub stages: Vec<StageConfig>,
    /// When this pipeline was created.
    pub created_at: OffsetDateTime,
    /// When this pipeline was last modified.
    pub updated_at: OffsetDateTime,
}

/// A proxy pipeline of a tenant.
///
/// An ordered list of stages that every request on its routes passes through.
/// Tenants cannot remove or disable the mandatory stages. They can add,
/// reorder, enable, disable and remove the others.
///
/// Mutations are only allowed when the pipeline is `Draft` or `Disabled`.
/// An `Active` pipeline must be disabled before reconfiguration.
///
/// Only a person makes or changes a pipeline. Sam's agent may manage
/// routing. Without this rule, it removes the rate limit and geofence in
/// front of the payments API and calls it as often as it likes.
#[derive(Debug, Clone)]
pub struct Pipeline<T: TenantScope> {
    id: PipelineId,
    name: Label,
    status: PipelineStatus,
    stages: Vec<StageConfig>,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
    raised: Raised<T>,
    _scope: PhantomData<T>,
}

impl<T: TenantScope> Pipeline<T> {
    /// Creates a new pipeline with platform-mandatory stages, on behalf of
    /// `by`. Raises `proxy.pipeline_created`.
    ///
    /// Starts `Draft`, so it refuses traffic until somebody configures it.
    /// A new pipeline that served at once would run a route through Identity
    /// and Policy and nothing else.
    ///
    /// # Errors
    ///
    /// - [`PipelineError::NotAllowed`] when `by` may not change pipelines.
    pub fn with_defaults(name: Label, by: &RoutingControl<'_>) -> Result<Self, PipelineError> {
        ensure_may(by, RoutingRight::CreatePipeline)?;
        let now = crate::shared::clock::now();
        let mut pipeline = Self {
            id: PipelineId::new(),
            name,
            status: PipelineStatus::Draft,
            stages: vec![
                StageConfig::locked(MandatoryStage::Identity),
                StageConfig::locked(MandatoryStage::Policy),
            ],
            created_at: now,
            updated_at: now,
            raised: Raised::default(),
            _scope: PhantomData,
        };
        pipeline.raised.raise(PipelineCreated {
            pipeline_id: pipeline.id,
            occurred_at: now,
        });
        Ok(pipeline)
    }

    /// Rebuilds a pipeline from storage.
    ///
    /// A tampered or stale row could skip authentication or authorization,
    /// or judge traffic before it knows who sent it. Such a row is refused.
    /// The routes using it then deny traffic instead of running a pipeline
    /// nobody configured.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the row lacks the Identity or
    ///   Policy stage, or holds one twice or disabled.
    /// - [`DomainError::Infrastructure`] when it runs anything before them,
    ///   or Policy before Identity.
    /// - [`DomainError::Infrastructure`] when it gives two stages one
    ///   position, or holds one stage id twice.
    /// - [`DomainError::Infrastructure`] when it changed before it was
    ///   created.
    pub fn reconstitute(row: PipelineRow) -> Result<Self, DomainError> {
        Self::ensure_consistent(&row)?;
        Ok(Self {
            id: row.id,
            name: row.name,
            status: row.status,
            stages: row.stages,
            created_at: row.created_at,
            updated_at: row.updated_at,
            raised: Raised::default(),
            _scope: PhantomData,
        })
    }

    /// Refuses a stored row that breaks a rule this keeps.
    fn ensure_consistent(row: &PipelineRow) -> Result<(), DomainError> {
        RowCheck::of("pipeline")
            .holds(
                mandatory_stages_in_force(&row.stages),
                "an Identity or Policy stage missing, doubled or disabled",
            )
            .holds(
                runs_mandatory_first(&row.stages),
                "a stage running before Identity and Policy, or Policy before Identity",
            )
            .holds(
                first_repeat(row.stages.iter().map(StageConfig::position)).is_none(),
                "two stages at one position",
            )
            .holds(
                first_repeat(row.stages.iter().map(StageConfig::id)).is_none(),
                "one stage id held twice",
            )
            .in_order(
                row.created_at,
                row.updated_at,
                "changed before it was created",
            )
            .finish()
    }

    /// The pipeline's id.
    #[must_use]
    pub fn id(&self) -> &PipelineId {
        &self.id
    }

    /// What a route names it by.
    #[must_use]
    pub fn name(&self) -> &Label {
        &self.name
    }

    /// Renames the pipeline. Raises `proxy.pipeline_renamed` with the name
    /// before and after.
    ///
    /// # Errors
    ///
    /// - [`PipelineError::NotAllowed`] when `by` may not change pipelines.
    pub fn rename(&mut self, name: Label, by: &RoutingControl<'_>) -> Result<(), PipelineError> {
        ensure_may(by, RoutingRight::ChangePipeline)?;
        let previous_name = std::mem::replace(&mut self.name, name);
        self.touch();
        self.raised.raise(PipelineRenamed {
            pipeline_id: self.id,
            previous_name,
            current_name: self.name.clone(),
            occurred_at: self.updated_at,
        });
        Ok(())
    }

    /// Current pipeline status.
    #[must_use]
    pub fn status(&self) -> PipelineStatus {
        self.status
    }

    /// Every stage as stored, in no particular order.
    ///
    /// Storage order is not run order. Position is. Use
    /// [`stages_in_order`](Self::stages_in_order) to show an operator the
    /// sequence the pipeline runs.
    #[must_use]
    pub fn stages(&self) -> &[StageConfig] {
        &self.stages
    }

    /// Every stage, enabled or not, in the order they run.
    ///
    /// A disabled stage keeps its place. It is skipped, not removed, and an
    /// operator reordering the pipeline needs to see where it sits.
    #[must_use]
    pub fn stages_in_order(&self) -> Vec<&StageConfig> {
        let mut ordered: Vec<_> = self.stages.iter().collect();
        ordered.sort_by_key(|s| s.position());
        ordered
    }

    /// Only enabled stages, in the order they run.
    #[must_use]
    pub fn active_stages(&self) -> Vec<&StageConfig> {
        let mut active: Vec<_> = self.stages.iter().filter(|s| s.enabled()).collect();
        active.sort_by_key(|s| s.position());
        active
    }

    /// The enabled stages that decide before the request is forwarded, in
    /// the order they run.
    ///
    /// A stage that only acts on the upstream's answer is left out: it runs
    /// in the response chain, which
    /// [`response_stages`](Self::response_stages) orders. A stage that runs
    /// both ways is in both lists.
    #[must_use]
    pub fn request_stages(&self) -> Vec<&StageConfig> {
        self.active_stages()
            .into_iter()
            .filter(|stage| stage.kind().phase().runs_on_request())
            .collect()
    }

    /// When this pipeline was created.
    #[must_use]
    pub fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    /// When this pipeline was last modified.
    #[must_use]
    pub fn updated_at(&self) -> OffsetDateTime {
        self.updated_at
    }

    /// Activates the pipeline, so it runs on traffic. Raises
    /// `proxy.pipeline_activated`, so every proxy reloads it.
    ///
    /// Stages change only while the pipeline is off, and its routes are
    /// refused then. So turning it on is where its stages first meet live
    /// traffic, and where they are held to the routes that run it.
    ///
    /// `routes` are every route that runs this pipeline, as stored, and each
    /// must work with its stages. The caller passes all of them: the check
    /// sees only what it is given. A route of another pipeline is refused,
    /// so an unrelated list cannot stand in for this pipeline's own.
    ///
    /// # Errors
    ///
    /// - [`PipelineError::NotAllowed`] when `by` may not change pipelines.
    /// - [`PipelineError::ForeignRoute`] if a route in `routes` runs on
    ///   another pipeline.
    /// - [`PipelineError::SharedCacheOnSignedInRoute`] if a stage shares
    ///   cached responses between callers and a route naming this pipeline
    ///   needs sign-in.
    /// - [`PipelineError::InvalidTransition`] if the pipeline is already
    ///   `Active`.
    pub fn activate(
        &mut self,
        routes: &[Route<T>],
        by: &RoutingControl<'_>,
    ) -> Result<(), PipelineError> {
        ensure_may(by, RoutingRight::ChangePipeline)?;
        self.ensure_its_own(routes)?;
        routes
            .iter()
            .try_for_each(|route| route.ensure_runs_on(self))
            .map_err(|_| PipelineError::SharedCacheOnSignedInRoute)?;
        self.status = self
            .status
            .try_transition(PipelineStatus::Active)
            .map_err(PipelineError::InvalidTransition)?;
        self.touch();
        self.raised.raise(PipelineActivated {
            pipeline_id: self.id,
            occurred_at: self.updated_at,
        });
        Ok(())
    }

    /// Disables the pipeline. Traffic on its routes is then denied. Raises
    /// `proxy.pipeline_disabled`, so every proxy stops running it.
    ///
    /// # Errors
    ///
    /// - [`PipelineError::NotAllowed`] when `by` may not change pipelines.
    /// - [`PipelineError::InvalidTransition`] if the pipeline is not
    ///   `Active`.
    pub fn disable(&mut self, by: &RoutingControl<'_>) -> Result<(), PipelineError> {
        ensure_may(by, RoutingRight::ChangePipeline)?;
        self.status = self
            .status
            .try_transition(PipelineStatus::Disabled)
            .map_err(PipelineError::InvalidTransition)?;
        self.touch();
        self.raised.raise(PipelineDisabled {
            pipeline_id: self.id,
            occurred_at: self.updated_at,
        });
        Ok(())
    }

    /// Deletes this pipeline, once `by` may manage pipelines and no route
    /// runs it. Raises `proxy.pipeline_deleted`, taken once the pipeline is
    /// removed from storage.
    ///
    /// `routes` are every route that runs this pipeline, as stored. The
    /// caller passes all of them. Deleting a pipeline a route still runs
    /// would leave that route with nothing to run, or move it to another
    /// pipeline nobody chose.
    ///
    /// # Errors
    ///
    /// - [`PipelineError::NotAllowed`] when `by` may not manage pipelines.
    /// - [`PipelineError::ForeignRoute`] if a route in `routes` runs on
    ///   another pipeline.
    /// - [`PipelineError::InUse`] if a route still runs this pipeline.
    pub fn delete(
        &mut self,
        routes: &[Route<T>],
        by: &RoutingControl<'_>,
    ) -> Result<(), PipelineError> {
        ensure_may(by, RoutingRight::DeletePipeline)?;
        self.ensure_its_own(routes)?;
        if !routes.is_empty() {
            return Err(PipelineError::InUse);
        }
        self.raised.raise(PipelineDeleted {
            pipeline_id: self.id,
            occurred_at: crate::shared::clock::now(),
        });
        Ok(())
    }

    /// Refuses `routes` unless every one runs this pipeline.
    fn ensure_its_own(&self, routes: &[Route<T>]) -> Result<(), PipelineError> {
        if routes.iter().any(|route| *route.pipeline_id() != self.id) {
            return Err(PipelineError::ForeignRoute);
        }
        Ok(())
    }

    /// Refuses a change by anyone but a person, or to a pipeline that is
    /// running.
    fn require_mutable(&self, by: &RoutingControl<'_>) -> Result<(), PipelineError> {
        ensure_may(by, RoutingRight::ChangePipeline)?;
        if !self.status.allows_mutation() {
            return Err(PipelineError::ActivePipelineImmutable);
        }
        Ok(())
    }

    /// Adds a new stage at the end of the pipeline. Raises
    /// `proxy.stage_added` with the position the stage took.
    ///
    /// The stage's own position is overwritten. Only the pipeline knows what
    /// is already in it, so it places the stage. A caller choosing a number
    /// could put a filter ahead of Identity, where it judges traffic before
    /// anyone knows who sent it. Reorder afterwards to move it.
    ///
    /// # Errors
    ///
    /// - [`PipelineError::NotAllowed`] when `by` may not change pipelines.
    /// - [`PipelineError::ActivePipelineImmutable`] if the pipeline is active.
    /// - [`PipelineError::CannotAddMandatory`] for an Identity or Policy
    ///   stage.
    pub fn add_stage(
        &mut self,
        mut stage: StageConfig,
        by: &RoutingControl<'_>,
    ) -> Result<(), PipelineError> {
        self.require_mutable(by)?;
        if stage.mandatory() {
            return Err(PipelineError::CannotAddMandatory);
        }
        stage.move_to(self.next_position());
        let (stage_id, stage_kind, position) = (*stage.id(), stage.kind().name(), stage.position());
        self.stages.push(stage);
        self.touch();
        self.raised.raise(StageAdded {
            pipeline_id: self.id,
            stage_id,
            stage_kind,
            position,
            occurred_at: self.updated_at,
        });
        Ok(())
    }

    /// Where the next stage goes: after everything already here.
    ///
    /// The pipeline decides this, not the caller. A position only means
    /// something next to the other stages, so a client picking a number has
    /// to know all of them. One that guesses wrong can put filtering in front
    /// of Identity, where traffic is judged before anyone knows who sent it.
    ///
    /// Appending is the only placement that is right without being told. A
    /// new stage has no tie to the others, and the operator reorders it into
    /// place afterwards.
    fn next_position(&self) -> u16 {
        self.stages
            .iter()
            .map(StageConfig::position)
            .max()
            .map_or(0, |highest| highest.saturating_add(1))
    }

    /// Removes a non-mandatory stage by ID. Raises `proxy.stage_removed`.
    ///
    /// # Errors
    ///
    /// - [`PipelineError::NotAllowed`] when `by` may not change pipelines.
    /// - [`PipelineError::ActivePipelineImmutable`] if the pipeline is active.
    /// - [`PipelineError::StageNotFound`] if the stage doesn't exist.
    /// - [`PipelineError::CannotRemoveMandatory`] if the stage is mandatory.
    pub fn remove_stage(
        &mut self,
        stage_id: &StageId,
        by: &RoutingControl<'_>,
    ) -> Result<(), PipelineError> {
        self.require_mutable(by)?;
        let (pos, stage) = self
            .stages
            .iter()
            .enumerate()
            .find(|(_, s)| s.id() == stage_id)
            .ok_or(PipelineError::StageNotFound)?;

        if stage.mandatory() {
            return Err(PipelineError::CannotRemoveMandatory);
        }

        self.stages.remove(pos);
        self.touch();
        self.raised.raise(StageRemoved {
            pipeline_id: self.id,
            stage_id: *stage_id,
            occurred_at: self.updated_at,
        });
        Ok(())
    }

    /// Enables a stage by ID. Raises `proxy.stage_enabled`.
    ///
    /// # Errors
    ///
    /// - [`PipelineError::NotAllowed`] when `by` may not change pipelines.
    /// - [`PipelineError::ActivePipelineImmutable`] if the pipeline is active.
    /// - [`PipelineError::StageNotFound`] if the stage doesn't exist.
    pub fn enable_stage(
        &mut self,
        stage_id: &StageId,
        by: &RoutingControl<'_>,
    ) -> Result<(), PipelineError> {
        self.require_mutable(by)?;
        let stage = self
            .stages
            .iter_mut()
            .find(|s| s.id() == stage_id)
            .ok_or(PipelineError::StageNotFound)?;
        stage.enable();
        self.touch();
        self.raised.raise(StageEnabled {
            pipeline_id: self.id,
            stage_id: *stage_id,
            occurred_at: self.updated_at,
        });
        Ok(())
    }

    /// Disables a non-mandatory stage by ID. Raises `proxy.stage_disabled`.
    ///
    /// # Errors
    ///
    /// - [`PipelineError::NotAllowed`] when `by` may not change pipelines.
    /// - [`PipelineError::ActivePipelineImmutable`] if the pipeline is active.
    /// - [`PipelineError::StageNotFound`] if the stage doesn't exist.
    /// - [`PipelineError::CannotRemoveMandatory`] if the stage is mandatory.
    pub fn disable_stage(
        &mut self,
        stage_id: &StageId,
        by: &RoutingControl<'_>,
    ) -> Result<(), PipelineError> {
        self.require_mutable(by)?;
        let stage = self
            .stages
            .iter_mut()
            .find(|s| s.id() == stage_id)
            .ok_or(PipelineError::StageNotFound)?;

        if stage.mandatory() {
            return Err(PipelineError::CannotRemoveMandatory);
        }

        stage.disable();
        self.touch();
        self.raised.raise(StageDisabled {
            pipeline_id: self.id,
            stage_id: *stage_id,
            occurred_at: self.updated_at,
        });
        Ok(())
    }

    /// Sets `updated_at` to now.
    fn touch(&mut self) {
        self.updated_at = crate::shared::clock::now();
    }
}

impl<T: TenantScope> Raises for Pipeline<T> {
    fn take_events(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent> {
        self.raised.take(saved_for)
    }
}

impl<T: TenantScope> crate::domains::routing::sealed::Sealed for Pipeline<T> {}

impl<T: TenantScope> RoutePipeline for Pipeline<T> {
    fn pipeline_id(&self) -> PipelineId {
        self.id
    }

    /// Shared when any stage, on or off, keeps one cached response for every
    /// caller.
    ///
    /// A switched-off stage counts too. Turning it back on needs no look at
    /// the routes, so it must already fit them.
    fn response_sharing(&self) -> ResponseSharing {
        if self
            .stages
            .iter()
            .any(|stage| stage.kind().shares_cached_responses())
        {
            return ResponseSharing::Shared;
        }
        ResponseSharing::PerCaller
    }
}

/// Refuses `by` making or changing a pipeline without the `right` for it.
/// Only a person signed in to the tenant holds one, so an agent never
/// changes a pipeline.
fn ensure_may(by: &RoutingControl<'_>, right: RoutingRight) -> Result<(), PipelineError> {
    by.ensure_may(right).map_err(|_| PipelineError::NotAllowed)
}

/// Whether stored stages hold Identity and Policy once each, enabled.
fn mandatory_stages_in_force(stages: &[StageConfig]) -> bool {
    [MandatoryStage::Identity, MandatoryStage::Policy]
        .into_iter()
        .all(|mandatory| {
            let mut found = stages.iter().filter(|stage| mandatory.is(stage.kind()));
            found.next().is_some_and(StageConfig::enabled) && found.next().is_none()
        })
}

/// Whether stored stages, read in position order, run Identity, then
/// Policy, then everything else. Every mutator keeps that order. A row that
/// breaks it would have traffic judged before anyone knows who sent it.
fn runs_mandatory_first(stages: &[StageConfig]) -> bool {
    let mut by_position: Vec<&StageConfig> = stages.iter().collect();
    by_position.sort_by_key(|stage| stage.position());
    by_position.is_sorted_by_key(|stage| stage.run_rank())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::authorization::permission::{PipelineAction, SystemPermission};
    use crate::domains::proxy::stages::stage::{
        CacheConfig, CacheScope, GeoFenceConfig, RateLimitConfig, RateLimitKey, StageConfigRow,
        StageKind, StageRemoval,
    };
    use crate::domains::routing::fixtures::{holding, route_on};
    use crate::domains::routing::policy::RoutePolicy;
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::model::row_check::refused_as_corrupt;
    use crate::test_support::events::{raised, raised_names};
    use crate::types::Seconds;

    /// Someone who may manage pipelines.
    fn person() -> RoutingControl<'static> {
        holding(&[SystemPermission::Pipeline(PipelineAction::Manage)])
    }

    /// Sam, who may manage routing but not pipelines.
    fn agent() -> RoutingControl<'static> {
        holding(&[SystemPermission::ManageRouting])
    }

    /// A cache stage that keeps one response for every caller.
    fn shared_cache_stage() -> StageConfig {
        StageConfig::new(
            StageKind::Cache(CacheConfig {
                ttl_seconds: Seconds::new(60),
                vary_by_user: CacheScope::Shared,
            }),
            0,
            StageRemoval::Allowed,
        )
        .unwrap()
    }

    fn with_defaults() -> Pipeline<ResolvedTenant> {
        Pipeline::with_defaults(Label::new("pipeline_name", "Default").unwrap(), &person()).unwrap()
    }

    /// Routing permission alone cannot disable, edit, reorder or activate
    /// the pipeline. After an authorized disable, the pipeline remains
    /// disabled with all three stages still enabled.
    #[test]
    fn only_the_pipeline_right_takes_a_stage_off_a_pipeline() {
        let (mut pipeline, geo_id) = drafted_with_geofence();
        pipeline.activate(&[], &person()).unwrap();

        let disabled = pipeline.disable(&agent());
        pipeline.disable(&person()).unwrap();
        let removed = pipeline.remove_stage(&geo_id, &agent());
        let switched_off = pipeline.disable_stage(&geo_id, &agent());
        let order: Vec<StageId> = pipeline.stages_in_order().iter().map(|s| *s.id()).collect();
        let reordered = pipeline.reorder_stages(&order, &agent());
        let activated = pipeline.activate(&[], &agent());

        for result in [disabled, removed, switched_off, reordered, activated] {
            assert_eq!(result, Err(PipelineError::NotAllowed));
        }
        assert_eq!(pipeline.active_stages().len(), 3);
        assert_eq!(pipeline.status(), PipelineStatus::Disabled);
    }

    /// Creating a default pipeline with routing permission alone returns
    /// `NotAllowed`.
    #[test]
    fn only_the_pipeline_right_makes_a_pipeline() {
        let made = Pipeline::<ResolvedTenant>::with_defaults(
            Label::new("pipeline_name", "Open").unwrap(),
            &agent(),
        );

        assert!(matches!(made, Err(PipelineError::NotAllowed)));
    }

    /// A new pipeline starts in draft, so it serves nothing yet. It holds
    /// only Identity, then Policy.
    #[test]
    fn default_pipeline_starts_in_draft() {
        let pipeline = with_defaults();
        assert_eq!(pipeline.status(), PipelineStatus::Draft);
        assert_eq!(pipeline.stages().len(), 2);
        assert!(matches!(pipeline.stages()[0].kind(), StageKind::Identity));
        assert!(matches!(pipeline.stages()[1].kind(), StageKind::Policy));
    }

    /// A geofence blocking North Korea is added to a draft pipeline, which
    /// then has three stages.
    #[test]
    fn add_stage_in_draft() {
        let mut pipeline = with_defaults();
        let geo = StageConfig::new(
            StageKind::GeoFence(GeoFenceConfig {
                allowed_countries: vec![],
                blocked_countries: vec![crate::types::CountryCode::new("KP").unwrap()],
            }),
            50,
            StageRemoval::Allowed,
        )
        .unwrap();

        pipeline.add_stage(geo, &person()).unwrap();
        assert_eq!(pipeline.stages().len(), 3);
    }

    /// A geofence requesting position 50 is appended after Identity and
    /// Policy, preserving their mandatory order.
    #[test]
    fn a_new_stage_goes_after_the_mandatory_ones() {
        let mut pipeline = with_defaults();

        let geo = StageConfig::new(
            StageKind::GeoFence(GeoFenceConfig {
                allowed_countries: vec![],
                blocked_countries: vec![crate::types::CountryCode::new("KP").unwrap()],
            }),
            50,
            StageRemoval::Allowed,
        )
        .unwrap();

        pipeline.add_stage(geo, &person()).unwrap();

        let ordered = pipeline.stages_in_order();
        assert!(
            matches!(ordered[0].kind(), StageKind::Identity),
            "a stage placed ahead of Identity filters traffic before anything \
             has worked out who sent it"
        );
        assert!(matches!(ordered[1].kind(), StageKind::Policy));
        assert!(matches!(ordered[2].kind(), StageKind::GeoFence(_)));
    }

    /// Three stages all asking for position 0 are added. Each gets its own
    /// position, so the run order never depends on how a sort breaks a tie.
    #[test]
    fn no_two_stages_share_a_position() {
        let mut pipeline = with_defaults();

        for _ in 0..3 {
            let stage = StageConfig::new(
                StageKind::GeoFence(GeoFenceConfig {
                    allowed_countries: vec![],
                    blocked_countries: vec![crate::types::CountryCode::new("KP").unwrap()],
                }),
                0,
                StageRemoval::Allowed,
            )
            .unwrap();
            pipeline.add_stage(stage, &person()).unwrap();
        }

        let mut positions: Vec<u16> = pipeline
            .stages()
            .iter()
            .map(crate::domains::proxy::stages::stage::StageConfig::position)
            .collect();
        let before = positions.len();
        positions.sort_unstable();
        positions.dedup();

        assert_eq!(
            positions.len(),
            before,
            "two stages sharing a position leave the run order to however the \
             sort breaks the tie"
        );
    }

    /// After a reorder renumbers the stages from zero, a new rate limit still
    /// lands last and Identity stays first.
    #[test]
    fn adding_after_a_reorder_still_appends() {
        let mut pipeline = with_defaults();
        let geo = StageConfig::new(
            StageKind::GeoFence(GeoFenceConfig {
                allowed_countries: vec![],
                blocked_countries: vec![crate::types::CountryCode::new("KP").unwrap()],
            }),
            0,
            StageRemoval::Allowed,
        )
        .unwrap();
        pipeline.add_stage(geo, &person()).unwrap();

        let order: Vec<StageId> = pipeline.stages_in_order().iter().map(|s| *s.id()).collect();
        pipeline.reorder_stages(&order, &person()).unwrap();

        let rate_limit = StageConfig::new(rate_limit(), 0, StageRemoval::Allowed).unwrap();
        pipeline.add_stage(rate_limit, &person()).unwrap();

        let ordered = pipeline.stages_in_order();
        assert!(
            matches!(ordered[0].kind(), StageKind::Identity),
            "Identity has to stay first after a reorder followed by an add"
        );
        assert!(matches!(
            ordered.last().unwrap().kind(),
            StageKind::RateLimit(_)
        ));
    }

    /// Adding a stage to a live pipeline is refused. It must be disabled
    /// first.
    #[test]
    fn cannot_add_stage_when_active() {
        let mut pipeline = with_defaults();
        pipeline.activate(&[], &person()).unwrap();

        let geo = StageConfig::new(
            StageKind::GeoFence(GeoFenceConfig {
                allowed_countries: vec![],
                blocked_countries: vec![crate::types::CountryCode::new("KP").unwrap()],
            }),
            50,
            StageRemoval::Allowed,
        )
        .unwrap();

        let result = pipeline.add_stage(geo, &person());
        assert_eq!(result, Err(PipelineError::ActivePipelineImmutable));
    }

    /// A pipeline that was live and is now disabled accepts a new stage.
    #[test]
    fn can_add_stage_after_disable() {
        let mut pipeline = with_defaults();
        pipeline.activate(&[], &person()).unwrap();
        pipeline.disable(&person()).unwrap();

        let geo = StageConfig::new(
            StageKind::GeoFence(GeoFenceConfig {
                allowed_countries: vec![],
                blocked_countries: vec![crate::types::CountryCode::new("KP").unwrap()],
            }),
            50,
            StageRemoval::Allowed,
        )
        .unwrap();

        pipeline.add_stage(geo, &person()).unwrap();
        assert_eq!(pipeline.stages().len(), 3);
    }

    /// A rate limit the tenant added can be removed again, leaving Identity
    /// and Policy.
    #[test]
    fn remove_non_mandatory_stage() {
        let mut pipeline = with_defaults();
        let rate = StageConfig::new(
            StageKind::RateLimit(RateLimitConfig {
                max_requests: 100,
                window_seconds: Seconds::new(60),
                key_by: RateLimitKey::UserId,
            }),
            150,
            StageRemoval::Allowed,
        )
        .unwrap();
        let rate_id = *rate.id();

        pipeline.add_stage(rate, &person()).unwrap();
        assert_eq!(pipeline.stages().len(), 3);

        pipeline.remove_stage(&rate_id, &person()).unwrap();
        assert_eq!(pipeline.stages().len(), 2);
    }

    /// Removing the default Identity stage returns `CannotRemoveMandatory`
    /// even with pipeline-management permission.
    #[test]
    fn cannot_remove_mandatory_stage() {
        let mut pipeline = with_defaults();
        let identity_id = *pipeline.stages()[0].id();

        let result = pipeline.remove_stage(&identity_id, &person());
        assert_eq!(result, Err(PipelineError::CannotRemoveMandatory));
    }

    /// Disabling the default Policy stage returns `CannotRemoveMandatory`
    /// even with pipeline-management permission.
    #[test]
    fn cannot_disable_mandatory_stage() {
        let mut pipeline = with_defaults();
        let policy_id = *pipeline.stages()[1].id();

        let result = pipeline.disable_stage(&policy_id, &person());
        assert_eq!(result, Err(PipelineError::CannotRemoveMandatory));
    }

    /// On a live pipeline, removing, disabling and reordering are all
    /// refused as changes to an active pipeline, before any other check.
    #[test]
    fn cannot_mutate_active_pipeline() {
        let mut pipeline = with_defaults();
        pipeline.activate(&[], &person()).unwrap();
        let identity_id = *pipeline.stages()[0].id();

        assert_eq!(
            pipeline.remove_stage(&identity_id, &person()),
            Err(PipelineError::ActivePipelineImmutable)
        );
        assert_eq!(
            pipeline.disable_stage(&identity_id, &person()),
            Err(PipelineError::ActivePipelineImmutable)
        );
        assert_eq!(
            pipeline.reorder_stages(&[identity_id], &person()),
            Err(PipelineError::ActivePipelineImmutable)
        );
    }

    /// A pipeline goes live, is disabled for an edit, and goes live again.
    #[test]
    fn activate_then_disable_then_reactivate() {
        let mut pipeline = with_defaults();

        pipeline.activate(&[], &person()).unwrap();
        assert_eq!(pipeline.status(), PipelineStatus::Active);

        pipeline.disable(&person()).unwrap();
        assert_eq!(pipeline.status(), PipelineStatus::Disabled);

        pipeline.activate(&[], &person()).unwrap();
        assert_eq!(pipeline.status(), PipelineStatus::Active);
    }

    /// Activating a pipeline that is already live is refused.
    #[test]
    fn cannot_activate_already_active() {
        let mut pipeline = with_defaults();
        pipeline.activate(&[], &person()).unwrap();

        assert!(pipeline.activate(&[], &person()).is_err());
    }

    /// Disabling a draft that was never live is refused.
    #[test]
    fn cannot_disable_draft() {
        let mut pipeline = with_defaults();
        assert!(pipeline.disable(&person()).is_err());
    }

    /// A rate limit asking for position 50 is appended, so the active stages
    /// run in position order with Identity first. Once the rate limit is
    /// disabled, it drops out of the active list.
    #[test]
    fn active_stages_returns_sorted_enabled_only() {
        let mut pipeline = with_defaults();
        let rate = StageConfig::new(
            StageKind::RateLimit(RateLimitConfig {
                max_requests: 100,
                window_seconds: Seconds::new(60),
                key_by: RateLimitKey::IpAddress,
            }),
            50,
            StageRemoval::Allowed,
        )
        .unwrap();
        let rate_id = *rate.id();
        pipeline.add_stage(rate, &person()).unwrap();

        let active = pipeline.active_stages();
        assert_eq!(active.len(), 3);

        let positions: Vec<u16> = active.iter().map(|s| s.position()).collect();
        let mut sorted = positions.clone();
        sorted.sort_unstable();
        assert_eq!(positions, sorted, "stages run in ascending position order");

        assert!(matches!(active[0].kind(), StageKind::Identity));

        pipeline.disable_stage(&rate_id, &person()).unwrap();
        assert_eq!(pipeline.active_stages().len(), 2);
    }

    /// A response transform acts only on the upstream's answer, so the
    /// chain run before forwarding leaves it out and keeps Identity and
    /// Policy in their order.
    #[test]
    fn request_stages_leave_out_what_acts_only_on_the_answer() {
        let mut pipeline = with_defaults();
        let transform = StageConfig::new(
            StageKind::ResponseTransform(
                crate::domains::proxy::request::transform::ResponseMutation::default(),
            ),
            50,
            StageRemoval::Allowed,
        )
        .unwrap();
        pipeline.add_stage(transform, &person()).unwrap();

        let request = pipeline.request_stages();

        assert_eq!(pipeline.active_stages().len(), 3);
        assert_eq!(request.len(), 2);
        assert!(matches!(request[0].kind(), StageKind::Identity));
        assert!(matches!(request[1].kind(), StageKind::Policy));
    }

    /// A pipeline in draft with Identity, Policy and a geo-fence stage.
    fn drafted_with_geofence() -> (Pipeline<ResolvedTenant>, StageId) {
        let mut pipeline = with_defaults();
        let geo = StageConfig::new(
            StageKind::GeoFence(GeoFenceConfig {
                allowed_countries: vec![],
                blocked_countries: vec![crate::types::CountryCode::new("KP").unwrap()],
            }),
            300,
            StageRemoval::Allowed,
        )
        .unwrap();
        let geo_id = *geo.id();
        pipeline.add_stage(geo, &person()).unwrap();
        (pipeline, geo_id)
    }

    fn stage_ids(pipeline: &Pipeline<ResolvedTenant>) -> Vec<StageId> {
        pipeline.stages().iter().map(|s| *s.id()).collect()
    }

    /// Requesting the geofence first in a reorder still places Identity
    /// and Policy first, followed by that geofence.
    #[test]
    fn identity_and_policy_stay_first_whatever_the_order_asks() {
        let (mut pipeline, geo_id) = drafted_with_geofence();
        let mut order = stage_ids(&pipeline);
        order.retain(|id| id != &geo_id);
        order.insert(0, geo_id);

        pipeline.reorder_stages(&order, &person()).unwrap();

        let active = pipeline.active_stages();
        assert!(matches!(active[0].kind(), StageKind::Identity));
        assert!(matches!(active[1].kind(), StageKind::Policy));
        assert_eq!(
            *active[2].id(),
            geo_id,
            "the geo-fence runs right after them"
        );
    }

    /// After a reorder, every stage has its own position, taken from its
    /// place in the sequence.
    #[test]
    fn reorder_leaves_no_two_stages_on_one_position() {
        let (mut pipeline, _) = drafted_with_geofence();
        let order = stage_ids(&pipeline);

        pipeline.reorder_stages(&order, &person()).unwrap();

        let positions: Vec<u16> = pipeline
            .stages()
            .iter()
            .map(StageConfig::position)
            .collect();
        let unique: std::collections::HashSet<&u16> = positions.iter().collect();
        assert_eq!(unique.len(), positions.len(), "{positions:?}");
    }

    /// An order naming only the geofence, naming it three times, or naming a
    /// stage from elsewhere is refused. The pipeline is left exactly as it
    /// was.
    #[test]
    fn reorder_refuses_an_order_that_is_not_the_whole_pipeline() {
        let (mut pipeline, geo_id) = drafted_with_geofence();
        let before = stage_ids(&pipeline);

        assert!(matches!(
            pipeline.reorder_stages(&[geo_id], &person()),
            Err(PipelineError::IncompleteOrder)
        ));
        assert!(matches!(
            pipeline.reorder_stages(&[geo_id, geo_id, geo_id], &person()),
            Err(PipelineError::IncompleteOrder)
        ));
        let mut with_a_stranger = before.clone();
        with_a_stranger[0] = StageId::new();
        assert!(matches!(
            pipeline.reorder_stages(&with_a_stranger, &person()),
            Err(PipelineError::IncompleteOrder)
        ));

        assert_eq!(stage_ids(&pipeline), before, "a refusal changes nothing");
    }

    /// A complete, valid order is still refused while the pipeline is live.
    #[test]
    fn reorder_is_refused_on_an_active_pipeline() {
        let (mut pipeline, _) = drafted_with_geofence();
        let order = stage_ids(&pipeline);
        pipeline.activate(&[], &person()).unwrap();

        assert!(matches!(
            pipeline.reorder_stages(&order, &person()),
            Err(PipelineError::ActivePipelineImmutable)
        ));
    }

    fn row_with(stages: Vec<StageConfig>) -> PipelineRow {
        let now = crate::shared::clock::now();
        PipelineRow {
            id: PipelineId::new(),
            name: Label::new("pipeline_name", "Default").unwrap(),
            status: PipelineStatus::Active,
            stages,
            created_at: now,
            updated_at: now,
        }
    }

    /// Reconstituting a pipeline with Policy disabled or absent refuses the
    /// stored row as corrupt.
    #[test]
    fn a_stored_pipeline_without_a_policy_stage_in_force_is_refused() {
        let identity = || StageConfig::new(StageKind::Identity, 100, StageRemoval::Locked).unwrap();
        let mut disabled_policy =
            StageConfig::new(StageKind::Policy, 200, StageRemoval::Locked).unwrap();
        disabled_policy.disable();

        for stages in [vec![identity(), disabled_policy], vec![identity()]] {
            assert!(refused_as_corrupt(
                &Pipeline::<ResolvedTenant>::reconstitute(row_with(stages))
            ));
        }
    }

    /// A stored pipeline with two Policy stages cannot come from this code,
    /// so the row is refused as corrupt.
    #[test]
    fn a_stored_pipeline_with_two_policy_stages_is_refused() {
        let identity = StageConfig::new(StageKind::Identity, 100, StageRemoval::Locked).unwrap();
        let policy = StageConfig::new(StageKind::Policy, 200, StageRemoval::Locked).unwrap();
        let again = StageConfig::new(StageKind::Policy, 300, StageRemoval::Locked).unwrap();

        let stored =
            Pipeline::<ResolvedTenant>::reconstitute(row_with(vec![identity, policy, again]));

        assert!(refused_as_corrupt(&stored));
    }

    fn rate_limit() -> StageKind {
        StageKind::RateLimit(RateLimitConfig {
            max_requests: 100,
            window_seconds: Seconds::new(60),
            key_by: RateLimitKey::UserId,
        })
    }

    /// A locked rate limit is refused, since nobody could ever remove it. An
    /// unlocked Identity stage is refused too, since it could be removed.
    #[test]
    fn only_identity_and_policy_can_be_locked() {
        assert!(StageConfig::new(rate_limit(), 0, StageRemoval::Locked).is_err());
        assert!(StageConfig::new(StageKind::Identity, 0, StageRemoval::Allowed).is_err());
    }

    /// Adding a second Identity stage is refused. It would be a locked stage
    /// the tenant could place but never remove.
    #[test]
    fn identity_and_policy_cannot_be_added_again() {
        let mut pipeline = with_defaults();
        let identity = StageConfig::new(StageKind::Identity, 0, StageRemoval::Locked).unwrap();

        assert_eq!(
            pipeline.add_stage(identity, &person()),
            Err(PipelineError::CannotAddMandatory)
        );
    }

    /// A stored rate limit marked locked is refused as corrupt, so a stored
    /// flag cannot pin a filter in place.
    #[test]
    fn a_stored_lock_on_a_filter_is_refused() {
        let stage = StageConfig::reconstitute(StageConfigRow {
            id: StageId::new(),
            kind: rate_limit(),
            position: 0,
            enabled: crate::types::Enablement::Enabled,
            removal: StageRemoval::Locked,
        });

        assert!(refused_as_corrupt(&stage));
    }

    /// A stored pipeline with a rate limit ahead of Identity, or Policy ahead
    /// of Identity, would judge a caller nobody has identified. Both rows are
    /// refused as corrupt.
    #[test]
    fn a_stored_pipeline_running_anything_before_identity_is_refused() {
        let filter = || StageConfig::new(rate_limit(), 0, StageRemoval::Allowed).unwrap();
        let filter_first = vec![
            filter(),
            StageConfig::new(StageKind::Identity, 100, StageRemoval::Locked).unwrap(),
            StageConfig::new(StageKind::Policy, 200, StageRemoval::Locked).unwrap(),
        ];
        let policy_first = vec![
            StageConfig::new(StageKind::Policy, 0, StageRemoval::Locked).unwrap(),
            StageConfig::new(StageKind::Identity, 1, StageRemoval::Locked).unwrap(),
        ];

        for stages in [filter_first, policy_first] {
            assert!(refused_as_corrupt(
                &Pipeline::<ResolvedTenant>::reconstitute(row_with(stages))
            ));
        }
    }

    /// A stored pipeline of Identity, Policy and a rate limit, in that order,
    /// loads.
    #[test]
    fn a_stored_pipeline_in_order_reads_back() {
        let stages = vec![
            StageConfig::new(StageKind::Identity, 100, StageRemoval::Locked).unwrap(),
            StageConfig::new(StageKind::Policy, 200, StageRemoval::Locked).unwrap(),
            StageConfig::new(rate_limit(), 300, StageRemoval::Allowed).unwrap(),
        ];

        assert!(Pipeline::<ResolvedTenant>::reconstitute(row_with(stages)).is_ok());
    }

    /// A stored pipeline containing two rate-limit stages with the same id
    /// at different positions is refused as corrupt.
    #[test]
    fn a_stored_pipeline_holding_one_stage_id_twice_is_refused() {
        let limit = StageConfig::new(rate_limit(), 300, StageRemoval::Allowed).unwrap();
        let mut copy = limit.clone();
        copy.move_to(400);
        let stages = vec![
            StageConfig::new(StageKind::Identity, 100, StageRemoval::Locked).unwrap(),
            StageConfig::new(StageKind::Policy, 200, StageRemoval::Locked).unwrap(),
            limit,
            copy,
        ];

        assert!(refused_as_corrupt(
            &Pipeline::<ResolvedTenant>::reconstitute(row_with(stages))
        ));
    }

    /// A reorder requesting Policy before Identity succeeds while keeping
    /// Identity first in the resulting order.
    #[test]
    fn a_reorder_cannot_put_policy_before_identity() {
        let mut pipeline = with_defaults();
        let identity = *pipeline.stages_in_order()[0].id();
        let policy = *pipeline.stages_in_order()[1].id();

        pipeline
            .reorder_stages(&[policy, identity], &person())
            .unwrap();

        assert!(matches!(
            pipeline.stages_in_order()[0].kind(),
            StageKind::Identity
        ));
    }

    /// Removing a stage id the pipeline does not hold is refused as not
    /// found.
    #[test]
    fn remove_nonexistent_stage_returns_error() {
        let mut pipeline = with_defaults();
        assert_eq!(
            pipeline.remove_stage(&StageId::new(), &person()),
            Err(PipelineError::StageNotFound)
        );
    }

    /// A new pipeline has a real, non-nil id and the name `Default`. After a
    /// rename it reads `Public API`.
    #[test]
    fn a_pipeline_carries_its_own_id_and_the_name_it_was_given() {
        let mut pipeline = with_defaults();

        assert!(!pipeline.id().as_uuid().is_nil());
        assert_eq!(pipeline.name().as_str(), "Default");

        pipeline
            .rename(
                Label::new("pipeline_name", "Public API").unwrap(),
                &person(),
            )
            .unwrap();

        assert_eq!(pipeline.name().as_str(), "Public API");
    }

    /// A disabled geofence is enabled again and counts among the active
    /// stages. Enabling a stage id this pipeline does not hold is refused as
    /// not found.
    #[test]
    fn enabling_a_stage_puts_it_back_in_the_pipeline() {
        let (mut pipeline, geo_id) = drafted_with_geofence();
        pipeline.disable_stage(&geo_id, &person()).unwrap();
        assert_eq!(pipeline.active_stages().len(), 2);

        pipeline.enable_stage(&geo_id, &person()).unwrap();

        assert_eq!(pipeline.active_stages().len(), 3);
        assert_eq!(
            pipeline.enable_stage(&StageId::new(), &person()),
            Err(PipelineError::StageNotFound),
            "a stage from another pipeline must not be reported as enabled"
        );
    }

    /// An order that names Identity twice and skips Policy is refused, and
    /// so is one that leaves out the geofence. Both would leave a stage
    /// unplaced.
    #[test]
    fn a_reorder_naming_a_stage_twice_is_refused() {
        let (mut pipeline, geo_id) = drafted_with_geofence();
        let ids = stage_ids(&pipeline);

        assert_eq!(
            pipeline.reorder_stages(&[ids[0], ids[0], geo_id], &person()),
            Err(PipelineError::IncompleteOrder)
        );
        assert_eq!(
            pipeline.reorder_stages(&[ids[0], ids[1]], &person()),
            Err(PipelineError::IncompleteOrder)
        );
    }

    /// Disabling a stage five minutes later moves `updated_at` to that time
    /// and leaves `created_at` alone. Caches watch `updated_at` to drop a
    /// stale pipeline.
    #[test]
    fn editing_a_pipeline_moves_the_timestamp_readers_watch() {
        let (mut pipeline, geo_id) = drafted_with_geofence();
        let created = pipeline.created_at();
        let later = pipeline.updated_at() + time::Duration::minutes(5);

        let _frozen = crate::shared::clock::freeze(later);
        pipeline.disable_stage(&geo_id, &person()).unwrap();

        assert_eq!(pipeline.updated_at(), later);
        assert_eq!(pipeline.created_at(), created);
    }

    /// Activating a draft pipeline with a shared cache for a signed-in
    /// route returns `SharedCacheOnSignedInRoute` and leaves it in draft.
    #[test]
    fn a_pipeline_sharing_cached_responses_does_not_run_a_signed_in_route() {
        let mut pipeline = with_defaults();
        let routes = [route_on(&pipeline, RoutePolicy::Authenticated)];
        pipeline.add_stage(shared_cache_stage(), &person()).unwrap();

        let activated = pipeline.activate(&routes, &person());

        assert_eq!(activated, Err(PipelineError::SharedCacheOnSignedInRoute));
        assert_eq!(pipeline.status(), PipelineStatus::Draft);
    }

    /// A pipeline with a cache kept once for everyone runs a public price
    /// list. Turning it on is allowed.
    #[test]
    fn a_pipeline_sharing_cached_responses_runs_public_routes() {
        let mut pipeline = with_defaults();
        let routes = [route_on(&pipeline, RoutePolicy::Public)];
        pipeline.add_stage(shared_cache_stage(), &person()).unwrap();

        pipeline.activate(&routes, &person()).unwrap();

        assert_eq!(pipeline.status(), PipelineStatus::Active);
    }

    /// Activating a draft pipeline with a shared cache while supplying
    /// another pipeline's public route returns `ForeignRoute` and leaves
    /// the pipeline in draft.
    #[test]
    fn turning_a_pipeline_on_refuses_another_pipelines_routes() {
        let mut pipeline = with_defaults();
        let other = with_defaults();
        let unrelated = [route_on(&other, RoutePolicy::Public)];
        pipeline.add_stage(shared_cache_stage(), &person()).unwrap();

        let activated = pipeline.activate(&unrelated, &person());

        assert_eq!(activated, Err(PipelineError::ForeignRoute));
        assert_eq!(pipeline.status(), PipelineStatus::Draft);
    }

    /// Fay manages pipelines and deletes one no route runs. It is allowed.
    #[test]
    fn a_pipeline_no_route_runs_may_be_deleted() {
        let mut pipeline = with_defaults();

        assert_eq!(pipeline.delete(&[], &person()), Ok(()));
    }

    /// Deleting a pipeline while supplying a signed-in route that uses it
    /// returns `InUse`.
    #[test]
    fn a_pipeline_a_route_still_runs_is_not_deleted() {
        let mut pipeline = with_defaults();
        let routes = [route_on(&pipeline, RoutePolicy::Authenticated)];

        let deleted = pipeline.delete(&routes, &person());

        assert_eq!(deleted, Err(PipelineError::InUse));
    }

    /// Deleting an unused pipeline with routing permission alone returns
    /// `NotAllowed`.
    #[test]
    fn deleting_a_pipeline_needs_the_pipeline_right() {
        let mut pipeline = with_defaults();

        let deleted = pipeline.delete(&[], &agent());

        assert_eq!(deleted, Err(PipelineError::NotAllowed));
    }

    /// Deleting a pipeline while supplying another pipeline's public route
    /// returns `ForeignRoute`.
    #[test]
    fn deleting_a_pipeline_refuses_another_pipelines_routes() {
        let mut pipeline = with_defaults();
        let other = with_defaults();
        let unrelated = [route_on(&other, RoutePolicy::Public)];

        let deleted = pipeline.delete(&unrelated, &person());

        assert_eq!(deleted, Err(PipelineError::ForeignRoute));
    }

    /// A missing stage, an incomplete order, a locked stage, a shared cache
    /// on a signed-in route, another pipeline's route and a pipeline still
    /// in use each have their own message. An operator
    /// sees these words when an edit is refused.
    #[test]
    fn every_pipeline_error_says_what_went_wrong() {
        assert_eq!(
            PipelineError::StageNotFound.to_string(),
            "stage not found in the pipeline"
        );
        assert_eq!(
            PipelineError::IncompleteOrder.to_string(),
            "a reorder must list every stage exactly once"
        );
        assert_eq!(
            PipelineError::CannotRemoveMandatory.to_string(),
            "cannot remove a mandatory stage"
        );
        assert_eq!(
            PipelineError::SharedCacheOnSignedInRoute.to_string(),
            "a cache shared between callers cannot run on a route that needs sign-in"
        );
        assert_eq!(
            PipelineError::ForeignRoute.to_string(),
            "a route given for this pipeline runs on another one"
        );
        assert_eq!(
            PipelineError::InUse.to_string(),
            "routes still run this pipeline, so it cannot be deleted"
        );
    }

    /// Changing a live pipeline and adding a second Identity stage are each
    /// refused in plain words, and a refused status move names both
    /// statuses.
    #[test]
    fn a_refused_edit_or_status_move_says_why_plainly() {
        assert_eq!(
            PipelineError::ActivePipelineImmutable.to_string(),
            "an active pipeline must be disabled before it is changed"
        );
        assert_eq!(
            PipelineError::CannotAddMandatory.to_string(),
            "a pipeline holds one Identity and one Policy stage, so neither is added"
        );
        let refused = PipelineStatus::Draft
            .try_transition(PipelineStatus::Disabled)
            .unwrap_err();
        assert_eq!(
            PipelineError::from(refused).to_string(),
            "cannot move a pipeline from Draft to Disabled"
        );
    }

    /// A pipeline with a geofence added, what it raised so far taken out.
    fn quiet_with_geofence() -> (Pipeline<ResolvedTenant>, StageId) {
        let (mut pipeline, geo_id) = drafted_with_geofence();
        raised_names(&mut pipeline);
        (pipeline, geo_id)
    }

    /// Fay makes a pipeline. The creation is raised for the audit trail.
    #[test]
    fn creating_raises_proxy_pipeline_created() {
        let mut pipeline = with_defaults();

        assert_eq!(raised_names(&mut pipeline), ["proxy.pipeline_created"]);
    }

    /// A pipeline is read back from storage. Loading it is no change, so it
    /// has raised nothing.
    #[test]
    fn a_pipeline_read_back_from_storage_has_raised_nothing() {
        let identity = StageConfig::new(StageKind::Identity, 100, StageRemoval::Locked).unwrap();
        let policy = StageConfig::new(StageKind::Policy, 200, StageRemoval::Locked).unwrap();

        let mut stored =
            Pipeline::<ResolvedTenant>::reconstitute(row_with(vec![identity, policy])).unwrap();

        assert!(raised_names(&mut stored).is_empty());
    }

    /// Fay renames `Default` to `Edge`. The rename is raised with both
    /// names, so the audit trail keeps what routes knew it as.
    #[test]
    fn renaming_raises_both_names() {
        let mut pipeline = with_defaults();
        raised_names(&mut pipeline);

        pipeline
            .rename(Label::new("pipeline_name", "Edge").unwrap(), &person())
            .unwrap();

        let events = raised(&mut pipeline);
        assert_eq!(events[0].event_type().to_string(), "proxy.pipeline_renamed");
        assert!(events[0].payload().value("name").is_some());
    }

    /// Fay adds a geofence to a new pipeline. It is raised with the place
    /// the pipeline gave it, after Identity and Policy.
    #[test]
    fn adding_a_stage_raises_the_place_it_took() {
        let (mut pipeline, _) = drafted_with_geofence();

        let events = raised(&mut pipeline);

        assert_eq!(events[1].event_type().to_string(), "proxy.stage_added");
        assert_eq!(events[1].payload().get("stage_kind"), Some("geo_fence"));
        assert_eq!(events[1].payload().get("position"), Some("201"));
    }

    /// Fay switches the geofence off and on again, then removes it. Each is
    /// raised, in order.
    #[test]
    fn stage_changes_raise_one_event_each() {
        let (mut pipeline, geo_id) = quiet_with_geofence();

        pipeline.disable_stage(&geo_id, &person()).unwrap();
        pipeline.enable_stage(&geo_id, &person()).unwrap();
        pipeline.remove_stage(&geo_id, &person()).unwrap();

        assert_eq!(
            raised_names(&mut pipeline),
            [
                "proxy.stage_disabled",
                "proxy.stage_enabled",
                "proxy.stage_removed"
            ]
        );
    }

    /// Fay reorders the pipeline. The order it runs now is raised, every
    /// stage in it.
    #[test]
    fn reordering_raises_the_order_it_runs_now() {
        let (mut pipeline, _) = quiet_with_geofence();
        let order = stage_ids(&pipeline);

        pipeline.reorder_stages(&order, &person()).unwrap();

        let events = raised(&mut pipeline);
        assert_eq!(
            events[0].event_type().to_string(),
            "proxy.pipeline_reordered"
        );
        assert_eq!(events[0].payload().get("stage_count"), Some("3"));
    }

    /// Fay activates the pipeline and later disables it. Each is raised, so
    /// every proxy reloads it.
    #[test]
    fn activating_and_disabling_raise_proxy_pipeline_activated_and_disabled() {
        let (mut pipeline, _) = quiet_with_geofence();

        pipeline.activate(&[], &person()).unwrap();
        pipeline.disable(&person()).unwrap();

        assert_eq!(
            raised_names(&mut pipeline),
            ["proxy.pipeline_activated", "proxy.pipeline_disabled"]
        );
    }

    /// Fay deletes a pipeline no route runs. The deletion is raised.
    #[test]
    fn deleting_raises_proxy_pipeline_deleted() {
        let mut pipeline = with_defaults();
        raised_names(&mut pipeline);

        pipeline.delete(&[], &person()).unwrap();

        assert_eq!(raised_names(&mut pipeline), ["proxy.pipeline_deleted"]);
    }

    /// Unauthorized geofence removal, editing an active pipeline and
    /// deleting an in-use pipeline are refused. After activation events
    /// are drained, the latter two refusals raise no events.
    #[test]
    fn a_refused_change_raises_nothing() {
        let (mut pipeline, geo_id) = quiet_with_geofence();
        let routes = [route_on(&pipeline, RoutePolicy::Authenticated)];

        let removed_by_sam = pipeline.remove_stage(&geo_id, &agent());
        pipeline.activate(&[], &person()).unwrap();
        raised_names(&mut pipeline);
        let edited_while_running = pipeline.disable_stage(&geo_id, &person());
        let deleted_in_use = pipeline.delete(&routes, &person());

        assert!(removed_by_sam.is_err());
        assert!(edited_while_running.is_err());
        assert!(deleted_in_use.is_err());
        assert!(raised_names(&mut pipeline).is_empty());
    }
}
