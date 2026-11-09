//! Pipeline stages: the steps a proxy pipeline is built from.
//!
//! Each stage is a kind with typed settings. The infrastructure layer runs
//! each kind through the `StageExecutor` port.

mod config;
mod kind;
mod kind_name;
mod watch;

pub use config::*;
pub use kind::*;
pub use kind_name::*;
pub use watch::*;

use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::model::row_check::RowCheck;
use crate::shared::model::two_cases::two_cases;
use crate::types::{Enablement, StageId};

two_cases! {
    /// Whether a tenant may remove a stage from its pipeline.
    ///
    /// It is stored as the `mandatory` flag, with `true` meaning locked.
    pub enum StageRemoval {
        /// A platform-mandatory stage, which stays.
        Locked => true,
        /// A stage the tenant chose, which it may remove.
        Allowed => false,
    }
}

impl StageRemoval {
    /// The removal rule a stage of `kind` has.
    ///
    /// It is locked exactly when `kind` is one of the [`MandatoryStage`]s.
    #[must_use]
    pub fn of(kind: &StageKind) -> Self {
        let mandatory = [MandatoryStage::Identity, MandatoryStage::Policy]
            .into_iter()
            .any(|stage| stage.is(kind));
        if mandatory {
            return Self::Locked;
        }
        Self::Allowed
    }

    /// Refuses a removal rule that does not belong to `kind`.
    ///
    /// A locked filter could never be removed. An unlocked Identity or Policy
    /// stage could be removed, and the pipeline would run without it.
    fn ensure_fits(self, kind: &StageKind) -> Result<(), DomainError> {
        if self != Self::of(kind) {
            return Err(DomainError::invalid(message!(
                "proxy-only-the-identity-and-policy-stages",
                "only the Identity and Policy stages are locked, and they always are"
            )));
        }
        Ok(())
    }
}

/// A stored stage, as [`StageConfig::reconstitute`] reads it.
pub struct StageConfigRow {
    /// The stage's id.
    pub id: StageId,
    /// What this stage does.
    pub kind: StageKind,
    /// Where it runs in the pipeline. Lower runs first.
    pub position: u16,
    /// Whether this stage is active.
    pub enabled: Enablement,
    /// Whether the tenant may remove this stage.
    pub removal: StageRemoval,
}

/// One stage in a pipeline: what it does, where it runs, and whether it is
/// on and may be removed.
///
/// JSON is read through the same check as [`StageConfig::new`]. So a
/// pipeline cached or handed over as JSON cannot carry a stage set up so it
/// could not do its job.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "StageConfigWire"))]
pub struct StageConfig {
    /// The stage's id, unique in its pipeline.
    id: StageId,
    /// What this stage does.
    kind: StageKind,
    /// Where it runs in the pipeline. Lower runs first.
    position: u16,
    /// Whether this stage runs.
    enabled: Enablement,
    /// Whether the tenant may remove this stage. Platform-mandatory stages
    /// are locked.
    #[cfg_attr(feature = "serde", serde(rename = "mandatory"))]
    removal: StageRemoval,
}

/// A [`StageConfig`] as JSON spells it, before its kind is checked.
#[cfg(feature = "serde")]
#[derive(serde::Deserialize)]
struct StageConfigWire {
    id: StageId,
    kind: StageKind,
    position: u16,
    enabled: Enablement,
    #[serde(rename = "mandatory")]
    removal: StageRemoval,
}

#[cfg(feature = "serde")]
impl TryFrom<StageConfigWire> for StageConfig {
    type Error = DomainError;

    fn try_from(wire: StageConfigWire) -> Result<Self, Self::Error> {
        wire.kind.validate()?;
        wire.removal.ensure_fits(&wire.kind)?;
        Ok(Self {
            id: wire.id,
            kind: wire.kind,
            position: wire.position,
            enabled: wire.enabled,
            removal: wire.removal,
        })
    }
}

/// A stage every pipeline runs and nobody may remove.
///
/// Neither has settings, so there is nothing about one to get wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MandatoryStage {
    /// Verifies the caller's session or token.
    Identity,
    /// Checks the route's authorization policy.
    Policy,
}

impl MandatoryStage {
    /// Whether `kind` is this stage.
    #[must_use]
    pub fn is(self, kind: &StageKind) -> bool {
        matches!(
            (self, kind),
            (Self::Identity, StageKind::Identity) | (Self::Policy, StageKind::Policy)
        )
    }

    fn kind_and_position(self) -> (StageKind, u16) {
        match self {
            Self::Identity => (StageKind::Identity, 100),
            Self::Policy => (StageKind::Policy, 200),
        }
    }
}

impl StageConfig {
    /// A locked stage every pipeline runs, at its fixed position.
    #[must_use]
    pub fn locked(stage: MandatoryStage) -> Self {
        let (kind, position) = stage.kind_and_position();
        Self {
            id: StageId::new(),
            kind,
            position,
            enabled: Enablement::Enabled,
            removal: StageRemoval::Locked,
        }
    }

    /// A new, enabled stage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] if `kind` is set up so it could not do
    ///   its job, as [`StageKind::validate`] decides.
    /// - [`DomainError::Validation`] if `removal` is not the one a stage of
    ///   that kind has, as [`StageRemoval::of`] gives it.
    pub fn new(kind: StageKind, position: u16, removal: StageRemoval) -> Result<Self, DomainError> {
        kind.validate()?;
        removal.ensure_fits(&kind)?;
        Ok(Self {
            id: StageId::new(),
            kind,
            position,
            enabled: Enablement::Enabled,
            removal,
        })
    }

    /// Rebuilds a stage from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the stored removal rule is not
    ///   the one its kind has. A row cannot lock a filter in place, or unlock
    ///   Identity or Policy.
    /// - [`DomainError::Infrastructure`] when its settings are ones its kind
    ///   refuses.
    pub fn reconstitute(row: StageConfigRow) -> Result<Self, DomainError> {
        Self::ensure_consistent(&row)?;
        Ok(Self {
            id: row.id,
            kind: row.kind,
            position: row.position,
            enabled: row.enabled,
            removal: row.removal,
        })
    }

    /// Refuses a stored row that breaks a rule this keeps.
    fn ensure_consistent(row: &StageConfigRow) -> Result<(), DomainError> {
        RowCheck::of("pipeline stage")
            .holds(
                row.removal == StageRemoval::of(&row.kind),
                "a removal rule its kind does not have",
            )
            .holds(row.kind.validate().is_ok(), "settings its kind refuses")
            .finish()
    }

    /// The stage's id.
    #[must_use]
    pub fn id(&self) -> &StageId {
        &self.id
    }

    /// What this stage does.
    #[must_use]
    pub fn kind(&self) -> &StageKind {
        &self.kind
    }

    /// Where it runs in the pipeline. Lower runs first.
    #[must_use]
    pub fn position(&self) -> u16 {
        self.position
    }

    /// Whether this stage runs.
    #[must_use]
    pub fn enabled(&self) -> bool {
        self.enabled == Enablement::Enabled
    }

    /// Whether the stage is locked, so the tenant may not remove it.
    #[must_use]
    pub fn mandatory(&self) -> bool {
        self.removal == StageRemoval::Locked
    }

    /// Where this stage must run beside the others.
    ///
    /// Identity runs first, so Policy decides on a known caller. Policy runs
    /// next, then everything else.
    pub(crate) fn run_rank(&self) -> u8 {
        if MandatoryStage::Identity.is(&self.kind) {
            return 0;
        }
        if MandatoryStage::Policy.is(&self.kind) {
            return 1;
        }
        2
    }

    /// Enables the stage. Only the pipeline does this, so a stage is never
    /// switched outside the rules the pipeline keeps.
    pub(in crate::domains::proxy) fn enable(&mut self) {
        self.enabled = Enablement::Enabled;
    }

    /// Disables the stage without removing it. Only the pipeline does this,
    /// which refuses it for Identity and Policy.
    pub(in crate::domains::proxy) fn disable(&mut self) {
        self.enabled = Enablement::Disabled;
    }

    /// Moves the stage to `position`. Only the pipeline does this, since a
    /// position means something only beside the other stages.
    pub(in crate::domains::proxy) fn move_to(&mut self, position: u16) {
        self.position = position;
    }

    /// Replaces the stage's settings with `kind`, which must be the same kind
    /// of stage. Only the pipeline does this, while it is off.
    ///
    /// A stage keeps its kind for life. A rate limit turned into a cache in
    /// place would keep its id and position, and the audit trail would show
    /// a settings change where a check was really taken out.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] if `kind` is another kind of stage.
    /// - [`DomainError::Validation`] if `kind` is set up so it could not do
    ///   its job, as [`StageKind::validate`] decides.
    pub(in crate::domains::proxy) fn reconfigure(
        &mut self,
        kind: StageKind,
    ) -> Result<(), DomainError> {
        if kind.name() != self.kind.name() {
            return Err(DomainError::invalid(message!(
                "proxy-a-stage-s-settings-are-changed",
                "a stage's settings are changed for settings of the same kind; add a new stage \
                 for another kind"
            )));
        }
        kind.validate()?;
        self.kind = kind;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::model::row_check::refused_as_corrupt;
    #[cfg(feature = "serde")]
    use crate::types::HeaderName;
    use crate::types::Seconds;

    /// An Identity stage is disabled and then enabled again. It reports
    /// itself on, so the check an operator turned back on really runs.
    #[test]
    fn enabling_a_stage_turns_it_back_on() {
        let mut stage = StageConfig::new(StageKind::Identity, 100, StageRemoval::Locked).unwrap();
        stage.disable();
        assert!(!stage.enabled());

        stage.enable();

        assert!(stage.enabled());
    }

    /// A locked Identity stage is written to JSON with `mandatory: true`, and
    /// a chosen rate limit with `false`. The locked one reads back locked.
    #[cfg(feature = "serde")]
    #[test]
    fn a_stage_keeps_its_stored_mandatory_flag() {
        let locked = StageConfig::locked(MandatoryStage::Identity);
        let chosen = StageConfig::new(
            StageKind::RateLimit(RateLimitConfig {
                max_requests: 100,
                window_seconds: Seconds::new(60),
                key_by: RateLimitKey::UserId,
            }),
            300,
            StageRemoval::Allowed,
        )
        .unwrap();

        let locked_json = serde_json::to_value(&locked).unwrap();
        let chosen_json = serde_json::to_value(&chosen).unwrap();

        assert_eq!(locked_json["mandatory"], serde_json::json!(true));
        assert_eq!(chosen_json["mandatory"], serde_json::json!(false));
        let read_back: StageConfig = serde_json::from_value(locked_json).unwrap();
        assert!(read_back.mandatory());
    }

    /// A stored `mandatory` flag of `true` reads as locked and `false` as
    /// allowed, and each writes back as the flag it came from.
    #[test]
    fn the_mandatory_flag_is_true_exactly_for_a_locked_stage() {
        assert_eq!(StageRemoval::from(true), StageRemoval::Locked);
        assert_eq!(StageRemoval::from(false), StageRemoval::Allowed);
        assert!(bool::from(StageRemoval::Locked));
        assert!(!bool::from(StageRemoval::Allowed));
    }

    /// A stored rate limit of zero requests would block every request on the
    /// route, and no new stage may hold one. The row is refused as corrupt.
    #[test]
    fn a_stored_stage_with_settings_its_kind_refuses_is_refused() {
        let row = StageConfigRow {
            id: StageId::new(),
            kind: StageKind::RateLimit(RateLimitConfig {
                max_requests: 0,
                window_seconds: Seconds::new(60),
                key_by: RateLimitKey::UserId,
            }),
            position: 300,
            enabled: Enablement::Enabled,
            removal: StageRemoval::Allowed,
        };

        assert!(refused_as_corrupt(&StageConfig::reconstitute(row)));
    }

    /// A signing stage read from JSON passes. The same JSON with a signature
    /// lifetime of zero seconds is refused, as it would be in code.
    #[cfg(feature = "serde")]
    #[test]
    fn a_stage_read_from_json_is_checked_like_a_new_one() {
        let signing = StageConfig::new(
            StageKind::RequestSign(RequestSignConfig {
                header_name: HeaderName::new("x-upstream-signature").unwrap(),
                ttl_seconds: Seconds::new(60),
            }),
            300,
            StageRemoval::Allowed,
        )
        .unwrap();
        let mut json = serde_json::to_value(&signing).unwrap();
        assert!(serde_json::from_value::<StageConfig>(json.clone()).is_ok());

        json["kind"]["RequestSign"]["ttl_seconds"] = serde_json::json!(0);

        assert!(serde_json::from_value::<StageConfig>(json).is_err());
    }

    fn rate_limit(max_requests: u32) -> StageKind {
        StageKind::RateLimit(RateLimitConfig {
            max_requests,
            window_seconds: Seconds::new(60),
            key_by: RateLimitKey::UserId,
        })
    }

    /// Ann raises a rate limit from 100 to 500 requests a minute. The stage
    /// keeps its id and now carries the new limit.
    #[test]
    fn a_stage_takes_new_settings_of_its_own_kind() {
        let mut stage = StageConfig::new(rate_limit(100), 300, StageRemoval::Allowed).unwrap();
        let id = *stage.id();

        stage.reconfigure(rate_limit(500)).unwrap();

        assert_eq!(stage.id(), &id);
        assert_eq!(stage.kind(), &rate_limit(500));
    }

    /// Replacing a rate limit's settings with a cache fails validation and
    /// retains the original rate limit.
    #[test]
    fn a_stage_cannot_become_another_kind() {
        let mut stage = StageConfig::new(rate_limit(100), 300, StageRemoval::Allowed).unwrap();

        let changed = stage.reconfigure(StageKind::Cache(CacheConfig {
            ttl_seconds: Seconds::new(60),
            vary_by_user: CacheScope::PerUser,
        }));

        assert!(matches!(changed, Err(DomainError::Validation(_))));
        assert_eq!(stage.kind(), &rate_limit(100));
    }

    /// Reconfiguring a rate limit to allow zero requests is refused and
    /// retains the previous limit of 100 requests.
    #[test]
    fn new_settings_are_checked_like_new_stages() {
        let mut stage = StageConfig::new(rate_limit(100), 300, StageRemoval::Allowed).unwrap();

        assert!(stage.reconfigure(rate_limit(0)).is_err());
        assert_eq!(stage.kind(), &rate_limit(100));
    }
}
