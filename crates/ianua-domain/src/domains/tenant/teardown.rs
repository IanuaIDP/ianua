//! A deleted tenant's teardown: the steps that remove what it held, and
//! which waits on which.
//!
//! A tenant is deleted first, which closes it to everyone, and torn down
//! after. Every tenant has its data removed. A tenant with a schema, an
//! instance or a cluster of its own also has its audit trail moved to the
//! platform's database, since the trail outlives the tenant for as long as
//! its retention says, and its own database removed last, once its data is
//! gone and its trail is safe. Each step is finished or failed through the
//! teardown. A step done twice, by a retry that ran it again, finishes
//! once. The last step done raises `tenant.torn_down`; a step failed for
//! good stops the teardown and raises `tenant.teardown_failed`.
//!
//! The teardown does no work itself: whoever runs the steps asks it which
//! are ready and tells it how each ended.

use time::OffsetDateTime;

use crate::domains::tenant::events::lifecycle::{TeardownFailed, TenantTornDown};
use crate::domains::tenant::lifecycle::Tenant;
use crate::domains::tenant::provisioning::infrastructure::IsolationLevel;
use crate::domains::tenant::status::TenantStatus;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{RaisedEvents, RaisesComplete};
use crate::shared::model::aggregate::Aggregate;
use crate::shared::model::row_check::RowCheck;
use crate::shared::model::steps::{Finished, PlanStep, RunFailure, RunOutcome, StepPlan, StepRun};
use crate::types::{TenantId, UntrustedText};

/// One step of a tenant's teardown.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TeardownStep {
    /// The tenant's data removed, wherever it lives, its audit trail kept.
    Data,
    /// The audit trail moved from the tenant's own database to the
    /// platform's.
    AuditTrail,
    /// The tenant's own database removed: a schema, an instance or a
    /// cluster.
    Database,
}

impl PlanStep for TeardownStep {
    const ALL: &'static [Self] = &[Self::Data, Self::AuditTrail, Self::Database];

    fn as_str(self) -> &'static str {
        match self {
            Self::Data => "data",
            Self::AuditTrail => "audit_trail",
            Self::Database => "database",
        }
    }
}

/// The plan of a teardown holding `planned`: the database waits on every
/// other step, and the audit trail is moved only where a database is
/// removed.
///
/// # Errors
///
/// [`DomainError::Validation`] when `planned` lacks the data step, holds
/// one of the audit trail and the database without the other, or lists a
/// step twice.
fn plan_of(planned: &[TeardownStep]) -> Result<StepPlan<TeardownStep>, DomainError> {
    if !planned.contains(&TeardownStep::Data) {
        return Err(DomainError::invalid(message!(
            "tenant-a-tenant-s-teardown-removes-its",
            "a tenant's teardown removes its data"
        )));
    }
    let trail = planned.contains(&TeardownStep::AuditTrail);
    let database = planned.contains(&TeardownStep::Database);
    if trail != database {
        return Err(DomainError::invalid(message!(
            "tenant-a-tenant-s-own-database-is",
            "a tenant's own database is removed only once its audit trail is moved"
        )));
    }
    let before_database: Vec<TeardownStep> = planned
        .iter()
        .copied()
        .filter(|step| *step != TeardownStep::Database)
        .collect();
    StepPlan::new(planned.iter().map(|step| {
        let after = match step {
            TeardownStep::Data | TeardownStep::AuditTrail => Vec::new(),
            TeardownStep::Database => before_database.clone(),
        };
        (*step, after)
    }))
}

/// The steps a tenant of `isolation` is torn down with.
fn steps_for(isolation: IsolationLevel) -> Vec<TeardownStep> {
    match isolation {
        IsolationLevel::Shared => vec![TeardownStep::Data],
        IsolationLevel::DedicatedSchema
        | IsolationLevel::DedicatedInstance
        | IsolationLevel::DedicatedCluster => TeardownStep::ALL.to_vec(),
    }
}

/// A [`TenantTeardown`] as storage holds it, read back through
/// [`TenantTeardown::reconstitute`].
#[derive(Debug, Clone)]
pub struct TenantTeardownRow {
    /// The tenant torn down.
    pub tenant_id: TenantId,
    /// The steps its teardown holds.
    pub planned: Vec<TeardownStep>,
    /// The steps done, in the order they were done.
    pub done: Vec<TeardownStep>,
    /// The step that failed and why, if one did.
    pub failed: RunFailure<TeardownStep>,
    /// When the teardown began.
    pub started_at: OffsetDateTime,
    /// When it last changed.
    pub updated_at: OffsetDateTime,
}

/// A deleted tenant's teardown, one per tenant, identified by its tenant.
#[derive(Debug)]
pub struct TenantTeardown {
    tenant_id: TenantId,
    run: StepRun<TeardownStep>,
    started_at: OffsetDateTime,
    updated_at: OffsetDateTime,
    raised: RaisedEvents,
}

impl TenantTeardown {
    /// Begins tearing down `tenant`, with the steps its residency asks for.
    ///
    /// # Errors
    ///
    /// [`DomainError::InvalidTransition`] unless the tenant is deleted:
    /// only a tenant closed to everyone for good is torn down.
    pub fn begin(tenant: &Tenant) -> Result<Self, DomainError> {
        if tenant.status() != TenantStatus::Deleted {
            return Err(DomainError::invalid_transition(message!(
                "tenant-only-a-deleted-tenant-is-torn",
                "only a deleted tenant is torn down"
            )));
        }
        let plan = plan_of(&steps_for(tenant.residency().isolation()))?;
        let now = crate::shared::clock::now();
        Ok(Self {
            tenant_id: *tenant.id(),
            run: StepRun::start(plan),
            started_at: now,
            updated_at: now,
            raised: RaisedEvents::default(),
        })
    }

    /// Rebuilds a teardown from storage.
    ///
    /// # Errors
    ///
    /// [`DomainError::Infrastructure`] when the row's steps are not a
    /// teardown's, a step is done before what it waits on or twice, its
    /// failed step was also done or never ready, or it changed before it
    /// began.
    pub fn reconstitute(row: TenantTeardownRow) -> Result<Self, DomainError> {
        RowCheck::of("tenant teardown")
            .in_order(row.started_at, row.updated_at, "changed before it began")
            .finish()?;
        let plan = plan_of(&row.planned).map_err(|_| {
            DomainError::corrupt_row("tenant teardown", "steps that are not a teardown's")
        })?;
        let run = StepRun::restored(plan, row.done, row.failed).ok_or_else(|| {
            DomainError::corrupt_row(
                "tenant teardown",
                "steps done before what they wait on, twice, or after a failure",
            )
        })?;
        Ok(Self {
            tenant_id: row.tenant_id,
            run,
            started_at: row.started_at,
            updated_at: row.updated_at,
            raised: RaisedEvents::default(),
        })
    }

    /// The tenant torn down.
    #[must_use]
    pub fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// The steps the teardown holds, in their planned order.
    #[must_use]
    pub fn planned(&self) -> Vec<TeardownStep> {
        self.run.plan().steps().collect()
    }

    /// The steps done, in the order they were done.
    #[must_use]
    pub fn done(&self) -> &[TeardownStep] {
        self.run.done()
    }

    /// The step that failed and why, if one did.
    #[must_use]
    pub fn failure(&self) -> Option<(TeardownStep, &UntrustedText)> {
        self.run.failure()
    }

    /// The steps ready to run now. None once a step failed.
    #[must_use]
    pub fn ready(&self) -> Vec<TeardownStep> {
        self.run.ready()
    }

    /// How the teardown stands.
    #[must_use]
    pub fn outcome(&self) -> RunOutcome {
        self.run.outcome()
    }

    /// Marks `step` done. A step done already stays done. The last step
    /// done raises `tenant.torn_down`.
    ///
    /// # Errors
    ///
    /// [`DomainError::InvalidTransition`] when the teardown failed, does
    /// not hold the step, or the step waits on one not yet done.
    pub fn finish(&mut self, step: TeardownStep) -> Result<Finished, DomainError> {
        let finished = self.run.finish(step)?;
        if finished == Finished::Already {
            return Ok(finished);
        }
        self.touch();
        if self.run.outcome() == RunOutcome::Done {
            self.raised.raise_tenant(
                self.tenant_id,
                TenantTornDown {
                    occurred_at: self.updated_at,
                },
            );
        }
        Ok(finished)
    }

    /// Marks `step` failed for good for `why`: the teardown stops. Raises
    /// `tenant.teardown_failed`.
    ///
    /// # Errors
    ///
    /// [`DomainError::InvalidTransition`] when the teardown failed already,
    /// or the step is done or not ready.
    pub fn fail(&mut self, step: TeardownStep, why: UntrustedText) -> Result<(), DomainError> {
        self.run.fail(step, why.clone())?;
        self.touch();
        self.raised.raise_tenant(
            self.tenant_id,
            TeardownFailed {
                step: step.as_str(),
                reason: why,
                occurred_at: self.updated_at,
            },
        );
        Ok(())
    }

    fn touch(&mut self) {
        self.updated_at = crate::shared::clock::now();
    }
}

/// The row a teardown is kept as.
impl From<&TenantTeardown> for TenantTeardownRow {
    fn from(teardown: &TenantTeardown) -> Self {
        Self {
            tenant_id: teardown.tenant_id,
            planned: teardown.planned(),
            done: teardown.done().to_vec(),
            failed: teardown.run.failed().clone(),
            started_at: teardown.started_at,
            updated_at: teardown.updated_at,
        }
    }
}

/// A teardown's records name the tenant it tears down.
impl RaisesComplete for TenantTeardown {
    fn take_events(&mut self) -> Vec<DomainEvent> {
        self.raised.take()
    }
}

/// A teardown is identified by the tenant it tears down.
impl Aggregate for TenantTeardown {
    type Id = TenantId;

    fn id(&self) -> &Self::Id {
        &self.tenant_id
    }

    fn created_at(&self) -> OffsetDateTime {
        self.started_at
    }

    fn updated_at(&self) -> OffsetDateTime {
        self.updated_at
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::tenant::compliance_limits::ComplianceLimits;
    use crate::domains::tenant::fixtures::{acme_params, active, deleted};
    use crate::domains::tenant::lifecycle::ProvisionTenantParams;
    use crate::domains::tenant::provisioning::infrastructure::{
        DeploymentRegion, Placement, TenantResidency,
    };
    use crate::shared::model::row_check::refused_as_corrupt;
    use crate::test_support::events::raised_complete_names;
    use crate::types::ActedBy;

    fn deleted_apart() -> Tenant {
        let residency = TenantResidency::new(
            Placement::Platform {
                region: DeploymentRegion::EuCentral1,
            },
            IsolationLevel::DedicatedSchema,
        )
        .unwrap();
        let params = ProvisionTenantParams {
            residency,
            ..acme_params()
        };
        let mut tenant =
            Tenant::provision(params, &ComplianceLimits::default(), ActedBy::Platform).unwrap();
        tenant.activate(ActedBy::Platform).unwrap();
        deleted(tenant)
    }

    fn why() -> UntrustedText {
        UntrustedText::record("the database host did not answer")
    }

    fn row_of(teardown: &TenantTeardown) -> TenantTeardownRow {
        TenantTeardownRow::from(teardown)
    }

    /// A tenant on the platform's database has only its data removed.
    #[test]
    fn a_shared_tenant_has_only_its_data_removed() {
        let teardown = TenantTeardown::begin(&deleted(active())).unwrap();

        assert_eq!(teardown.planned(), [TeardownStep::Data]);
        assert_eq!(teardown.ready(), [TeardownStep::Data]);
    }

    /// A dedicated-schema teardown offers data removal and audit relocation
    /// first; database removal becomes ready only after both are complete.
    #[test]
    fn a_tenant_apart_keeps_its_trail_before_its_database_goes() {
        let mut teardown = TenantTeardown::begin(&deleted_apart()).unwrap();

        let first = teardown.ready();
        teardown.finish(TeardownStep::Data).unwrap();
        let after_data = teardown.ready();
        teardown.finish(TeardownStep::AuditTrail).unwrap();

        assert_eq!(first, [TeardownStep::Data, TeardownStep::AuditTrail]);
        assert_eq!(after_data, [TeardownStep::AuditTrail]);
        assert_eq!(teardown.ready(), [TeardownStep::Database]);
    }

    /// Starting teardown for an active tenant is rejected as an invalid transition.
    #[test]
    fn a_tenant_not_deleted_is_not_torn_down() {
        let begun = TenantTeardown::begin(&active());

        assert!(matches!(begun, Err(DomainError::InvalidTransition(_))));
    }

    /// The last step done ends the teardown and goes on record once, and a
    /// retry finishing it again records nothing more.
    #[test]
    fn the_last_step_done_records_the_teardown() {
        let mut teardown = TenantTeardown::begin(&deleted(active())).unwrap();

        teardown.finish(TeardownStep::Data).unwrap();
        let again = teardown.finish(TeardownStep::Data).unwrap();

        assert_eq!(again, Finished::Already);
        assert_eq!(teardown.outcome(), RunOutcome::Done);
        assert_eq!(raised_complete_names(&mut teardown), ["tenant.torn_down"]);
    }

    /// A step that failed for good stops the teardown, and goes on record
    /// for the operators with its step and reason.
    #[test]
    fn a_failed_step_stops_the_teardown_and_is_recorded() {
        let mut teardown = TenantTeardown::begin(&deleted_apart()).unwrap();

        teardown.fail(TeardownStep::AuditTrail, why()).unwrap();

        assert_eq!(teardown.outcome(), RunOutcome::Failed);
        assert!(teardown.ready().is_empty());
        assert_eq!(
            raised_complete_names(&mut teardown),
            ["tenant.teardown_failed"]
        );
    }

    /// A teardown reads back as it was kept, and has raised nothing.
    #[test]
    fn a_kept_teardown_reads_back() {
        let mut teardown = TenantTeardown::begin(&deleted_apart()).unwrap();
        teardown.finish(TeardownStep::Data).unwrap();

        let mut stored = TenantTeardown::reconstitute(row_of(&teardown)).unwrap();

        assert_eq!(stored.done(), [TeardownStep::Data]);
        assert_eq!(stored.ready(), teardown.ready());
        assert!(raised_complete_names(&mut stored).is_empty());
    }

    /// Reconstitution rejects teardown rows with premature database removal,
    /// no audit-relocation step or an update time earlier than the start.
    #[test]
    fn a_row_that_cannot_have_happened_is_refused() {
        let teardown = TenantTeardown::begin(&deleted_apart()).unwrap();
        let early = TenantTeardownRow {
            done: vec![TeardownStep::Database],
            ..row_of(&teardown)
        };
        let trail_lost = TenantTeardownRow {
            planned: vec![TeardownStep::Data, TeardownStep::Database],
            ..row_of(&teardown)
        };
        let backwards = TenantTeardownRow {
            updated_at: teardown.started_at - time::Duration::SECOND,
            ..row_of(&teardown)
        };

        for row in [early, trail_lost, backwards] {
            assert!(refused_as_corrupt(&TenantTeardown::reconstitute(row)));
        }
    }
}
