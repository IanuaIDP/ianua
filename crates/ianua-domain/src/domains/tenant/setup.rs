//! A new tenant's setup: the steps that make it usable, and which waits on
//! which.
//!
//! A tenant is created provisioning and stays so until its setup is done.
//! The setup follows the tenant's residency: a tenant with a schema, an
//! instance or a cluster of its own first gets its database; every tenant
//! gets its signing key, its assertion key (which the gateway signs the
//! identity it hands upstreams with) and its starting roles, all kept in
//! that database, so all wait on it when there is one; and the tenant is
//! activated last, once every other step is done. Each step is finished or
//! failed through the setup. A step done twice, by a retry that ran it
//! again, finishes once. A step failed for good stops the setup and raises
//! `tenant.infra_failed`; activating the tenant raises its own
//! `tenant.status_changed`.
//!
//! The setup does no work itself: whoever runs the steps asks it which are
//! ready and tells it how each ended.

use time::OffsetDateTime;

use crate::domains::authorization::role::starting::StartingRolesGrant;
use crate::domains::tenant::events::lifecycle::InfraFailed;
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

/// One step of a tenant's setup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SetupStep {
    /// The tenant's own database: a schema, an instance or a cluster.
    Database,
    /// The tenant's first signing key.
    SigningKey,
    /// The tenant's first assertion key, for the identity the gateway
    /// hands upstreams.
    AssertionKey,
    /// The roles the tenant starts with.
    StartingRoles,
    /// The tenant made active.
    Activate,
}

impl PlanStep for SetupStep {
    const ALL: &'static [Self] = &[
        Self::Database,
        Self::SigningKey,
        Self::AssertionKey,
        Self::StartingRoles,
        Self::Activate,
    ];

    fn as_str(self) -> &'static str {
        match self {
            Self::Database => "database",
            Self::SigningKey => "signing_key",
            Self::AssertionKey => "assertion_key",
            Self::StartingRoles => "starting_roles",
            Self::Activate => "activate",
        }
    }
}

/// The plan of a setup holding `planned`: the signing key, the assertion
/// key and the starting roles wait on the database when there is one, and
/// activation on every other step.
///
/// # Errors
///
/// [`DomainError::Validation`] when `planned` lacks a step every setup
/// holds, or lists one twice.
fn plan_of(planned: &[SetupStep]) -> Result<StepPlan<SetupStep>, DomainError> {
    ensure_every_setup_step(planned)?;
    let database: Vec<SetupStep> = planned
        .iter()
        .copied()
        .filter(|step| *step == SetupStep::Database)
        .collect();
    let before_activation: Vec<SetupStep> = planned
        .iter()
        .copied()
        .filter(|step| *step != SetupStep::Activate)
        .collect();
    StepPlan::new(planned.iter().map(|step| {
        let after = match step {
            SetupStep::Database => Vec::new(),
            SetupStep::SigningKey | SetupStep::AssertionKey | SetupStep::StartingRoles => {
                database.clone()
            }
            SetupStep::Activate => before_activation.clone(),
        };
        (*step, after)
    }))
}

/// The steps every setup holds, whatever the tenant's isolation.
const EVERY_SETUP: [SetupStep; 4] = [
    SetupStep::SigningKey,
    SetupStep::AssertionKey,
    SetupStep::StartingRoles,
    SetupStep::Activate,
];

/// Refuses a plan lacking a step every setup holds.
fn ensure_every_setup_step(planned: &[SetupStep]) -> Result<(), DomainError> {
    if EVERY_SETUP.iter().all(|step| planned.contains(step)) {
        return Ok(());
    }
    Err(DomainError::invalid(message!(
        "tenant-a-tenant-s-setup-makes-its",
        "a tenant's setup makes its signing key, assertion key and starting roles and activates it"
    )))
}

/// The steps a tenant of `isolation` is set up with.
fn steps_for(isolation: IsolationLevel) -> Vec<SetupStep> {
    let database = match isolation {
        IsolationLevel::Shared => None,
        IsolationLevel::DedicatedSchema
        | IsolationLevel::DedicatedInstance
        | IsolationLevel::DedicatedCluster => Some(SetupStep::Database),
    };
    database.into_iter().chain(EVERY_SETUP).collect()
}

/// A [`TenantSetup`] as storage holds it, read back through
/// [`TenantSetup::reconstitute`].
#[derive(Debug, Clone)]
pub struct TenantSetupRow {
    /// The tenant set up.
    pub tenant_id: TenantId,
    /// The steps its setup holds.
    pub planned: Vec<SetupStep>,
    /// The steps done, in the order they were done.
    pub done: Vec<SetupStep>,
    /// The step that failed and why, if one did.
    pub failed: RunFailure<SetupStep>,
    /// When the setup began.
    pub started_at: OffsetDateTime,
    /// When it last changed.
    pub updated_at: OffsetDateTime,
}

/// A tenant's setup, one per tenant, identified by its tenant.
#[derive(Debug)]
pub struct TenantSetup {
    tenant_id: TenantId,
    run: StepRun<SetupStep>,
    started_at: OffsetDateTime,
    updated_at: OffsetDateTime,
    raised: RaisedEvents,
}

impl TenantSetup {
    /// Begins setting up `tenant`, with the steps its residency asks for.
    ///
    /// # Errors
    ///
    /// [`DomainError::InvalidTransition`] when the tenant is no longer
    /// provisioning: only a new tenant is set up.
    pub fn begin(tenant: &Tenant) -> Result<Self, DomainError> {
        if tenant.status() != TenantStatus::Provisioning {
            return Err(DomainError::invalid_transition(message!(
                "tenant-only-a-tenant-still-provisioning-is",
                "only a tenant still provisioning is set up"
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

    /// Rebuilds a setup from storage.
    ///
    /// # Errors
    ///
    /// [`DomainError::Infrastructure`] when the row's steps are not a
    /// setup's, a step is done before what it waits on or twice, its failed
    /// step was also done or never ready, or it changed before it began.
    pub fn reconstitute(row: TenantSetupRow) -> Result<Self, DomainError> {
        RowCheck::of("tenant setup")
            .in_order(row.started_at, row.updated_at, "changed before it began")
            .finish()?;
        let plan = plan_of(&row.planned).map_err(|_| {
            DomainError::corrupt_row("tenant setup", "steps that are not a setup's")
        })?;
        let run = StepRun::restored(plan, row.done, row.failed).ok_or_else(|| {
            DomainError::corrupt_row(
                "tenant setup",
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

    /// The tenant set up.
    #[must_use]
    pub fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// The steps the setup holds, in their planned order.
    #[must_use]
    pub fn planned(&self) -> Vec<SetupStep> {
        self.run.plan().steps().collect()
    }

    /// The steps done, in the order they were done.
    #[must_use]
    pub fn done(&self) -> &[SetupStep] {
        self.run.done()
    }

    /// The step that failed and why, if one did.
    #[must_use]
    pub fn failure(&self) -> Option<(SetupStep, &UntrustedText)> {
        self.run.failure()
    }

    /// The steps ready to run now. None once a step failed.
    #[must_use]
    pub fn ready(&self) -> Vec<SetupStep> {
        self.run.ready()
    }

    /// How the setup stands.
    #[must_use]
    pub fn outcome(&self) -> RunOutcome {
        self.run.outcome()
    }

    /// The grant that makes the tenant's starting roles, while that step is
    /// ready.
    ///
    /// # Errors
    ///
    /// [`DomainError::InvalidTransition`] unless the starting-roles step is
    /// ready to run.
    pub fn starting_roles_grant(&self) -> Result<StartingRolesGrant, DomainError> {
        if !self.run.ready().contains(&SetupStep::StartingRoles) {
            return Err(DomainError::invalid_transition(message!(
                "tenant-a-tenant-s-starting-roles-are",
                "a tenant's starting roles are made only at that step of its setup"
            )));
        }
        Ok(StartingRolesGrant::for_setup())
    }

    /// Marks `step` done. A step done already stays done.
    ///
    /// # Errors
    ///
    /// [`DomainError::InvalidTransition`] when the setup failed, does not
    /// hold the step, or the step waits on one not yet done.
    pub fn finish(&mut self, step: SetupStep) -> Result<Finished, DomainError> {
        let finished = self.run.finish(step)?;
        if finished == Finished::Now {
            self.touch();
        }
        Ok(finished)
    }

    /// Marks `step` failed for good for `why`: the setup stops. Raises
    /// `tenant.infra_failed`.
    ///
    /// # Errors
    ///
    /// [`DomainError::InvalidTransition`] when the setup failed already, or
    /// the step is done or not ready.
    pub fn fail(&mut self, step: SetupStep, why: UntrustedText) -> Result<(), DomainError> {
        self.run.fail(step, why.clone())?;
        self.touch();
        self.raised.raise_tenant(
            self.tenant_id,
            InfraFailed {
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

/// The row a setup is kept as.
impl From<&TenantSetup> for TenantSetupRow {
    fn from(setup: &TenantSetup) -> Self {
        Self {
            tenant_id: setup.tenant_id,
            planned: setup.planned(),
            done: setup.done().to_vec(),
            failed: setup.run.failed().clone(),
            started_at: setup.started_at,
            updated_at: setup.updated_at,
        }
    }
}

/// A setup's records name the tenant it sets up.
impl RaisesComplete for TenantSetup {
    fn take_events(&mut self) -> Vec<DomainEvent> {
        self.raised.take()
    }
}

/// A setup is identified by the tenant it sets up.
impl Aggregate for TenantSetup {
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

/// How a tenant's setup stands, as the tenant's answer shows it beside its
/// status.
///
/// A tenant whose setup failed stays provisioning: nothing activates it.
/// Its status alone reads the same as one still being set up, so Ann would
/// wait for a tenant that is never coming. This tells the two apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetupStanding {
    /// The tenant is provisioning and its setup is still under way, or not
    /// begun yet.
    Running,
    /// The tenant is provisioning and this step of its setup failed for
    /// good: the setup stopped there.
    Failed(SetupStep),
    /// The tenant left provisioning: its setup finished and activated it,
    /// or the platform stopped it and archived the tenant.
    Over,
}

impl SetupStanding {
    /// How the setup of `tenant` stands, given `setup`, the one kept for it
    /// if any. Only a tenant still provisioning has a setup that matters.
    #[must_use]
    pub fn of(tenant: &Tenant, setup: Option<&TenantSetup>) -> Self {
        if tenant.status() != TenantStatus::Provisioning {
            return Self::Over;
        }
        setup
            .and_then(TenantSetup::failure)
            .map_or(Self::Running, |(step, _)| Self::Failed(step))
    }

    /// Whether `tenant` is one whose setup needs reading to say how it
    /// stands: only one still provisioning does.
    #[must_use]
    pub fn needs_setup(tenant: &Tenant) -> bool {
        tenant.status() == TenantStatus::Provisioning
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::tenant::compliance_limits::ComplianceLimits;
    use crate::domains::tenant::fixtures::{acme_params, active, provisioned};
    use crate::domains::tenant::lifecycle::ProvisionTenantParams;
    use crate::domains::tenant::provisioning::infrastructure::{
        DeploymentRegion, Placement, TenantResidency,
    };
    use crate::shared::model::row_check::refused_as_corrupt;
    use crate::test_support::events::raised_complete_names;
    use crate::types::ActedBy;

    fn with_schema() -> Tenant {
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
        Tenant::provision(params, &ComplianceLimits::default(), ActedBy::Platform).unwrap()
    }

    fn why() -> UntrustedText {
        UntrustedText::record("the key store did not answer")
    }

    fn row_of(setup: &TenantSetup) -> TenantSetupRow {
        TenantSetupRow::from(setup)
    }

    /// A tenant sharing the platform's database is set up without a
    /// database step: its keys and its roles first, activation last.
    #[test]
    fn a_shared_tenant_is_set_up_without_a_database() {
        let setup = TenantSetup::begin(&provisioned()).unwrap();

        assert_eq!(
            setup.planned(),
            [
                SetupStep::SigningKey,
                SetupStep::AssertionKey,
                SetupStep::StartingRoles,
                SetupStep::Activate
            ]
        );
        assert_eq!(
            setup.ready(),
            [
                SetupStep::SigningKey,
                SetupStep::AssertionKey,
                SetupStep::StartingRoles
            ]
        );
    }

    /// A dedicated-schema setup offers only its database step initially;
    /// completing it makes the signing key, assertion key and starting roles ready.
    #[test]
    fn a_tenant_apart_gets_its_database_before_its_key_and_roles() {
        let mut setup = TenantSetup::begin(&with_schema()).unwrap();

        let first = setup.ready();
        setup.finish(SetupStep::Database).unwrap();

        assert_eq!(first, [SetupStep::Database]);
        assert_eq!(
            setup.ready(),
            [
                SetupStep::SigningKey,
                SetupStep::AssertionKey,
                SetupStep::StartingRoles
            ]
        );
    }

    /// Starting setup for an active tenant is rejected as an invalid transition.
    #[test]
    fn an_active_tenant_is_not_set_up() {
        let begun = TenantSetup::begin(&active());

        assert!(matches!(begun, Err(DomainError::InvalidTransition(_))));
    }

    /// Activation comes last: it is ready once every other step is done,
    /// and the setup is done after it.
    #[test]
    fn activation_comes_once_every_other_step_is_done() {
        let mut setup = TenantSetup::begin(&provisioned()).unwrap();

        setup.finish(SetupStep::SigningKey).unwrap();
        setup.finish(SetupStep::AssertionKey).unwrap();
        let before_roles = setup.ready();
        setup.finish(SetupStep::StartingRoles).unwrap();
        let after_roles = setup.ready();
        setup.finish(SetupStep::Activate).unwrap();

        assert!(!before_roles.contains(&SetupStep::Activate));
        assert_eq!(after_roles, [SetupStep::Activate]);
        assert_eq!(setup.outcome(), RunOutcome::Done);
    }

    /// Starting-role authority is unavailable before the database step
    /// and after roles finish, but is issued while the roles step is ready.
    #[test]
    fn the_starting_roles_grant_is_handed_out_only_at_its_step() {
        let mut setup = TenantSetup::begin(&with_schema()).unwrap();

        let before_database = setup.starting_roles_grant();
        setup.finish(SetupStep::Database).unwrap();
        let at_its_step = setup.starting_roles_grant();
        setup.finish(SetupStep::StartingRoles).unwrap();
        let after = setup.starting_roles_grant();

        assert!(before_database.is_err());
        assert!(at_its_step.is_ok());
        assert!(after.is_err());
    }

    /// A step that failed for good stops the setup, names the step and its
    /// reason, and goes on record for the operators.
    #[test]
    fn a_failed_step_stops_the_setup_and_is_recorded() {
        let mut setup = TenantSetup::begin(&provisioned()).unwrap();

        setup.fail(SetupStep::SigningKey, why()).unwrap();

        assert_eq!(setup.outcome(), RunOutcome::Failed);
        assert!(setup.ready().is_empty());
        assert_eq!(raised_complete_names(&mut setup), ["tenant.infra_failed"]);
    }

    /// A setup reads back as it was kept, and has raised nothing.
    #[test]
    fn a_kept_setup_reads_back() {
        let mut setup = TenantSetup::begin(&with_schema()).unwrap();
        setup.finish(SetupStep::Database).unwrap();

        let mut stored = TenantSetup::reconstitute(row_of(&setup)).unwrap();

        assert_eq!(stored.done(), [SetupStep::Database]);
        assert_eq!(stored.ready(), setup.ready());
        assert!(raised_complete_names(&mut stored).is_empty());
    }

    /// Reconstitution rejects setup rows with premature activation, missing
    /// key steps or an update time earlier than the setup's start.
    #[test]
    fn a_row_that_cannot_have_happened_is_refused() {
        let setup = TenantSetup::begin(&provisioned()).unwrap();
        let skipped = TenantSetupRow {
            done: vec![SetupStep::Activate],
            ..row_of(&setup)
        };
        let keyless = TenantSetupRow {
            planned: vec![SetupStep::StartingRoles, SetupStep::Activate],
            ..row_of(&setup)
        };
        let unasserted = TenantSetupRow {
            planned: vec![
                SetupStep::SigningKey,
                SetupStep::StartingRoles,
                SetupStep::Activate,
            ],
            ..row_of(&setup)
        };
        let backwards = TenantSetupRow {
            updated_at: setup.started_at - time::Duration::SECOND,
            ..row_of(&setup)
        };

        for row in [skipped, keyless, unasserted, backwards] {
            assert!(refused_as_corrupt(&TenantSetup::reconstitute(row)));
        }
    }

    /// Acme's tenant is provisioning and its signing key failed for good.
    /// Its answer says the setup failed at that step, not that it is still
    /// being set up.
    #[test]
    fn a_failed_setup_stands_failed_at_its_step() {
        let tenant = provisioned();
        let mut setup = TenantSetup::begin(&tenant).unwrap();
        setup.fail(SetupStep::SigningKey, why()).unwrap();

        let standing = SetupStanding::of(&tenant, Some(&setup));

        assert_eq!(standing, SetupStanding::Failed(SetupStep::SigningKey));
    }

    /// Acme's tenant is provisioning, its setup half done or not begun
    /// yet. It stands running.
    #[test]
    fn a_setup_under_way_or_not_begun_stands_running() {
        let tenant = provisioned();
        let mut setup = TenantSetup::begin(&tenant).unwrap();
        setup.finish(SetupStep::SigningKey).unwrap();

        assert_eq!(
            SetupStanding::of(&tenant, Some(&setup)),
            SetupStanding::Running
        );
        assert_eq!(SetupStanding::of(&tenant, None), SetupStanding::Running);
    }

    /// Acme's tenant is active. Its setup is over, whatever was kept of it,
    /// and only a provisioning tenant needs its setup read.
    #[test]
    fn an_active_tenants_setup_is_over() {
        let tenant = active();

        assert_eq!(SetupStanding::of(&tenant, None), SetupStanding::Over);
        assert!(!SetupStanding::needs_setup(&tenant));
        assert!(SetupStanding::needs_setup(&provisioned()));
    }
}
