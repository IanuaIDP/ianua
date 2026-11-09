//! Start clone: copy one tenant's setup into another tenant of the same
//! organization.
//!
//! Starting records what is to be copied and queues the job that copies
//! it, in the same unit of work, so a started clone always has its job. A
//! worker runs the copy part by part
//! ([`RunUseCase`](crate::use_cases::tenant::clones::RunUseCase)).

use std::sync::Arc;

use ianua_domain::domains::tenant::clone::{ClonePart, TenantClone};
use ianua_domain::message;
use ianua_domain::shared::events::raised::RaisesComplete as _;
use ianua_domain::types::{TenantCloneId, TenantId};

use crate::acting::{OperatorAuthorities, OrgActors};
use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::tenant::{TenantCloneStore, TenantStore};
use crate::use_case::Command;
use crate::use_cases::tenant::clones::CloneRuns;
use crate::use_cases::tenant::lifecycle::steward::{Acting, StewardSources, TenantSteward};

/// Which tenant to copy into which, and what of it.
pub struct StartRequest {
    /// The tenant copied from.
    pub source: TenantId,
    /// The tenant filled.
    pub target: TenantId,
    /// The parts of the source's setup to copy.
    pub parts: Vec<ClonePart>,
}

/// The ports [`StartUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct StartPorts {
    /// Loads the source and destination workspaces for the copy.
    pub tenant_store: Arc<dyn TenantStore>,
    /// Where clones are kept.
    pub clone_store: Arc<dyn TenantCloneStore>,
    /// Who acts on an organization.
    pub org_actors: Arc<dyn OrgActors>,
    /// What an operator may do on the platform.
    pub operator_authorities: Arc<dyn OperatorAuthorities>,
    /// Queues the job that copies the clone.
    pub runs: CloneRuns,
}

/// Starts copying one tenant's setup into another of its organization.
pub struct StartUseCase {
    ports: StartPorts,
}

impl StartUseCase {
    /// A use case writing through `ports`.
    #[must_use]
    pub fn new(ports: StartPorts) -> Self {
        Self { ports }
    }

    /// Refuses a second clone into `target` while one still copies into it:
    /// two copies writing one tenant at once would leave it a mix of both.
    async fn ensure_target_free(&self, target: &TenantId) -> Result<(), AppError> {
        let busy = self
            .ports
            .clone_store
            .copying_into(target)
            .await
            .or_internal()?;
        if busy {
            return Err(AppError::Conflict(message!(
                "tenant-a-clone-into-this-tenant-is",
                "a clone into this tenant is still copying"
            )));
        }
        Ok(())
    }
}

impl Command for StartUseCase {
    type Caller = TenantSteward;
    type Input = StartRequest;
    type Output = Result<TenantCloneId, AppError>;

    /// Starts copying the parts `request` names from its source tenant into
    /// its target, records `tenant.clone_started` under the target, and
    /// returns the clone's id for following its progress.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `Forbidden` without tenant-creation rights, across organizations or for a disabled operator.
    /// - `AppError::NotFound` for missing tenants or tenants outside the member's organization.
    /// - `AppError::Conflict` for a closed source, unfillable target or ongoing copy; `Domain` for identical tenants or empty/duplicate parts.
    /// - `AppError::Internal` on persistence or audit failure.
    async fn execute(
        &self,
        caller: &TenantSteward,
        auditor: &RequestAuditor,
        request: StartRequest,
    ) -> Result<TenantCloneId, AppError> {
        let sources = StewardSources {
            org_actors: self.ports.org_actors.as_ref(),
            operator_authorities: self.ports.operator_authorities.as_ref(),
        };
        let acting = Acting::resolve(sources, caller).await?;
        let tenants = self.ports.tenant_store.as_ref();
        let source = acting.reached_tenant(tenants, &request.source).await?;
        let target = acting.reached_tenant(tenants, &request.target).await?;
        let mut clone =
            acting.decide(|by| TenantClone::start(request.parts, &source, &target, by))?;
        self.ensure_target_free(target.id()).await?;
        self.ports.clone_store.save(&clone).await.or_internal()?;
        self.ports.runs.queue(*clone.id(), *target.id()).await?;
        auditor
            .dispatch_by(&acting.actor(), clone.take_events())
            .await
            .or_internal()?;
        Ok(*clone.id())
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::organization::members::membership::OrgRole;
    use ianua_domain::domains::tenant::lifecycle::Tenant;
    use ianua_domain::types::OrganizationId;

    use super::*;
    use crate::test_support::acting::{FakeOrgActors, Refusal};
    use crate::test_support::operator::test_operator_caller;
    use crate::test_support::scheduling::FakeJobQueue;
    use crate::test_support::tenant::{
        FakeTenantCloneStore, FakeTenantStore, clone_runs, test_tenant_for_ctx, test_tenant_in,
    };
    use crate::test_support::{
        FakeEventDispatcher, block_on, test_auditor, test_ctx, test_org_caller,
    };
    use crate::use_cases::tenant::clones::RUN_CLONE_JOB;

    struct Setup {
        uc: StartUseCase,
        clones: Arc<FakeTenantCloneStore>,
        audit: Arc<FakeEventDispatcher>,
        source: TenantId,
        target: TenantId,
    }

    impl Setup {
        fn with(target: Tenant, actors: FakeOrgActors) -> Self {
            let source = test_tenant_for_ctx();
            let ids = (*source.id(), *target.id());
            let clones = Arc::new(FakeTenantCloneStore::empty());
            Self {
                uc: StartUseCase::new(StartPorts {
                    tenant_store: Arc::new(FakeTenantStore::holding_all([source, target])),
                    clone_store: clones.clone(),
                    org_actors: Arc::new(actors),
                    ..StartPorts::fakes()
                }),
                clones,
                audit: Arc::new(FakeEventDispatcher::new()),
                source: ids.0,
                target: ids.1,
            }
        }

        fn new() -> Self {
            Self::with(staging(), FakeOrgActors::in_role(OrgRole::Owner))
        }

        /// Starts the configured copy with the supplied caller's authority.
        fn start_as(&self, caller: &TenantSteward) -> Result<TenantCloneId, AppError> {
            let request = StartRequest {
                source: self.source,
                target: self.target,
                parts: vec![ClonePart::Settings, ClonePart::Routes],
            };
            block_on(
                self.uc
                    .execute(caller, &test_auditor(self.audit.clone()), request),
            )
        }

        fn start(&self) -> Result<TenantCloneId, AppError> {
            self.start_as(&TenantSteward::Member(test_org_caller()))
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }
    }

    /// Ann copies production into staging. The job that copies it is
    /// queued with the clone, for staging, so a worker takes it up even if
    /// the record of the start never reaches one.
    #[test]
    fn a_started_clone_has_its_copy_job_queued() {
        let mut setup = Setup::new();
        let queue = Arc::new(FakeJobQueue::new());
        setup.uc.ports.runs = clone_runs(queue.clone());

        setup.start().unwrap();

        let jobs = queue.jobs_of(RUN_CLONE_JOB);
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].tenant_id(), Some(&setup.target));
    }

    /// Acme's staging tenant, beside the production tenant `test_ctx` acts in.
    fn staging() -> Tenant {
        test_tenant_in(test_ctx().organization_id(), "staging", "staging.acme.com")
    }

    /// Ann, an owner of Acme, copies production's settings and routes into
    /// staging. The clone is kept, copying, and its start recorded.
    #[test]
    fn a_clone_is_kept_and_recorded() {
        let setup = Setup::new();

        let id = setup.start().unwrap();

        let clone = setup.clones.stored(&id).unwrap();
        assert_eq!(clone.remaining(), [ClonePart::Settings, ClonePart::Routes]);
        assert_eq!(setup.recorded(), vec!["tenant.clone_started"]);
    }

    /// Bob, an operator, starts a clone for the platform. It is kept.
    #[test]
    fn the_platform_starts_a_clone() {
        let setup = Setup::new();

        let id = setup
            .start_as(&TenantSteward::Platform(test_operator_caller()))
            .unwrap();

        assert!(setup.clones.stored(&id).is_some());
    }

    /// Ann starts a second clone into staging while the first still copies.
    /// It is refused, so two copies never write one tenant at once.
    #[test]
    fn a_second_clone_into_a_busy_tenant_is_refused() {
        let setup = Setup::new();
        setup.start().unwrap();

        let result = setup.start();

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert_eq!(setup.clones.count(), 1);
    }

    /// A member cannot clone into another organization's tenant. The target
    /// is not found and no clone is saved.
    #[test]
    fn a_target_of_another_organization_is_not_found() {
        let foreign = test_tenant_in(OrganizationId::new(), "evil", "evil.example.com");
        let setup = Setup::with(foreign, FakeOrgActors::in_role(OrgRole::Owner));

        let result = setup.start();

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(setup.clones.count(), 0);
    }

    /// A member without tenant-creation rights cannot start a clone.
    /// No clone is saved and no start is recorded.
    #[test]
    fn a_member_who_may_not_make_tenants_is_refused() {
        let setup = Setup::with(staging(), FakeOrgActors::in_role(OrgRole::Member));

        let result = setup.start();

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(setup.clones.count(), 0);
        assert!(setup.recorded().is_empty());
    }

    /// A signed-out session cannot start a clone. No clone is saved.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let setup = Setup::with(staging(), FakeOrgActors::refusing(Refusal::SignedOut));

        let result = setup.start();

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(setup.clones.count(), 0);
    }
}
