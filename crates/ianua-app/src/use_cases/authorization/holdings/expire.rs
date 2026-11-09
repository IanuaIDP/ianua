//! Expire holdings: the background sweep that clears away role
//! assignments and group memberships whose end has passed.
//!
//! Each already counts for nothing from its end on, whether or not the
//! sweep has run; clearing it keeps the records honest and says so in the
//! audit trail, by the platform.

use std::sync::Arc;

use ianua_domain::domains::authorization::group::GroupMembership;
use ianua_domain::domains::authorization::role::RoleAssignment;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::ActorRef;
use time::OffsetDateTime;

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::authorization::{
    AssignmentPosition, GroupMembershipStore, GroupStore, HOLDING_BATCH_SIZE, HoldingBatch,
    MembershipPosition, RoleAssignmentStore, RoleStore,
};
use crate::ports::runtime::UnitOfWork;
use crate::ports::shared::AuditLabelResolver;
use crate::ports::tenant::TenantStore;
use crate::services::lookup::existing_role;
use crate::services::tenant_batches::TenantBatches;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::authorization::audit_labels::tenant_principal_label;
use crate::use_cases::authorization::lookup::existing_group;
use crate::use_cases::authorization::sweeps::swept;

/// The ports [`ExpireUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ExpirePorts {
    /// Lists the tenants to look in.
    pub tenant_store: Arc<dyn TenantStore>,
    /// Finds and removes the role assignments that ran out.
    pub assignment_store: Arc<dyn RoleAssignmentStore>,
    /// Finds and removes the memberships that ran out.
    pub membership_store: Arc<dyn GroupMembershipStore>,
    /// Loads the role an assignment gave.
    pub role_store: Arc<dyn RoleStore>,
    /// Loads the group a membership was of.
    pub group_store: Arc<dyn GroupStore>,
    /// Names the holder in the audit record.
    pub audit_label_resolver: Arc<dyn AuditLabelResolver>,
    /// Keeps each removal and the record of it together.
    pub unit_of_work: Arc<dyn UnitOfWork>,
}

/// Clears away every role assignment and membership that ran out.
pub struct ExpireUseCase {
    ports: ExpirePorts,
}

/// One tenant the sweep works in, with the auditor its records go through.
struct InTenant<'a> {
    /// The scope whose elapsed grants and memberships are removed.
    tenant: ScopedTenant,
    /// Its auditor, attributing records to the system.
    auditor: &'a RequestAuditor,
    /// The time the sweep compares each end with.
    now: OffsetDateTime,
}

impl ExpireUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: ExpirePorts) -> Self {
        Self { ports }
    }

    /// How many of one tenant's holdings were cleared.
    async fn expire_in(&self, within: &InTenant<'_>) -> Result<u64, AppError> {
        let assignments = self.expire_assignments(within).await?;
        let memberships = self.expire_memberships(within).await?;
        Ok(assignments.saturating_add(memberships))
    }

    /// Walks expired assignments with a complete key, advancing past failed
    /// removals so each is attempted only once in this sweep.
    async fn expire_assignments(&self, within: &InTenant<'_>) -> Result<u64, AppError> {
        let store = self.ports.assignment_store.as_ref();
        let unit = self.ports.unit_of_work.as_ref();
        let mut batch = HoldingBatch {
            now: within.now,
            after: None,
        };
        let mut cleared: u64 = 0;
        loop {
            let rows = store
                .find_lapsed(&within.tenant, &batch)
                .await
                .or_internal()?;
            let exhausted = rows.len() < HOLDING_BATCH_SIZE;
            let Some(next) = rows.last().and_then(AssignmentPosition::of) else {
                return Ok(cleared);
            };
            for assignment in rows {
                let work = self.lapse_assignment(within, assignment);
                cleared = cleared.saturating_add(swept(unit, "role assignment", work).await);
            }
            if exhausted {
                return Ok(cleared);
            }
            batch.after = Some(next);
        }
    }

    /// Walks expired memberships with a complete key, keeping the original
    /// cutoff and advancing past failed removals as well as successful ones.
    async fn expire_memberships(&self, within: &InTenant<'_>) -> Result<u64, AppError> {
        let store = self.ports.membership_store.as_ref();
        let unit = self.ports.unit_of_work.as_ref();
        let mut batch = HoldingBatch {
            now: within.now,
            after: None,
        };
        let mut cleared: u64 = 0;
        loop {
            let rows = store
                .find_lapsed(&within.tenant, &batch)
                .await
                .or_internal()?;
            let exhausted = rows.len() < HOLDING_BATCH_SIZE;
            let Some(next) = rows.last().and_then(MembershipPosition::of) else {
                return Ok(cleared);
            };
            for membership in rows {
                let work = self.lapse_membership(within, membership);
                cleared = cleared.saturating_add(swept(unit, "group membership", work).await);
            }
            if exhausted {
                return Ok(cleared);
            }
            batch.after = Some(next);
        }
    }

    /// Clears `assignment` away and records it, by the platform. One given
    /// again since the sweep read it is in force once more: it is left,
    /// and no end is recorded for it.
    async fn lapse_assignment(
        &self,
        within: &InTenant<'_>,
        mut assignment: RoleAssignment<ResolvedTenant>,
    ) -> Result<(), AppError> {
        let tenant = &within.tenant;
        let roles = self.ports.role_store.as_ref();
        let role = existing_role(roles, tenant, assignment.role_id()).await?;
        let resolver = self.ports.audit_label_resolver.as_ref();
        let label = tenant_principal_label(resolver, tenant, assignment.principal()).await?;
        assignment
            .lapse(&role, within.now, label)
            .map_err(AppError::from_domain)?;
        let removed = self
            .ports
            .assignment_store
            .remove_lapsed(tenant, &assignment, within.now)
            .await
            .or_internal()?;
        if !removed {
            return Ok(());
        }
        within
            .auditor
            .dispatch_by(&ActorRef::System, assignment.take_events(tenant))
            .await
            .or_internal()
    }

    /// Clears `membership` away and records it, by the platform. A place
    /// given again since the sweep read it is in force once more: it is
    /// left, and no end is recorded for it.
    async fn lapse_membership(
        &self,
        within: &InTenant<'_>,
        mut membership: GroupMembership<ResolvedTenant>,
    ) -> Result<(), AppError> {
        let tenant = &within.tenant;
        let groups = self.ports.group_store.as_ref();
        let group = existing_group(groups, tenant, membership.group_id()).await?;
        let resolver = self.ports.audit_label_resolver.as_ref();
        let label = tenant_principal_label(resolver, tenant, membership.principal()).await?;
        membership
            .lapse(&group, within.now, label)
            .map_err(AppError::from_domain)?;
        let removed = self
            .ports
            .membership_store
            .remove_lapsed(tenant, &membership, within.now)
            .await
            .or_internal()?;
        if !removed {
            return Ok(());
        }
        within
            .auditor
            .dispatch_by(&ActorRef::System, membership.take_events(tenant))
            .await
            .or_internal()
    }
}

impl Command for ExpireUseCase {
    type Caller = ();
    type Input = OffsetDateTime;
    type Output = Result<u64, AppError>;

    /// Clears away every role assignment and group membership in every
    /// tenant whose end passed by `now`, and returns how many went.
    ///
    /// Each is kept together with its record as one unit. One that cannot
    /// be cleared is logged and tried again on the next run; it does not
    /// stop the others, and it grants nothing meanwhile. Each tenant's
    /// records go through `auditor` scoped to that tenant, attributed to
    /// the system.
    ///
    /// # Errors
    ///
    /// - `AppError::Internal` when the tenants, or a tenant's ended
    ///   holdings, cannot be read.
    async fn execute(
        &self,
        (): &(),
        auditor: &RequestAuditor,
        now: OffsetDateTime,
    ) -> Result<u64, AppError> {
        let mut cleared: u64 = 0;
        let mut tenants = TenantBatches::over(self.ports.tenant_store.as_ref());
        while let Some(batch) = tenants.next_ids().await? {
            for tenant_id in batch {
                let tenant_auditor = auditor.with_tenant(tenant_id);
                let within = InTenant {
                    tenant: ScopedTenant::for_background(tenant_id),
                    auditor: &tenant_auditor,
                    now,
                };
                cleared = cleared.saturating_add(self.expire_in(&within).await?);
            }
        }
        Ok(cleared)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::group::GroupPlace;
    use ianua_domain::shared::clock;
    use ianua_domain::types::{Expiry, GroupId, PrincipalRef, RoleId, UserId};
    use time::Duration;

    use super::*;
    use crate::ports::runtime::Settlement;
    use crate::test_support::authorization::{
        FakeGroupMembershipStore, FakeGroupStore, FakeRoleAssignmentStore, FakeRoleStore,
        stored_assignment_until, stored_group, stored_membership_until, stored_role,
    };
    use crate::test_support::tenant::{FakeTenantStore, test_tenant_for_ctx};
    use crate::test_support::{
        FakeEventDispatcher, RecordingUnitOfWork, block_on, test_auditor, test_ctx,
    };

    /// Acme's stores, with the "on-call" role and the "Production" group,
    /// and what watches the sweep.
    struct Acme {
        roles: Arc<FakeRoleStore>,
        groups: Arc<FakeGroupStore>,
        assignments: Arc<FakeRoleAssignmentStore>,
        memberships: Arc<FakeGroupMembershipStore>,
        unit: Arc<RecordingUnitOfWork>,
        sink: Arc<FakeEventDispatcher>,
    }

    impl Acme {
        /// Bob held "on-call" and sat in "Production" until `ended`; Ann
        /// holds both with no end.
        fn holding_until(ended: Expiry) -> Self {
            let tenant = test_ctx().tenant_id();
            let on_call = stored_role("on-call", Vec::new(), Vec::new());
            let production = stored_group("Production", GroupPlace::TopLevel, Vec::new());
            let bob = PrincipalRef::User(UserId::new());
            let ann = PrincipalRef::User(UserId::new());
            let assignments = [
                stored_assignment_until(bob, *on_call.id(), ended),
                stored_assignment_until(ann, *on_call.id(), Expiry::Never),
            ];
            let memberships = [
                stored_membership_until(bob, *production.id(), ended),
                stored_membership_until(ann, *production.id(), Expiry::Never),
            ];
            Self {
                roles: Arc::new(FakeRoleStore::holding(tenant, [on_call])),
                groups: Arc::new(FakeGroupStore::holding(tenant, [production])),
                assignments: Arc::new(FakeRoleAssignmentStore::holding(tenant, assignments)),
                memberships: Arc::new(FakeGroupMembershipStore::holding(tenant, memberships)),
                unit: Arc::new(RecordingUnitOfWork::default()),
                sink: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn sweep(&self) -> u64 {
            let use_case = ExpireUseCase::new(ExpirePorts {
                tenant_store: Arc::new(FakeTenantStore::holding(test_tenant_for_ctx())),
                assignment_store: self.assignments.clone(),
                membership_store: self.memberships.clone(),
                role_store: self.roles.clone(),
                group_store: self.groups.clone(),
                unit_of_work: self.unit.clone(),
                ..ExpirePorts::fakes()
            });
            let auditor = test_auditor(self.sink.clone());
            block_on(use_case.execute(&(), &auditor, clock::now())).unwrap()
        }
    }

    /// More than one batch of each holding expires. Missing resources leave
    /// their earliest holdings pending, but later batches complete once and
    /// the next sweep retries only the failures, with every read bounded.
    #[test]
    fn holdings_expiry_reads_bounded_batches_and_progresses_past_failures() {
        let acme = large_expiry_backlog();

        assert_eq!(acme.sweep(), 1002);
        assert_eq!((acme.assignments.count(), acme.memberships.count()), (1, 1));
        assert_eq!(acme.sink.records.lock().unwrap().len(), 1002);
        assert_eq!(acme.sweep(), 0);
        assert_eq!(acme.sink.records.lock().unwrap().len(), 1002);
        for reads in [
            acme.assignments.lapsed_reads(),
            acme.memberships.lapsed_reads(),
        ] {
            assert!(
                reads.iter().all(|count| *count <= 500),
                "unbounded reads: {reads:?}"
            );
            assert_eq!(reads.iter().sum::<usize>(), 503);
        }
    }

    /// One missing resource precedes 501 valid expired holdings of each kind.
    fn large_expiry_backlog() -> Acme {
        let tenant = test_ctx().tenant_id();
        let role = stored_role("on-call", Vec::new(), Vec::new());
        let group = stored_group("Production", GroupPlace::TopLevel, Vec::new());
        let expired = Expiry::At(clock::now() - Duration::hours(1));
        let earlier = Expiry::At(clock::now() - Duration::hours(2));
        let mut assignments = vec![stored_assignment_until(
            PrincipalRef::User(UserId::new()),
            RoleId::new(),
            earlier,
        )];
        let mut memberships = vec![stored_membership_until(
            PrincipalRef::User(UserId::new()),
            GroupId::new(),
            earlier,
        )];
        for _ in 0..501 {
            let person = PrincipalRef::User(UserId::new());
            assignments.push(stored_assignment_until(person, *role.id(), expired));
            memberships.push(stored_membership_until(person, *group.id(), expired));
        }
        Acme {
            roles: Arc::new(FakeRoleStore::holding(tenant, [role])),
            groups: Arc::new(FakeGroupStore::holding(tenant, [group])),
            assignments: Arc::new(FakeRoleAssignmentStore::holding(tenant, assignments)),
            memberships: Arc::new(FakeGroupMembershipStore::holding(tenant, memberships)),
            unit: Arc::new(RecordingUnitOfWork::default()),
            sink: Arc::new(FakeEventDispatcher::new()),
        }
    }

    /// Bob's night on call ended an hour ago. The sweep clears his role and
    /// his place in "Production", records each, and leaves Ann's alone.
    #[test]
    fn ended_holdings_are_cleared_and_recorded() {
        let acme = Acme::holding_until(Expiry::At(clock::now() - Duration::hours(1)));

        let cleared = acme.sweep();

        assert_eq!(cleared, 2);
        assert_eq!(acme.assignments.count(), 1);
        assert_eq!(acme.memberships.count(), 1);
        assert_eq!(
            acme.sink.records.lock().unwrap().as_slice(),
            [
                "authorization.role_assignment_expired",
                "authorization.group_membership_expired"
            ]
        );
        assert_eq!(
            acme.unit.settlements(),
            [Settlement::Commit, Settlement::Commit]
        );
    }

    /// Bob's night on call ends tomorrow. The sweep clears nothing and
    /// records nothing.
    #[test]
    fn holdings_still_running_are_kept() {
        let acme = Acme::holding_until(Expiry::At(clock::now() + Duration::days(1)));

        let cleared = acme.sweep();

        assert_eq!(cleared, 0);
        assert_eq!(acme.assignments.count(), 2);
        assert_eq!(acme.memberships.count(), 2);
        assert!(acme.sink.records.lock().unwrap().is_empty());
    }
}
