//! Approve access request: say yes to someone's request for a role or a
//! group, and give it to them until the end the request asked for.
//!
//! Only someone who could give the role or the group by hand approves, and
//! never the person who asked, through any of their accounts. What is given
//! is checked against the tenant's separation of duties like any grant. A
//! hold of the same that ran out and the sweep has not cleared is cleared
//! and its end recorded by the platform first.

use std::sync::Arc;

use ianua_domain::domains::authorization::access_request::{
    AccessRequest, ensure_answers_requests,
};
use ianua_domain::domains::authorization::group::GroupMembership;
use ianua_domain::domains::authorization::holding::HeldAccess;
use ianua_domain::domains::authorization::role::RoleAssignment;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::clock;
use ianua_domain::shared::events::event::DomainEvent;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{AccessRequestId, PrincipalRef};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrConflict, OrInternal};
use crate::ports::authorization::{
    AccessRecordStore, AccessRequestStore, GroupMembershipStore, GroupStore, RoleAssignmentStore,
    RoleStore, SeparationRuleStore,
};
use crate::services::authorization::duties::{DutySources, Granting, ensure_duties_kept};
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::authorization::access_requests::lookup::{
    ANSWERED_MEANWHILE, Asked, AskedSources, existing_asked, existing_request, requester_label,
};
use crate::use_cases::authorization::holdings::lapsed::{RanOut, place_cleared, role_cleared};

/// The ports [`ApproveUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ApprovePorts {
    /// Loads and saves the request.
    pub request_store: Arc<dyn AccessRequestStore>,
    /// Loads the role asked for.
    pub role_store: Arc<dyn RoleStore>,
    /// Loads the group asked for.
    pub group_store: Arc<dyn GroupStore>,
    /// Reads who holds what, for what a group brings and the separation
    /// check.
    pub access_records: Arc<dyn AccessRecordStore>,
    /// Saves the role given.
    pub assignment_store: Arc<dyn RoleAssignmentStore>,
    /// Saves the place in the group given.
    pub membership_store: Arc<dyn GroupMembershipStore>,
    /// The tenant's separation-of-duties rules.
    pub separation_rules: Arc<dyn SeparationRuleStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Approves an access request of the caller's tenant.
pub struct ApproveUseCase {
    ports: ApprovePorts,
}

impl ApproveUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: ApprovePorts) -> Self {
        Self { ports }
    }

    /// The role or group `request` asks for, as the tenant holds it now.
    ///
    /// # Errors
    ///
    /// - `AppError::NotFound` when the role or group is gone.
    /// - `AppError::Internal` on persistence failure.
    async fn asked_for(
        &self,
        tenant: &ScopedTenant,
        request: &AccessRequest<ResolvedTenant>,
    ) -> Result<Asked, AppError> {
        let sources = AskedSources::of(
            self.ports.role_store.as_ref(),
            self.ports.group_store.as_ref(),
            self.ports.access_records.as_ref(),
        );
        existing_asked(sources, tenant, request.asked()).await
    }

    /// Refuses giving `asked` to the asker of `request` when they would then
    /// hold both roles of a separation-of-duties rule.
    ///
    /// # Errors
    ///
    /// - `AppError::Conflict` when a separation-of-duties rule is broken.
    /// - `AppError::Internal` on persistence failure.
    async fn ensure_duties_kept(
        &self,
        tenant: &ScopedTenant,
        request: &AccessRequest<ResolvedTenant>,
        asked: &Asked,
    ) -> Result<(), AppError> {
        let principal = request.requester().principal();
        let duties = DutySources::of(
            self.ports.access_records.as_ref(),
            self.ports.separation_rules.as_ref(),
        );
        ensure_duties_kept(duties, tenant, granting(asked, principal)).await
    }

    /// The record of the end of the asker's hold of `asked` that ran out and
    /// the sweep has not cleared, cleared now so what the approval gives
    /// does not replace it unrecorded.
    async fn ran_out(
        &self,
        tenant: &ScopedTenant,
        request: &AccessRequest<ResolvedTenant>,
        asked: &Asked,
    ) -> Result<Vec<DomainEvent>, AppError> {
        let principal = request.requester().principal();
        let ran_out = RanOut {
            principal: &principal,
            label: requester_label(request),
            now: clock::now(),
        };
        match asked {
            Asked::Role(role) => {
                role_cleared(self.ports.assignment_store.as_ref(), tenant, role, ran_out).await
            }
            Asked::Group(group, _) => {
                place_cleared(self.ports.membership_store.as_ref(), tenant, group, ran_out).await
            }
        }
    }

    /// Saves the approved request and what it gives.
    async fn save(
        &self,
        tenant: &ScopedTenant,
        request: &AccessRequest<ResolvedTenant>,
        holding: &HeldAccess<ResolvedTenant>,
    ) -> Result<(), AppError> {
        self.ports
            .request_store
            .save(tenant, request)
            .await
            .or_conflict(message!(
                "authorization-the-request-was-answered-withdrawn-or",
                ANSWERED_MEANWHILE
            ))?;
        let saved = match holding {
            HeldAccess::Role(assignment) => {
                self.ports.assignment_store.save(tenant, assignment).await
            }
            HeldAccess::Membership(membership) => {
                self.ports.membership_store.save(tenant, membership).await
            }
        };
        saved.or_internal()
    }
}

impl Command for ApproveUseCase {
    type Caller = CallerContext;
    type Input = AccessRequestId;
    type Output = Result<AccessRequest<ResolvedTenant>, AppError>;

    /// Approves request `id` for the caller, gives the asker what it asked
    /// for until its end, counted from now, and records both.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `Forbidden` without role/group assignment rights, before reading the request.
    /// - `AppError::NotFound` for a missing request, role or group; `Forbidden` for self-approval or access the caller could not grant directly.
    /// - `AppError::Conflict` for expiry, a concurrent answer/withdrawal, or a separation-of-duties violation.
    /// - `AppError::Domain` for an already answered/withdrawn request; `Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        id: AccessRequestId,
    ) -> Result<AccessRequest<ResolvedTenant>, AppError> {
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        ensure_answers_requests(&authority.standing()).map_err(AppError::from_domain)?;
        let store = self.ports.request_store.as_ref();
        let mut request = existing_request(store, &tenant, &id).await?;
        let asked = self.asked_for(&tenant, &request).await?;
        request
            .approve(&asked.grant(), &authority)
            .map_err(AppError::from_domain)?;
        let mut holding = granted(&request, &asked)?;
        self.ensure_duties_kept(&tenant, &request, &asked).await?;
        let ended = self.ran_out(&tenant, &request, &asked).await?;

        self.save(&tenant, &request, &holding).await?;
        auditor.dispatch(&ended).await.or_internal()?;
        let mut events = request.take_events(&tenant);
        events.extend(holding.take_events(&tenant));
        auditor
            .dispatch_by(&authority.actor(), events)
            .await
            .or_internal()?;
        Ok(request)
    }
}

/// What the approved `request` gives, of `asked`.
fn granted(
    request: &AccessRequest<ResolvedTenant>,
    asked: &Asked,
) -> Result<HeldAccess<ResolvedTenant>, AppError> {
    let label = requester_label(request);
    let holding = match asked {
        Asked::Role(role) => {
            RoleAssignment::from_approved_request(request, role, label).map(HeldAccess::Role)
        }
        Asked::Group(group, _) => GroupMembership::from_approved_request(request, group, label)
            .map(HeldAccess::Membership),
    };
    holding.map_err(AppError::from_domain)
}

/// The grant `asked` makes to `principal`, for the separation check.
fn granting(asked: &Asked, principal: PrincipalRef) -> Granting<'_> {
    match asked {
        Asked::Role(role) => Granting::Role {
            principal,
            role: role.id(),
        },
        Asked::Group(_, conferred) => Granting::Membership {
            principal,
            conferred,
        },
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::access_request::{AccessRequestStatus, AskedAccess};
    use ianua_domain::domains::authorization::group::GroupPlace;
    use ianua_domain::shared::clock;
    use ianua_domain::types::{Expiry, GroupId, RoleId};
    use time::{Duration, OffsetDateTime};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authorization::{
        AccessSources, FakeAccessRecordStore, FakeAccessRequestStore, FakeGroupStore,
        FakeRoleAssignmentStore, FakeRoleStore, FakeSeparationRuleStore, pending_request_by,
        separation_between, stored_assignment, stored_assignment_until, stored_group, stored_role,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// The person every fake caller signs in as.
    const CALLER: &str = "caller@example.test";

    /// A tenant with the "production" role, and the "Production" group
    /// carrying it.
    struct Tenant {
        role_id: RoleId,
        group_id: GroupId,
        requests: Arc<FakeAccessRequestStore>,
        sources: AccessSources,
    }

    fn tenant() -> Tenant {
        let tenant = test_ctx().tenant_id();
        let role = stored_role("production", Vec::new(), Vec::new());
        let group = stored_group("Production", GroupPlace::TopLevel, vec![*role.id()]);
        Tenant {
            role_id: *role.id(),
            group_id: *group.id(),
            requests: Arc::new(FakeAccessRequestStore::empty()),
            sources: AccessSources {
                roles: Arc::new(FakeRoleStore::holding(tenant, [role])),
                groups: Arc::new(FakeGroupStore::holding(tenant, [group])),
                ..AccessSources::default()
            },
        }
    }

    impl Tenant {
        /// A pending request for `asked` by `address`, made at `at`.
        fn asked(&self, asked: AskedAccess, address: &str, at: OffsetDateTime) -> AccessRequestId {
            let request = pending_request_by(asked, address, at);
            block_on(self.requests.save(&test_ctx().tenant(), &request)).unwrap();
            *request.id()
        }

        /// Bob's request for "production", made just now.
        fn bob_asks_for_the_role(&self) -> AccessRequestId {
            self.asked(
                AskedAccess::Role(self.role_id),
                "bob@acme.test",
                clock::now(),
            )
        }

        fn ports(&self) -> ApprovePorts {
            ApprovePorts {
                request_store: self.requests.clone(),
                role_store: self.sources.roles.clone(),
                group_store: self.sources.groups.clone(),
                access_records: Arc::new(FakeAccessRecordStore::reading(self.sources.clone())),
                assignment_store: self.sources.assignments.clone(),
                membership_store: self.sources.memberships.clone(),
                ..ApprovePorts::fakes()
            }
        }

        fn status(&self, id: &AccessRequestId) -> Option<AccessRequestStatus> {
            self.requests.status_of(test_ctx().tenant_id(), id)
        }

        fn nothing_given(&self) -> bool {
            self.sources.assignments.count() == 0 && self.sources.memberships.count() == 0
        }
    }

    fn approve(
        ports: ApprovePorts,
        sink: &Arc<FakeEventDispatcher>,
        id: AccessRequestId,
    ) -> Result<AccessRequest<ResolvedTenant>, AppError> {
        block_on(ApproveUseCase::new(ports).execute(&test_ctx(), &test_auditor(sink.clone()), id))
    }

    /// Bob asked for "production" for two hours. Ann approves: the request
    /// is approved, Bob holds the role until two hours from now, and both
    /// are recorded.
    #[test]
    fn an_approved_role_is_given_until_the_end_asked() {
        let tenant = tenant();
        let id = tenant.bob_asks_for_the_role();
        let sink = Arc::new(FakeEventDispatcher::new());

        approve(tenant.ports(), &sink, id).unwrap();

        assert_eq!(tenant.status(&id), Some(AccessRequestStatus::Approved));
        let held = tenant
            .sources
            .assignments
            .of_tenant(test_ctx().tenant_id())
            .unwrap();
        assert!(matches!(held[0].expires(), Expiry::At(_)));
        assert_eq!(
            sink.records.lock().unwrap().as_slice(),
            [
                "authorization.access_request_approved",
                "authorization.role_assigned"
            ]
        );
    }

    /// Approving Bob's new request replaces his expired production assignment
    /// with one current assignment, recording expiry before approval and grant.
    #[test]
    fn an_approval_records_the_end_of_a_hold_that_ran_out() {
        let tenant = tenant();
        let request = pending_request_by(
            AskedAccess::Role(tenant.role_id),
            "bob@acme.test",
            clock::now(),
        );
        block_on(tenant.requests.save(&test_ctx().tenant(), &request)).unwrap();
        let tenant = Tenant {
            sources: AccessSources {
                assignments: expired_assignment(request.requester().principal(), tenant.role_id),
                ..tenant.sources
            },
            ..tenant
        };
        let sink = Arc::new(FakeEventDispatcher::new());

        approve(tenant.ports(), &sink, *request.id()).unwrap();

        assert_eq!(tenant.sources.assignments.count(), 1);
        assert_eq!(
            sink.records.lock().unwrap().as_slice(),
            [
                "authorization.role_assignment_expired",
                "authorization.access_request_approved",
                "authorization.role_assigned"
            ]
        );
    }

    /// The requester's direct role assignment expired a day before this approval.
    fn expired_assignment(principal: PrincipalRef, role: RoleId) -> Arc<FakeRoleAssignmentStore> {
        let ran_out = stored_assignment_until(
            principal,
            role,
            Expiry::At(clock::now() - Duration::days(1)),
        );
        Arc::new(FakeRoleAssignmentStore::holding(
            test_ctx().tenant_id(),
            [ran_out],
        ))
    }

    /// Bob asked for a place in "Production". Ann approves and he is in it.
    #[test]
    fn an_approved_group_is_joined() {
        let tenant = tenant();
        let id = tenant.asked(
            AskedAccess::Group(tenant.group_id),
            "bob@acme.test",
            clock::now(),
        );
        let sink = Arc::new(FakeEventDispatcher::new());

        approve(tenant.ports(), &sink, id).unwrap();

        assert_eq!(tenant.sources.memberships.count(), 1);
        assert_eq!(
            sink.records.lock().unwrap().as_slice(),
            [
                "authorization.access_request_approved",
                "authorization.group_member_added"
            ]
        );
    }

    /// Self-approval is forbidden: Ann's request stays pending, with no
    /// assignment, membership or audit record added.
    #[test]
    fn nobody_approves_their_own_request() {
        let tenant = tenant();
        let id = tenant.asked(AskedAccess::Role(tenant.role_id), CALLER, clock::now());
        let sink = Arc::new(FakeEventDispatcher::new());

        let result = approve(tenant.ports(), &sink, id);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(tenant.status(&id), Some(AccessRequestStatus::Pending));
        assert!(tenant.nothing_given());
        assert!(sink.records.lock().unwrap().is_empty());
    }

    /// A caller without assignment rights cannot approve Bob's request;
    /// no role or group membership is granted.
    #[test]
    fn a_caller_who_could_not_give_it_is_refused() {
        let tenant = tenant();
        let id = tenant.bob_asks_for_the_role();
        let ports = ApprovePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[])),
            ..tenant.ports()
        };

        let result = approve(ports, &Arc::new(FakeEventDispatcher::new()), id);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(tenant.nothing_given());
    }

    /// Bob asked eight days ago and nobody answered. The request ran out a
    /// day ago, so Ann's approval is refused as a conflict.
    #[test]
    fn a_request_that_ran_out_is_not_approved() {
        let tenant = tenant();
        let id = tenant.asked(
            AskedAccess::Role(tenant.role_id),
            "bob@acme.test",
            clock::now() - Duration::days(8),
        );

        let result = approve(tenant.ports(), &Arc::new(FakeEventDispatcher::new()), id);

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert!(tenant.nothing_given());
    }

    /// Withdrawal during approval produces a conflict and leaves the request
    /// cancelled. No access is granted and no approval is recorded.
    #[test]
    fn an_approval_of_a_request_withdrawn_meanwhile_is_a_conflict() {
        let tenant = tenant();
        let request = pending_request_by(
            AskedAccess::Role(tenant.role_id),
            "bob@acme.test",
            clock::now(),
        );
        let id = *request.id();
        let tenant = Tenant {
            requests: Arc::new(FakeAccessRequestStore::withdrawn_while_answered(
                test_ctx().tenant_id(),
                [request],
            )),
            ..tenant
        };
        let sink = Arc::new(FakeEventDispatcher::new());

        let result = approve(tenant.ports(), &sink, id);

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert_eq!(tenant.status(&id), Some(AccessRequestStatus::Cancelled));
        assert!(tenant.nothing_given());
        assert!(sink.records.lock().unwrap().is_empty());
    }

    /// Ann approves a request the tenant does not have. It is not found.
    #[test]
    fn an_unknown_request_is_not_found() {
        let tenant = tenant();

        let result = approve(
            tenant.ports(),
            &Arc::new(FakeEventDispatcher::new()),
            AccessRequestId::new(),
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A separation rule prevents approving production access for a payment
    /// raiser. The request stays pending, only his original assignment remains,
    /// and no approval is recorded.
    #[test]
    fn an_approval_breaking_a_separation_of_duties_is_refused() {
        let mut tenant = tenant();
        let tenant_id = test_ctx().tenant_id();
        let raiser = stored_role("raiser", Vec::new(), Vec::new());
        let production = tenant.sources.roles.stored(tenant_id).remove(0);
        let rule = separation_between("raise or run", &raiser, &production);
        let id = tenant.bob_asks_for_the_role();
        let bob = block_on(tenant.requests.find_by_id(&test_ctx().tenant(), &id))
            .unwrap()
            .unwrap()
            .requester()
            .principal();
        tenant.sources.roles.add(tenant_id, [raiser.clone()]);
        tenant.sources.assignments = Arc::new(FakeRoleAssignmentStore::holding(
            tenant_id,
            [stored_assignment(bob, *raiser.id())],
        ));
        let sink = Arc::new(FakeEventDispatcher::new());
        let ports = ApprovePorts {
            separation_rules: Arc::new(FakeSeparationRuleStore::holding(tenant_id, [rule])),
            ..tenant.ports()
        };

        let result = approve(ports, &sink, id);

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert_eq!(tenant.sources.assignments.count(), 1);
        assert_eq!(tenant.status(&id), Some(AccessRequestStatus::Pending));
        assert!(sink.records.lock().unwrap().is_empty());
    }

    /// A signed-out session cannot approve Bob's request or grant him access.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let tenant = tenant();
        let id = tenant.bob_asks_for_the_role();
        let ports = ApprovePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..tenant.ports()
        };

        let result = approve(ports, &Arc::new(FakeEventDispatcher::new()), id);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert!(tenant.nothing_given());
    }
}
