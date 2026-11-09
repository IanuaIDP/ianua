//! Add group member: put a principal into a group of the tenant.
//!
//! Joining a group hands the member every role it carries, and those of the
//! groups above it. So it is a role grant by another name, and the domain
//! checks it as one against what the whole tree brings. Without the walk up,
//! someone adds themselves to a harmless-looking child of a privileged group.
//!
//! The member may be a person, an agent or a consumer: a tier of partner
//! apps shares roles the way a team of people does.
//!
//! A membership may end at a time, after which it brings nothing. Put back
//! in, the place that ran out is cleared and its end recorded by the
//! platform first, as the sweep would. Nobody
//! joins a group that, with what they hold, leaves them with both roles of
//! a separation-of-duties rule.

use std::sync::Arc;

use ianua_domain::domains::authorization::authority::TenantAuthority;
use ianua_domain::domains::authorization::group::{Group, GroupMembership, GroupPlace};
use ianua_domain::domains::authorization::group_tree::Conferred;
use ianua_domain::domains::authorization::holding::NewHolding;
use ianua_domain::domains::authorization::permission::{RoleAction, SystemPermission};
use ianua_domain::domains::authorization::role::Role;
use ianua_domain::domains::workflows::triggers::before::GuardedChange;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::clock;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{EventLabel, Expiry, GroupId, PrincipalRef};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::authorization::{
    AccessRecordStore, AccessRecords, GroupMembershipStore, GroupStore, SeparationRuleStore,
};
use crate::ports::shared::{
    AuditLabelResolver, ControlPlaneLabelResolver, PrincipalExistenceChecker,
};
use crate::ports::workflows::ChangeGuard;
use crate::services::authorization::duties::{DutySources, Granting, ensure_duties_kept};
use crate::services::guarded::{AdminHolder, ensure_admin_rules_allow, ensure_rules_allow};
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::authorization::audit_labels::principal_label;
use crate::use_cases::authorization::groups::placement::conferred_at;
use crate::use_cases::authorization::holdings::lapsed::{RanOut, place_cleared};
use crate::use_cases::authorization::lookup::{existing_group, place_records};

/// The ports [`AddMemberUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct AddMemberPorts {
    /// Loads groups.
    pub group_store: Arc<dyn GroupStore>,
    /// Saves memberships.
    pub membership_store: Arc<dyn GroupMembershipStore>,
    /// Reads the tenant's groups and roles, for what joining brings.
    pub access_records: Arc<dyn AccessRecordStore>,
    /// Says whether the member exists.
    pub principal_checker: Arc<dyn PrincipalExistenceChecker>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
    /// Names the member in the audit record.
    pub audit_label_resolver: Arc<dyn AuditLabelResolver>,
    /// Names a member who is an organization member in the audit record.
    pub control_plane_label_resolver: Arc<dyn ControlPlaneLabelResolver>,
    /// The tenant's separation-of-duties rules.
    pub separation_rules: Arc<dyn SeparationRuleStore>,
    /// The company's "before" rules, asked before anyone is given access.
    pub guard: Arc<dyn ChangeGuard>,
}

/// Which principal joins which group, and until when.
pub struct AddMemberRequest {
    /// The group joined.
    pub group_id: GroupId,
    /// The user, agent or consumer who joins.
    pub member: PrincipalRef,
    /// When the membership ends, or that it does not.
    pub until: Expiry,
}

/// Puts a principal into a group of the caller's tenant.
pub struct AddMemberUseCase {
    ports: AddMemberPorts,
}

impl AddMemberUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: AddMemberPorts) -> Self {
        Self { ports }
    }

    /// Asks the company's "before access given" rules about putting
    /// `joined`'s member into `group_id`, then its "before admin given"
    /// rules about each admin role the group brings them.
    async fn ensure_rules_allow(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        group_id: &GroupId,
        joined: &Joined,
    ) -> Result<(), AppError> {
        let member = joined.membership.principal();
        let fields = [("group", group_id.to_string()), ("member", member.label())];
        let guard = self.ports.guard.as_ref();
        ensure_rules_allow(guard, tenant, auditor, GuardedChange::AccessGiven, &fields).await?;
        for role in &joined.admin_roles {
            let holder = AdminHolder::Principal(member);
            ensure_admin_rules_allow(guard, tenant, auditor, role, holder).await?;
        }
        Ok(())
    }
}

impl Command for AddMemberUseCase {
    type Caller = CallerContext;
    type Input = AddMemberRequest;
    type Output = Result<(), AppError>;

    /// Puts `request.member` into `request.group_id`, granted by the caller.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `Forbidden` without assignment rights, before reading the group.
    /// - `AppError::NotFound` for a missing group/member; `Conflict` for an existing membership.
    /// - `AppError::Forbidden` when the caller cannot grant the group's own and inherited rights.
    /// - `AppError::Domain` for an end not in the future; `Conflict` for a separation-of-duties violation.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: AddMemberRequest,
    ) -> Result<(), AppError> {
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        authority
            .standing()
            .ensure_holds(SystemPermission::Roles(RoleAction::Assign))
            .map_err(AppError::from_domain)?;
        let group_id = request.group_id;
        let group = existing_group(self.ports.group_store.as_ref(), &tenant, &group_id).await?;
        ensure_may_join(&self.ports, &tenant, &request.member, &group_id).await?;
        let mut joined = joined(&self.ports, ctx, &authority, request, &group).await?;
        let store = self.ports.membership_store.as_ref();
        let ran_out = RanOut {
            principal: joined.membership.principal(),
            label: joined.label.clone(),
            now: clock::now(),
        };
        let ended = place_cleared(store, &tenant, &group, ran_out).await?;
        self.ensure_rules_allow(&tenant, auditor, &group_id, &joined)
            .await?;
        let membership = &mut joined.membership;
        store.save(&tenant, membership).await.or_internal()?;
        auditor.dispatch(&ended).await.or_internal()?;
        auditor
            .dispatch_by(&authority.actor(), membership.take_events(&tenant))
            .await
            .or_internal()?;
        Ok(())
    }
}

/// Refuses a member that does not exist or already belongs to the group.
async fn ensure_may_join(
    ports: &AddMemberPorts,
    tenant: &ScopedTenant,
    member: &PrincipalRef,
    group_id: &GroupId,
) -> Result<(), AppError> {
    let exists = ports
        .principal_checker
        .principal_exists(tenant, member)
        .await
        .or_internal()?;
    if !exists {
        return Err(AppError::NotFound(message!(
            "authorization-member-not-found",
            "member not found"
        )));
    }
    let belongs = ports
        .membership_store
        .exists(tenant, member, group_id)
        .await
        .or_internal()?;
    if belongs {
        return Err(AppError::Conflict(message!(
            "authorization-already-a-member-of-this-group",
            "already a member of this group"
        )));
    }
    Ok(())
}

/// A membership about to be kept, with how its member is named and the
/// admin roles it brings them.
struct Joined {
    membership: GroupMembership<ResolvedTenant>,
    label: EventLabel,
    admin_roles: Vec<Role<ResolvedTenant>>,
}

/// `request`'s member in `group` until its end, with how `ctx`'s tenant
/// names them, once `authority` may hand out all it brings and the tenant's
/// separation of duties allows it.
async fn joined(
    ports: &AddMemberPorts,
    ctx: &CallerContext,
    authority: &TenantAuthority,
    request: AddMemberRequest,
    group: &Group<ResolvedTenant>,
) -> Result<Joined, AppError> {
    let tenant = ctx.tenant();
    let place = GroupPlace::Under(*group.id());
    let records = place_records(ports.access_records.as_ref(), &tenant, place).await?;
    let conferred = conferred_at(&records, place)?;
    let resolver = ports.audit_label_resolver.as_ref();
    let control_plane = ports.control_plane_label_resolver.as_ref();
    let label = principal_label(resolver, control_plane, ctx, &request.member).await?;
    let holding = NewHolding {
        principal: request.member,
        label: label.clone(),
        until: request.until,
    };
    let membership = GroupMembership::join_until(holding, group, &conferred, &authority.standing())
        .map_err(AppError::from_domain)?;
    let sources = DutySources::of(
        ports.access_records.as_ref(),
        ports.separation_rules.as_ref(),
    );
    let granting = Granting::Membership {
        principal: request.member,
        conferred: &conferred,
    };
    ensure_duties_kept(sources, &tenant, granting).await?;
    Ok(Joined {
        membership,
        label,
        admin_roles: admin_roles(records, &conferred),
    })
}

/// The roles among `records` that `conferred` brings and that do admin
/// work.
fn admin_roles(records: AccessRecords, conferred: &Conferred) -> Vec<Role<ResolvedTenant>> {
    records
        .roles
        .into_iter()
        .filter(|role| conferred.roles().contains(role.id()) && role.grants_admin_work())
        .collect()
}

#[cfg(test)]
mod tests {
    use ianua_domain::shared::clock;
    use ianua_domain::types::{ConsumerId, UserId};
    use time::Duration;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authorization::{
        AccessSources, FakeAccessRecordStore, FakeGroupMembershipStore, FakeGroupStore,
        FakeRoleAssignmentStore, FakeRoleStore, FakeSeparationRuleStore, separation_between,
        stored_assignment, stored_group, stored_membership_until, stored_role,
    };
    use crate::test_support::{
        FakeAuditLabelResolver, FakeEventDispatcher, FakePrincipalChecker, block_on, test_auditor,
        test_ctx,
    };

    const ASSIGN_ROLES: SystemPermission = SystemPermission::Roles(RoleAction::Assign);

    fn admin_role() -> Role<ResolvedTenant> {
        stored_role("admin", vec![SystemPermission::ManageUsers], Vec::new())
    }

    /// A tenant's groups and roles, read by every port.
    struct Tenant {
        stores: AccessSources,
    }

    impl Tenant {
        fn with(groups: Vec<Group<ResolvedTenant>>, roles: Vec<Role<ResolvedTenant>>) -> Self {
            let tenant = test_ctx().tenant_id();
            Self {
                stores: AccessSources {
                    groups: Arc::new(FakeGroupStore::holding(tenant, groups)),
                    roles: Arc::new(FakeRoleStore::holding(tenant, roles)),
                    ..AccessSources::default()
                },
            }
        }

        /// A tenant with the group "Engineering", which carries nothing.
        fn with_engineering() -> (Self, GroupId) {
            let engineering = stored_group("Engineering", GroupPlace::TopLevel, Vec::new());
            let id = *engineering.id();
            (Self::with(vec![engineering], Vec::new()), id)
        }

        /// A tenant whose group "Admins" carries the admin role.
        fn with_admins() -> (Self, GroupId) {
            let admin = admin_role();
            let admins = stored_group("Admins", GroupPlace::TopLevel, vec![*admin.id()]);
            let id = *admins.id();
            (Self::with(vec![admins], vec![admin]), id)
        }

        fn ports(&self) -> AddMemberPorts {
            AddMemberPorts {
                group_store: self.stores.groups.clone(),
                membership_store: self.stores.memberships.clone(),
                access_records: Arc::new(FakeAccessRecordStore::reading(self.stores.clone())),
                ..AddMemberPorts::fakes()
            }
        }

        fn ports_holding(&self, system: &[SystemPermission]) -> AddMemberPorts {
            AddMemberPorts {
                tenant_authorities: Arc::new(FakeTenantAuthorities::holding(system)),
                ..self.ports()
            }
        }

        fn members(&self) -> usize {
            self.stores.memberships.count()
        }
    }

    fn add(
        ports: AddMemberPorts,
        sink: &Arc<FakeEventDispatcher>,
        group_id: GroupId,
        member: PrincipalRef,
    ) -> Result<(), AppError> {
        block_on(AddMemberUseCase::new(ports).execute(
            &test_ctx(),
            &test_auditor(sink.clone()),
            AddMemberRequest {
                group_id,
                member,
                until: Expiry::Never,
            },
        ))
    }

    fn bob() -> PrincipalRef {
        PrincipalRef::User(UserId::new())
    }

    /// Rejoining after expiry leaves Bob with one Engineering membership
    /// and records the old membership's expiry first among two events.
    #[test]
    fn a_place_that_ran_out_is_recorded_ended_before_the_member_joins_again() {
        let (tenant, engineering) = Tenant::with_engineering();
        let bob = bob();
        let ended = Expiry::At(clock::now() - Duration::days(1));
        let tenant = Tenant {
            stores: AccessSources {
                memberships: Arc::new(FakeGroupMembershipStore::holding(
                    test_ctx().tenant_id(),
                    [stored_membership_until(bob, engineering, ended)],
                )),
                ..tenant.stores
            },
        };
        let sink = Arc::new(FakeEventDispatcher::new());

        add(tenant.ports(), &sink, engineering, bob).unwrap();

        assert_eq!(tenant.members(), 1);
        let records = sink.records.lock().unwrap().clone();
        assert_eq!(records[0], "authorization.group_membership_expired");
        assert_eq!(records.len(), 2);
    }

    fn quietly(ports: AddMemberPorts, group_id: GroupId) -> Result<(), AppError> {
        add(
            ports,
            &Arc::new(FakeEventDispatcher::new()),
            group_id,
            bob(),
        )
    }

    /// Ann puts Bob into "Engineering". He belongs to it, and the record
    /// names the group and him.
    #[test]
    fn a_member_joins_and_is_recorded() {
        let (tenant, id) = Tenant::with_engineering();
        let sink = Arc::new(FakeEventDispatcher::new());

        add(tenant.ports(), &sink, id, bob()).unwrap();

        let event = "authorization.group_member_added";
        assert_eq!(tenant.members(), 1);
        assert_eq!(sink.records.lock().unwrap().as_slice(), [event]);
        assert_eq!(
            sink.label_of(event, "group").as_deref(),
            Some("Engineering")
        );
        assert_eq!(sink.label_of(event, "member").as_deref(), Some("test user"));
    }

    /// Bob's user row cannot be named. The record names him by his id.
    #[test]
    fn the_record_falls_back_to_the_member_id_when_the_name_is_gone() {
        let (tenant, id) = Tenant::with_engineering();
        let sink = Arc::new(FakeEventDispatcher::new());
        let bob_id = UserId::new();
        let ports = AddMemberPorts {
            audit_label_resolver: Arc::new(FakeAuditLabelResolver::missing()),
            ..tenant.ports()
        };

        add(ports, &sink, id, PrincipalRef::User(bob_id)).unwrap();

        assert_eq!(
            sink.label_of("authorization.group_member_added", "member"),
            Some(bob_id.to_string())
        );
    }

    /// Ann puts the partner app Acme Sync into "Engineering". An app joins a
    /// group the way a person does.
    #[test]
    fn a_consumer_can_join_a_group() {
        let (tenant, id) = Tenant::with_engineering();
        let app = PrincipalRef::Consumer(ConsumerId::new());

        add(
            tenant.ports(),
            &Arc::new(FakeEventDispatcher::new()),
            id,
            app,
        )
        .unwrap();

        assert_eq!(tenant.members(), 1);
    }

    /// Ann puts Bob into a group the tenant does not have. It is not found
    /// and nothing is recorded.
    #[test]
    fn an_unknown_group_is_not_found_and_not_recorded() {
        let (tenant, _) = Tenant::with_engineering();
        let sink = Arc::new(FakeEventDispatcher::new());

        let result = add(tenant.ports(), &sink, GroupId::new(), bob());

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(sink.records.lock().unwrap().is_empty());
    }

    /// Ann puts in a member the tenant does not have. It is not found.
    #[test]
    fn an_unknown_member_is_not_found() {
        let (tenant, id) = Tenant::with_engineering();
        let ports = AddMemberPorts {
            principal_checker: Arc::new(FakePrincipalChecker::rejecting()),
            ..tenant.ports()
        };

        let result = quietly(ports, id);

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(tenant.members(), 0);
    }

    /// Ann puts Bob into "Engineering" twice. The second is refused as a
    /// conflict.
    #[test]
    fn a_member_already_in_the_group_is_a_conflict() {
        let (tenant, id) = Tenant::with_engineering();
        let sink = Arc::new(FakeEventDispatcher::new());
        let bob = bob();
        add(tenant.ports(), &sink, id, bob).unwrap();

        let result = add(tenant.ports(), &sink, id, bob);

        assert!(matches!(result, Err(AppError::Conflict(_))));
    }

    /// Sam may assign roles. "Engineering" carries nothing, so he may put
    /// anyone into it.
    #[test]
    fn a_group_carrying_nothing_needs_only_the_right_to_assign_roles() {
        let (tenant, id) = Tenant::with_engineering();

        quietly(tenant.ports_holding(&[ASSIGN_ROLES]), id).unwrap();

        assert_eq!(tenant.members(), 1);
    }

    /// Sam may assign roles and manage users. He puts Bob into "Admins",
    /// whose admin role he could have given Bob himself.
    #[test]
    fn a_caller_may_fill_a_group_they_could_staff_directly() {
        let (tenant, id) = Tenant::with_admins();
        let held = [ASSIGN_ROLES, SystemPermission::ManageUsers];

        quietly(tenant.ports_holding(&held), id).unwrap();

        assert_eq!(tenant.members(), 1);
    }

    /// Assignment permission alone cannot add a member to Admins when its
    /// user-management rights exceed the caller's. No membership is saved.
    #[test]
    fn a_caller_cannot_fill_a_group_richer_than_themselves() {
        let (tenant, id) = Tenant::with_admins();

        let result = quietly(tenant.ports_holding(&[ASSIGN_ROLES]), id);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(tenant.members(), 0);
    }

    /// Backend's inherited admin role prevents an assignment-only caller from
    /// adding a member, even though Backend carries no role directly.
    /// No membership is saved.
    #[test]
    fn a_role_inherited_from_a_group_above_counts() {
        let admin = admin_role();
        let platform = stored_group("Platform", GroupPlace::TopLevel, vec![*admin.id()]);
        let backend = stored_group("Backend", GroupPlace::Under(*platform.id()), Vec::new());
        let id = *backend.id();
        let tenant = Tenant::with(vec![platform, backend], vec![admin]);

        let result = quietly(tenant.ports_holding(&[ASSIGN_ROLES]), id);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(tenant.members(), 0);
    }

    /// Without assignment permission, adding an Engineering member is forbidden
    /// and leaves the membership store empty.
    #[test]
    fn a_caller_who_may_not_assign_roles_is_refused() {
        let (tenant, id) = Tenant::with_engineering();

        let result = quietly(tenant.ports_holding(&[]), id);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(tenant.members(), 0);
    }

    /// A signed-out session cannot add a member; the membership store stays empty.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let (tenant, id) = Tenant::with_engineering();
        let ports = AddMemberPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..tenant.ports()
        };

        let result = quietly(ports, id);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(tenant.members(), 0);
    }

    /// Ann puts Bob on call in "Engineering" for the night. The membership
    /// is saved with its end, and the record says when it ends.
    #[test]
    fn a_member_joins_until_a_time() {
        let (tenant, id) = Tenant::with_engineering();
        let sink = Arc::new(FakeEventDispatcher::new());
        let morning = clock::now() + Duration::hours(8);

        block_on(AddMemberUseCase::new(tenant.ports()).execute(
            &test_ctx(),
            &test_auditor(sink.clone()),
            AddMemberRequest {
                group_id: id,
                member: bob(),
                until: Expiry::At(morning),
            },
        ))
        .unwrap();

        let held = tenant
            .stores
            .memberships
            .of_tenant(test_ctx().tenant_id())
            .unwrap();
        assert_eq!(held[0].expires(), Expiry::At(morning));
        assert!(
            sink.payload_of("authorization.group_member_added")
                .get("expires_at")
                .is_some()
        );
    }

    /// A separation rule prevents payment raiser Bob from joining Approvers.
    /// No membership is saved and no join is recorded.
    #[test]
    fn joining_a_group_that_breaks_a_separation_of_duties_is_refused() {
        let tenant_id = test_ctx().tenant_id();
        let raiser = stored_role("raiser", Vec::new(), Vec::new());
        let approver = stored_role("approver", Vec::new(), Vec::new());
        let rule = separation_between("raise or approve payments", &raiser, &approver);
        let approvers = stored_group("Approvers", GroupPlace::TopLevel, vec![*approver.id()]);
        let group_id = *approvers.id();
        let bob = UserId::new();
        let raises = stored_assignment(PrincipalRef::User(bob), *raiser.id());
        let mut tenant = Tenant::with(vec![approvers], vec![raiser, approver]);
        tenant.stores.assignments = Arc::new(FakeRoleAssignmentStore::holding(tenant_id, [raises]));
        let ports = AddMemberPorts {
            separation_rules: Arc::new(FakeSeparationRuleStore::holding(tenant_id, [rule])),
            ..tenant.ports()
        };
        let sink = Arc::new(FakeEventDispatcher::new());

        let result = add(ports, &sink, group_id, PrincipalRef::User(bob));

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert_eq!(tenant.members(), 0);
        assert!(sink.records.lock().unwrap().is_empty());
    }

    /// The rules Tess's company asks when Bob joins the group `pick` names.
    fn asked_joining(pick: fn() -> (Tenant, GroupId)) -> Vec<GuardedChange> {
        let (tenant, group) = pick();
        let guard = Arc::new(crate::test_support::workflows::AllowingGuard::default());
        let ports = AddMemberPorts {
            guard: guard.clone(),
            ..tenant.ports()
        };

        quietly(ports, group).unwrap();

        guard.asked.lock().unwrap().clone()
    }

    /// Bob joins "Admins", which carries the admin role. Both the "access
    /// given" and the "admin given" rules are asked, in that order.
    #[test]
    fn joining_a_group_with_an_admin_role_asks_the_admin_rules_too() {
        let asked = asked_joining(Tenant::with_admins);

        assert_eq!(
            asked,
            [GuardedChange::AccessGiven, GuardedChange::AdminGiven]
        );
    }

    /// Bob joins "Engineering", which carries nothing. Only the "access
    /// given" rules are asked.
    #[test]
    fn joining_a_group_with_no_admin_role_asks_only_the_access_rules() {
        let asked = asked_joining(Tenant::with_engineering);

        assert_eq!(asked, [GuardedChange::AccessGiven]);
    }

    /// Ann's company rule refuses every change it is asked about. Tess puts
    /// Bob into "Admins": it is refused and he is in no group.
    #[test]
    fn a_company_rule_refusing_keeps_the_member_out() {
        let (tenant, admins) = Tenant::with_admins();
        let ports = AddMemberPorts {
            guard: Arc::new(crate::test_support::workflows::RefusingGuard),
            ..tenant.ports()
        };

        let result = quietly(ports, admins);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(tenant.members(), 0);
    }
}
