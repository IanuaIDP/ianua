//! Remove group member: take a principal out of a group of the tenant.
//!
//! The member loses everything the group brought them, so only someone who
//! could have given it takes them out, and never the last administrator.

use std::sync::Arc;

use ianua_domain::domains::authorization::authority::TenantAuthority;
use ianua_domain::domains::authorization::group::{Group, GroupMembership, GroupPlace};
use ianua_domain::domains::authorization::permission::{RoleAction, SystemPermission};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{GroupId, PrincipalRef};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal, OrNotFound};
use crate::ports::authorization::{AccessRecordStore, GroupMembershipStore, GroupStore, Holder};
use crate::ports::shared::{AuditLabelResolver, ControlPlaneLabelResolver};
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::authorization::audit_labels::principal_label;
use crate::use_cases::authorization::groups::placement::conferred_at;
use crate::use_cases::authorization::lookup::{existing_group, held_records};
use crate::use_cases::authorization::stewardship::{Lost, ensure_administered_after_losing};

/// The ports [`RemoveMemberUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RemoveMemberPorts {
    /// Loads groups.
    pub group_store: Arc<dyn GroupStore>,
    /// Loads and removes memberships.
    pub membership_store: Arc<dyn GroupMembershipStore>,
    /// Reads the tenant's groups, roles and who holds what.
    pub access_records: Arc<dyn AccessRecordStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
    /// Names the member in the audit record.
    pub audit_label_resolver: Arc<dyn AuditLabelResolver>,
    /// Names a member who is an organization member in the audit record.
    pub control_plane_label_resolver: Arc<dyn ControlPlaneLabelResolver>,
}

/// Which principal leaves which group.
pub struct RemoveMemberRequest {
    /// The group left.
    pub group_id: GroupId,
    /// The user, agent or consumer who leaves.
    pub member: PrincipalRef,
}

/// Takes a principal out of a group of the caller's tenant.
pub struct RemoveMemberUseCase {
    ports: RemoveMemberPorts,
}

impl RemoveMemberUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: RemoveMemberPorts) -> Self {
        Self { ports }
    }
}

impl Command for RemoveMemberUseCase {
    type Caller = CallerContext;
    type Input = RemoveMemberRequest;
    type Output = Result<(), AppError>;

    /// Takes `request.member` out of `request.group_id`, for the caller.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `Forbidden` without assignment rights, before reading the group.
    /// - `AppError::NotFound` for a missing group/membership; `Forbidden` when the caller could not grant all the group's rights.
    /// - `AppError::Conflict` when the membership supplies the tenant's last administrator; `Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: RemoveMemberRequest,
    ) -> Result<(), AppError> {
        let RemoveMemberRequest { group_id, member } = request;
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        authority
            .standing()
            .ensure_holds(SystemPermission::Roles(RoleAction::Assign))
            .map_err(AppError::from_domain)?;
        let group = existing_group(self.ports.group_store.as_ref(), &tenant, &group_id).await?;
        let mut membership = held(&self.ports, &tenant, &member, &group_id).await?;
        end(&self.ports, ctx, &authority, &mut membership, &group).await?;

        self.ports
            .membership_store
            .delete(&tenant, &member, &group_id)
            .await
            .or_internal()?;
        auditor
            .dispatch_by(&authority.actor(), membership.take_events(&tenant))
            .await
            .or_internal()?;
        Ok(())
    }
}

/// Ends `membership` of `group` for `authority`, naming the member as
/// `ctx`'s tenant knows them, once it may and the tenant keeps an
/// administrator without it.
async fn end(
    ports: &RemoveMemberPorts,
    ctx: &CallerContext,
    authority: &TenantAuthority,
    membership: &mut GroupMembership<ResolvedTenant>,
    group: &Group<ResolvedTenant>,
) -> Result<(), AppError> {
    let tenant = ctx.tenant();
    let resolver = ports.audit_label_resolver.as_ref();
    let control_plane = ports.control_plane_label_resolver.as_ref();
    let label = principal_label(resolver, control_plane, ctx, membership.principal()).await?;
    let store = ports.access_records.as_ref();
    let records = held_records(store, &tenant, Holder::of(*membership.principal())).await?;
    let conferred = conferred_at(records.records(), GroupPlace::Under(*membership.group_id()))?;
    membership
        .end(group, &conferred, &authority.standing(), label)
        .map_err(AppError::from_domain)?;
    let losing = [*membership.principal()];
    let lost = Lost::Membership(membership.group_id());
    ensure_administered_after_losing(store, &tenant, &losing, lost).await
}

/// `member`'s membership of `group_id`.
async fn held(
    ports: &RemoveMemberPorts,
    tenant: &ScopedTenant,
    member: &PrincipalRef,
    group_id: &GroupId,
) -> Result<GroupMembership<ResolvedTenant>, AppError> {
    ports
        .membership_store
        .find_by_principal(tenant, member)
        .await
        .or_internal()?
        .into_iter()
        .find(|membership| membership.group_id() == group_id)
        .or_not_found(message!(
            "authorization-not-a-member-of-this-group",
            "not a member of this group"
        ))
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::role::Role;
    use ianua_domain::types::{ConsumerId, UserId};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authorization::{
        AccessSources, FakeAccessRecordStore, FakeGroupMembershipStore, FakeGroupStore,
        FakeRoleStore, stored_group, stored_membership, stored_role,
    };
    use crate::test_support::{
        FakeAuditLabelResolver, FakeEventDispatcher, block_on, test_auditor, test_ctx,
    };

    fn admin_role() -> Role<ResolvedTenant> {
        stored_role(
            "admin",
            vec![SystemPermission::ManageUsers, SystemPermission::ManageRoles],
            Vec::new(),
        )
    }

    /// One group of a tenant, its roles and its members, read by every
    /// port.
    struct Tenant {
        group_id: GroupId,
        stores: AccessSources,
    }

    impl Tenant {
        fn group_carrying(roles: Vec<Role<ResolvedTenant>>, members: &[PrincipalRef]) -> Self {
            let tenant = test_ctx().tenant_id();
            let role_ids = roles.iter().map(|role| *role.id()).collect();
            let group = stored_group("Engineering", GroupPlace::TopLevel, role_ids);
            let group_id = *group.id();
            let memberships = members
                .iter()
                .map(|member| stored_membership(*member, group_id));
            Self {
                group_id,
                stores: AccessSources {
                    groups: Arc::new(FakeGroupStore::holding(tenant, [group])),
                    roles: Arc::new(FakeRoleStore::holding(tenant, roles)),
                    memberships: Arc::new(FakeGroupMembershipStore::holding(tenant, memberships)),
                    ..AccessSources::default()
                },
            }
        }

        fn engineering(members: &[PrincipalRef]) -> Self {
            Self::group_carrying(Vec::new(), members)
        }

        fn ports(&self) -> RemoveMemberPorts {
            RemoveMemberPorts {
                group_store: self.stores.groups.clone(),
                membership_store: self.stores.memberships.clone(),
                access_records: Arc::new(FakeAccessRecordStore::reading(self.stores.clone())),
                ..RemoveMemberPorts::fakes()
            }
        }

        fn ports_holding(&self, system: &[SystemPermission]) -> RemoveMemberPorts {
            RemoveMemberPorts {
                tenant_authorities: Arc::new(FakeTenantAuthorities::holding(system)),
                ..self.ports()
            }
        }

        fn members(&self) -> usize {
            self.stores.memberships.count()
        }
    }

    fn remove(
        ports: RemoveMemberPorts,
        sink: &Arc<FakeEventDispatcher>,
        group_id: GroupId,
        member: PrincipalRef,
    ) -> Result<(), AppError> {
        block_on(RemoveMemberUseCase::new(ports).execute(
            &test_ctx(),
            &test_auditor(sink.clone()),
            RemoveMemberRequest { group_id, member },
        ))
    }

    fn quietly(
        ports: RemoveMemberPorts,
        group_id: GroupId,
        member: PrincipalRef,
    ) -> Result<(), AppError> {
        remove(
            ports,
            &Arc::new(FakeEventDispatcher::new()),
            group_id,
            member,
        )
    }

    /// Removing one of two admin members counts administrators only while
    /// holding the tenant's grants lock and leaves one membership stored.
    #[test]
    fn the_last_administrators_are_counted_under_the_hold() {
        let (ann, bob) = (
            PrincipalRef::User(UserId::new()),
            PrincipalRef::User(UserId::new()),
        );
        let tenant = Tenant::group_carrying(vec![admin_role()], &[ann, bob]);
        let records = Arc::new(FakeAccessRecordStore::reading(tenant.stores.clone()));
        let ports = RemoveMemberPorts {
            access_records: records.clone(),
            ..tenant.ports()
        };

        quietly(ports, tenant.group_id, bob).unwrap();

        assert_eq!(records.counted_without_a_hold(), 0);
        assert_eq!(tenant.members(), 1);
    }

    /// Ann takes Bob out of "Engineering". He no longer belongs, and the
    /// record names the group and him.
    #[test]
    fn a_member_leaves_and_is_recorded() {
        let bob = PrincipalRef::User(UserId::new());
        let tenant = Tenant::engineering(&[bob]);
        let sink = Arc::new(FakeEventDispatcher::new());

        remove(tenant.ports(), &sink, tenant.group_id, bob).unwrap();

        let event = "authorization.group_member_removed";
        assert_eq!(tenant.members(), 0);
        assert_eq!(sink.records.lock().unwrap().as_slice(), [event]);
        assert_eq!(
            sink.label_of(event, "group").as_deref(),
            Some("Engineering")
        );
        assert_eq!(sink.label_of(event, "member").as_deref(), Some("test user"));
    }

    /// Ann takes Bob out of "Engineering". What the group brings him and
    /// whether the tenant keeps an administrator are worked out from his
    /// own records and the tenant's count, never from every record.
    #[test]
    fn a_member_leaving_reads_only_their_records() {
        let bob = PrincipalRef::User(UserId::new());
        let tenant = Tenant::group_carrying(vec![admin_role()], &[bob]);
        let records = Arc::new(FakeAccessRecordStore::reading(tenant.stores.clone()));
        let ports = RemoveMemberPorts {
            access_records: records.clone(),
            ..tenant.ports()
        };

        let result = quietly(ports, tenant.group_id, bob);

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert_eq!(records.whole_reads(), 0);
    }

    /// Bob's user row cannot be named. The record names him by his id.
    #[test]
    fn the_record_falls_back_to_the_member_id_when_the_name_is_gone() {
        let bob_id = UserId::new();
        let bob = PrincipalRef::User(bob_id);
        let tenant = Tenant::engineering(&[bob]);
        let sink = Arc::new(FakeEventDispatcher::new());
        let ports = RemoveMemberPorts {
            audit_label_resolver: Arc::new(FakeAuditLabelResolver::missing()),
            ..tenant.ports()
        };

        remove(ports, &sink, tenant.group_id, bob).unwrap();

        assert_eq!(
            sink.label_of("authorization.group_member_removed", "member"),
            Some(bob_id.to_string())
        );
    }

    /// Ann takes the partner app Acme Sync out of "Engineering". An app's
    /// membership is taken back like a person's, which is what ends the
    /// permissions it held at the proxy.
    #[test]
    fn a_consumer_can_be_taken_out() {
        let app = PrincipalRef::Consumer(ConsumerId::new());
        let tenant = Tenant::engineering(&[app]);

        quietly(tenant.ports(), tenant.group_id, app).unwrap();

        assert_eq!(tenant.members(), 0);
    }

    /// Ann takes Bob out of "Engineering", which he never joined. It is not
    /// found and nothing is recorded.
    #[test]
    fn a_principal_not_in_the_group_is_not_found_and_not_recorded() {
        let tenant = Tenant::engineering(&[]);
        let sink = Arc::new(FakeEventDispatcher::new());

        let result = remove(
            tenant.ports(),
            &sink,
            tenant.group_id,
            PrincipalRef::User(UserId::new()),
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(sink.records.lock().unwrap().is_empty());
    }

    /// Ann takes Bob out of a group the tenant does not have. It is not
    /// found.
    #[test]
    fn an_unknown_group_is_not_found() {
        let bob = PrincipalRef::User(UserId::new());
        let tenant = Tenant::engineering(&[bob]);

        let result = quietly(tenant.ports(), GroupId::new(), bob);

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(tenant.members(), 1);
    }

    /// Ann takes Bob out of the admin group while Carol is still in it. It
    /// goes through.
    #[test]
    fn an_administrator_may_leave_while_another_remains() {
        let (bob, carol) = (
            PrincipalRef::User(UserId::new()),
            PrincipalRef::User(UserId::new()),
        );
        let tenant = Tenant::group_carrying(vec![admin_role()], &[bob, carol]);

        quietly(tenant.ports(), tenant.group_id, bob).unwrap();

        assert_eq!(tenant.members(), 1);
    }

    /// Removing the sole administrator's group membership is a conflict
    /// and leaves that membership stored.
    #[test]
    fn the_last_administrator_stays_in_the_group() {
        let ann = PrincipalRef::User(UserId::new());
        let tenant = Tenant::group_carrying(vec![admin_role()], &[ann]);

        let result = quietly(tenant.ports(), tenant.group_id, ann);

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert_eq!(tenant.members(), 1);
    }

    /// Assignment permission alone cannot remove an admin membership whose
    /// rights exceed the caller's. Both admin members remain stored.
    #[test]
    fn a_caller_cannot_end_a_membership_bringing_more_than_they_hold() {
        let (ann, carol) = (
            PrincipalRef::User(UserId::new()),
            PrincipalRef::User(UserId::new()),
        );
        let tenant = Tenant::group_carrying(vec![admin_role()], &[ann, carol]);
        let sam = tenant.ports_holding(&[SystemPermission::Roles(RoleAction::Assign)]);

        let result = quietly(sam, tenant.group_id, ann);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(tenant.members(), 2);
    }

    /// Without assignment permission, removing Bob is forbidden and leaves
    /// his Engineering membership stored.
    #[test]
    fn a_caller_who_may_not_assign_roles_is_refused() {
        let bob = PrincipalRef::User(UserId::new());
        let tenant = Tenant::engineering(&[bob]);

        let result = quietly(tenant.ports_holding(&[]), tenant.group_id, bob);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(tenant.members(), 1);
    }

    /// A signed-out session cannot remove Bob's stored group membership.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let bob = PrincipalRef::User(UserId::new());
        let tenant = Tenant::engineering(&[bob]);
        let ports = RemoveMemberPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..tenant.ports()
        };

        let result = quietly(ports, tenant.group_id, bob);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(tenant.members(), 1);
    }
}
