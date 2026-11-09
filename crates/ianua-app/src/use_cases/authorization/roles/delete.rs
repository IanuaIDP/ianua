//! Delete role: remove a role from the tenant for good.
//!
//! With a replacement, every holder moves onto it before the role goes.
//! Without one, the delete waits until nobody holds the role. Moving the
//! holders hands them everything the replacement grants, so the caller must
//! be able to hand that out, or the right to delete roles alone would give
//! out the admin role by naming it as the replacement.
//!
//! Either way the delete waits until no group carries the role: a group
//! would go on naming a role that no longer exists, and its members would
//! lose what it gave them with nothing on record. The role comes off each
//! group first, as its own change. For the same reason it waits until no
//! pending invitation gives the role, as the person invited would accept
//! and get nothing, and until no federation connection or SCIM hands it
//! out. Those are changed first.

use std::sync::Arc;

use ianua_domain::domains::authorization::authority::TenantAuthority;
use ianua_domain::domains::authorization::permission::{RoleAction, SystemPermission};
use ianua_domain::domains::authorization::role::Role;
use ianua_domain::domains::authorization::role_reassignment::RoleReassignment;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::events::event::DomainEvent;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::RoleId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal, OrNotFound};
use crate::ports::authorization::{
    AccessRecordStore, GroupStore, RoleAssignmentStore, RoleDeletionUnitOfWork, RoleStore,
};
use crate::ports::federation::{ConnectionStore, ScimStore};
use crate::ports::identity::InvitationStore;
use crate::services::lookup::existing_role;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::authorization::lookup::access_records;
use crate::use_cases::authorization::stewardship::{Withdrawal, ensure_still_administered};

/// The ports [`DeleteUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct DeletePorts {
    /// Loads and deletes roles.
    pub role_store: Arc<dyn RoleStore>,
    /// Counts who holds the role.
    pub assignment_store: Arc<dyn RoleAssignmentStore>,
    /// Counts the groups carrying the role.
    pub group_store: Arc<dyn GroupStore>,
    /// Counts the invitations still waiting to give the role.
    pub invitation_store: Arc<dyn InvitationStore>,
    /// Counts the federation connections handing out the role.
    pub connection_store: Arc<dyn ConnectionStore>,
    /// Reads the SCIM endpoint, which may give the role to whom it makes.
    pub scim_store: Arc<dyn ScimStore>,
    /// Moves the holders and deletes the role together.
    pub unit_of_work: Arc<dyn RoleDeletionUnitOfWork>,
    /// Reads who holds what across the tenant, to keep an administrator.
    pub access_records: Arc<dyn AccessRecordStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Which role to delete, and where its holders go.
pub struct DeleteRequest {
    /// The role to delete.
    pub role_id: RoleId,
    /// The role its holders move onto, or `None` to refuse the delete while
    /// anyone holds it.
    pub replacement_role_id: Option<RoleId>,
}

/// Deletes a role of the caller's tenant.
pub struct DeleteUseCase {
    ports: DeletePorts,
}

impl DeleteUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: DeletePorts) -> Self {
        Self { ports }
    }
}

impl Command for DeleteUseCase {
    type Caller = CallerContext;
    type Input = DeleteRequest;
    type Output = Result<(), AppError>;

    /// Deletes `request.role_id`, moving its holders onto the replacement
    /// when one is named.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `Forbidden` without deletion rights, before reading the role.
    /// - `AppError::NotFound` for a missing role/replacement; `Forbidden` for ungrantable rights in either.
    /// - `AppError::Domain` for replacing a role with itself.
    /// - `AppError::Conflict` for group/invitation/federation/SCIM references, holders without a replacement, or loss of the last administrator.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: DeleteRequest,
    ) -> Result<(), AppError> {
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        authority
            .standing()
            .ensure_holds(SystemPermission::Roles(RoleAction::Delete))
            .map_err(AppError::from_domain)?;
        let mut role =
            existing_role(self.ports.role_store.as_ref(), &tenant, &request.role_id).await?;
        role.delete(&authority.standing())
            .map_err(AppError::from_domain)?;
        ensure_no_group_carries(self.ports.group_store.as_ref(), &tenant, role.id()).await?;
        ensure_no_invitation_gives(self.ports.invitation_store.as_ref(), &tenant, role.id())
            .await?;
        ensure_no_federation_gives(&self.ports, &tenant, role.id()).await?;
        let deletion = Deletion {
            tenant: &tenant,
            authority: &authority,
            role: &role,
        };
        let moved = deleted(&self.ports, &deletion, request.replacement_role_id).await?;

        let events: Vec<DomainEvent> = moved.into_iter().chain(role.take_events(&tenant)).collect();
        auditor
            .dispatch_by(&authority.actor(), events)
            .await
            .or_internal()?;
        Ok(())
    }
}

/// A role being deleted, by whom, in which tenant.
struct Deletion<'a> {
    /// The scope containing the definition and its holders.
    tenant: &'a ScopedTenant,
    /// Who deletes it.
    authority: &'a TenantAuthority,
    /// The permission definition to remove after holder checks.
    role: &'a Role<ResolvedTenant>,
}

/// Refuses deleting a role someone still holds directly.
async fn ensure_unheld(
    store: &dyn RoleAssignmentStore,
    tenant: &ScopedTenant,
    role_id: &RoleId,
) -> Result<(), AppError> {
    let holders = store.count_by_role(tenant, role_id).await.or_internal()?;
    if holders > 0 {
        return Err(AppError::Conflict(message!(
            "authorization-cannot-delete-role-with-active-assignments",
            "cannot delete role with active assignments"
        )));
    }
    Ok(())
}

/// Refuses deleting a role any group still carries.
async fn ensure_no_group_carries(
    store: &dyn GroupStore,
    tenant: &ScopedTenant,
    role_id: &RoleId,
) -> Result<(), AppError> {
    let carrying = store
        .count_carrying_role(tenant, role_id)
        .await
        .or_internal()?;
    if carrying > 0 {
        return Err(AppError::Conflict(message!(
            "authorization-cannot-delete-a-role-a-group",
            "cannot delete a role a group still carries"
        )));
    }
    Ok(())
}

/// Refuses deleting a role a pending invitation still gives: the person
/// invited would accept and get nothing, with nothing on record.
async fn ensure_no_invitation_gives(
    store: &dyn InvitationStore,
    tenant: &ScopedTenant,
    role_id: &RoleId,
) -> Result<(), AppError> {
    let waiting = store
        .count_pending_for_role(tenant, role_id)
        .await
        .or_internal()?;
    if waiting > 0 {
        return Err(AppError::Conflict(message!(
            "authorization-cannot-delete-a-role-a-pending",
            "cannot delete a role a pending invitation still gives; revoke the invitation first"
        )));
    }
    Ok(())
}

/// Refuses deleting a role a federation connection hands out, or the SCIM
/// endpoint gives the accounts it makes: they would go on handing out a
/// role that is gone.
async fn ensure_no_federation_gives(
    ports: &DeletePorts,
    tenant: &ScopedTenant,
    role_id: &RoleId,
) -> Result<(), AppError> {
    let connections = ports
        .connection_store
        .count_naming_role(tenant, role_id)
        .await
        .or_internal()?;
    let scim = ports.scim_store.find(tenant).await.or_internal()?;
    let scim_gives = scim.is_some_and(|endpoint| endpoint.default_role_id() == Some(role_id));
    if connections > 0 || scim_gives {
        return Err(AppError::Conflict(message!(
            "authorization-cannot-delete-a-role-a-federation",
            "cannot delete a role a federation connection or SCIM still hands out; change it there first"
        )));
    }
    Ok(())
}

/// Refuses a delete that leaves the tenant nobody can administer, its
/// holders moving onto `replacement` when there is one.
async fn ensure_administered_after(
    store: &dyn AccessRecordStore,
    deletion: &Deletion<'_>,
    replacement: Option<&RoleId>,
) -> Result<(), AppError> {
    let before = access_records(store, deletion.tenant).await?;
    let change = Withdrawal::RoleRemoved {
        role: deletion.role.id(),
        replacement,
    };
    ensure_still_administered(deletion.tenant, before, change)
}

/// Deletes the role, its holders moving onto `replacement` when one is
/// named, and gives back what the move raised: nothing when there was none.
async fn deleted(
    ports: &DeletePorts,
    deletion: &Deletion<'_>,
    replacement: Option<RoleId>,
) -> Result<Vec<DomainEvent>, AppError> {
    let Some(replacement) = replacement else {
        unheld_and_deleted(ports, deletion).await?;
        return Ok(Vec::new());
    };
    let mut moved = reassigned_and_deleted(ports, deletion, replacement).await?;
    Ok(moved.take_events(deletion.tenant))
}

/// Deletes a role nobody holds directly, once the tenant keeps an
/// administrator without it.
async fn unheld_and_deleted(ports: &DeletePorts, deletion: &Deletion<'_>) -> Result<(), AppError> {
    let role_id = deletion.role.id();
    ensure_unheld(ports.assignment_store.as_ref(), deletion.tenant, role_id).await?;
    ensure_administered_after(ports.access_records.as_ref(), deletion, None).await?;
    ports
        .role_store
        .delete(deletion.tenant, role_id)
        .await
        .or_internal()
}

/// Moves every holder onto `replacement_id` and deletes the role, together,
/// once the caller may hand out what the replacement grants and the tenant
/// keeps an administrator.
async fn reassigned_and_deleted(
    ports: &DeletePorts,
    deletion: &Deletion<'_>,
    replacement_id: RoleId,
) -> Result<RoleReassignment<ResolvedTenant>, AppError> {
    let mut reassignment =
        replacement(ports.role_store.as_ref(), deletion, &replacement_id).await?;
    ensure_administered_after(
        ports.access_records.as_ref(),
        deletion,
        Some(&replacement_id),
    )
    .await?;
    let count = ports
        .unit_of_work
        .reassign_and_delete(
            deletion.tenant,
            deletion.role.id(),
            &replacement_id,
            deletion.authority.actor(),
        )
        .await
        .or_internal()?;
    reassignment.record_reassignment(count);
    Ok(reassignment)
}

/// The move of the role's holders onto `replacement_id`, once it is
/// another role and the caller may hand out everything it grants.
async fn replacement(
    store: &dyn RoleStore,
    deletion: &Deletion<'_>,
    replacement_id: &RoleId,
) -> Result<RoleReassignment<ResolvedTenant>, AppError> {
    let to = store
        .find_by_id(deletion.tenant, replacement_id)
        .await
        .or_internal()?
        .or_not_found(message!(
            "authorization-replacement-role-not-found",
            "replacement role not found"
        ))?;
    RoleReassignment::plan(deletion.role, &to, &deletion.authority.standing())
        .map_err(AppError::from_domain)
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::group::{
        Group, GroupMembership, GroupMembershipRow, GroupOrigin, GroupPlace, GroupRow,
    };
    use ianua_domain::domains::authorization::role::{
        DefaultAssignment, NewRole, RoleAssignment, RoleAssignmentRow,
    };
    use ianua_domain::domains::federation::connection::MappedGrant;
    use ianua_domain::domains::federation::scim::{
        ScimActivation, ScimEndpoint, ScimEndpointRow, ScimRemoval,
    };
    use ianua_domain::shared::clock;
    use ianua_domain::types::{
        ActorRef, Enablement, Expiry, GroupId, Label, OrgUserId, PrincipalRef, Setting, TokenHash,
        UserId,
    };

    use super::*;
    use crate::context::{CallerIdentity, Credential};
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authorization::{
        AccessSources, FakeAccessRecordStore, FakeGroupMembershipStore, FakeGroupStore,
        FakeRoleAssignmentStore, FakeRoleDeletionUnitOfWork, FakeRoleStore,
    };
    use crate::test_support::federation::{
        FakeConnectionStore, FakeScimStore, test_connection_mapping_to,
    };
    use crate::test_support::identity::{FakeInvitationStore, InvitationSeed};
    use crate::test_support::{
        FakeEventDispatcher, block_on, test_auditor, test_ctx, test_session_id,
    };

    fn role(name: &str, system: Vec<SystemPermission>) -> Role<ResolvedTenant> {
        Role::provisioned(NewRole {
            id: RoleId::new(),
            name: Label::new("role_name", name).unwrap(),
            system_permissions: system,
            custom_permissions: Vec::new(),
            assignment: DefaultAssignment::Manual,
        })
    }

    fn admin_role() -> Role<ResolvedTenant> {
        role(
            "admin",
            vec![SystemPermission::ManageUsers, SystemPermission::ManageRoles],
        )
    }

    fn given(user: UserId, role: &Role<ResolvedTenant>) -> RoleAssignment<ResolvedTenant> {
        RoleAssignment::reconstitute(RoleAssignmentRow {
            principal: PrincipalRef::User(user),
            role_id: *role.id(),
            assigned_by: ActorRef::System,
            assigned_at: clock::now(),
            expires: Expiry::Never,
        })
        .unwrap()
    }

    /// A group carrying `role`, with `member` in it.
    fn group_carrying(
        role: &Role<ResolvedTenant>,
        member: UserId,
    ) -> (Group<ResolvedTenant>, GroupMembership<ResolvedTenant>) {
        let now = clock::now();
        let group = Group::reconstitute(GroupRow {
            id: GroupId::new(),
            name: Label::new("group_name", "Admins").unwrap(),
            origin: GroupOrigin::Dashboard,
            place: GroupPlace::TopLevel,
            role_ids: vec![*role.id()],
            created_at: now,
            updated_at: now,
        })
        .unwrap();
        let membership = GroupMembership::reconstitute(GroupMembershipRow {
            principal: PrincipalRef::User(member),
            group_id: *group.id(),
            joined_at: now,
            expires: Expiry::Never,
        })
        .unwrap();
        (group, membership)
    }

    /// A tenant's roles and who holds them, read by every port.
    struct Tenant {
        stores: AccessSources,
    }

    impl Tenant {
        fn with(roles: Vec<Role<ResolvedTenant>>) -> Self {
            Self {
                stores: AccessSources {
                    roles: Arc::new(FakeRoleStore::holding(test_ctx().tenant_id(), roles)),
                    ..AccessSources::default()
                },
            }
        }

        fn held_by(self, assignments: Vec<RoleAssignment<ResolvedTenant>>) -> Self {
            let tenant = test_ctx().tenant_id();
            Self {
                stores: AccessSources {
                    assignments: Arc::new(FakeRoleAssignmentStore::holding(tenant, assignments)),
                    ..self.stores
                },
            }
        }

        fn grouped(
            self,
            (group, membership): (Group<ResolvedTenant>, GroupMembership<ResolvedTenant>),
        ) -> Self {
            let tenant = test_ctx().tenant_id();
            Self {
                stores: AccessSources {
                    groups: Arc::new(FakeGroupStore::holding(tenant, [group])),
                    memberships: Arc::new(FakeGroupMembershipStore::holding(tenant, [membership])),
                    ..self.stores
                },
            }
        }

        fn ports(&self) -> DeletePorts {
            DeletePorts {
                role_store: self.stores.roles.clone(),
                assignment_store: self.stores.assignments.clone(),
                group_store: self.stores.groups.clone(),
                unit_of_work: Arc::new(FakeRoleDeletionUnitOfWork {
                    role_store: self.stores.roles.clone(),
                    assignment_store: self.stores.assignments.clone(),
                }),
                access_records: Arc::new(FakeAccessRecordStore::reading(self.stores.clone())),
                ..DeletePorts::fakes()
            }
        }

        fn holders_of(&self, role: &RoleId) -> usize {
            self.stores
                .assignments
                .holders_of(test_ctx().tenant_id(), role)
                .len()
        }
    }

    fn delete(
        ports: DeletePorts,
        sink: &Arc<FakeEventDispatcher>,
        role_id: RoleId,
        replacement_role_id: Option<RoleId>,
    ) -> Result<(), AppError> {
        block_on(DeleteUseCase::new(ports).execute(
            &test_ctx(),
            &test_auditor(sink.clone()),
            DeleteRequest {
                role_id,
                replacement_role_id,
            },
        ))
    }

    /// Ann deletes "editor", which nobody holds. It is gone, and the delete
    /// is recorded.
    #[test]
    fn a_role_nobody_holds_is_deleted_and_recorded() {
        let editor = role("editor", Vec::new());
        let id = *editor.id();
        let tenant = Tenant::with(vec![editor]);
        let sink = Arc::new(FakeEventDispatcher::new());

        delete(tenant.ports(), &sink, id, None).unwrap();

        assert_eq!(tenant.stores.roles.count(), 0);
        assert_eq!(
            sink.records.lock().unwrap().as_slice(),
            ["authorization.role_deleted"]
        );
    }

    /// Ann deletes a role the tenant does not have. It is not found.
    #[test]
    fn an_unknown_role_is_not_found() {
        let tenant = Tenant::with(Vec::new());

        let result = delete(
            tenant.ports(),
            &Arc::new(FakeEventDispatcher::new()),
            RoleId::new(),
            None,
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Ann deletes "editor" while Bob holds it, naming no replacement. She is
    /// refused and the role stays.
    #[test]
    fn a_held_role_without_a_replacement_is_kept() {
        let editor = role("editor", Vec::new());
        let id = *editor.id();
        let bob = given(UserId::new(), &editor);
        let tenant = Tenant::with(vec![editor]).held_by(vec![bob]);

        let result = delete(
            tenant.ports(),
            &Arc::new(FakeEventDispatcher::new()),
            id,
            None,
        );

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert_eq!(tenant.stores.roles.count(), 1);
    }

    /// A refused delete leaves no record behind.
    #[test]
    fn a_refused_delete_is_not_recorded() {
        let sink = Arc::new(FakeEventDispatcher::new());

        let _ = delete(Tenant::with(Vec::new()).ports(), &sink, RoleId::new(), None);

        assert!(sink.records.lock().unwrap().is_empty());
    }

    /// Ann deletes "editor", held by Bob and Carol, moving them onto
    /// "viewer". Both hold "viewer", "editor" is gone, and the move and the
    /// delete are recorded in that order.
    #[test]
    fn holders_move_onto_the_replacement_before_the_role_goes() {
        let (editor, viewer) = (role("editor", Vec::new()), role("viewer", Vec::new()));
        let (editor_id, viewer_id) = (*editor.id(), *viewer.id());
        let holders = vec![given(UserId::new(), &editor), given(UserId::new(), &editor)];
        let tenant = Tenant::with(vec![editor, viewer]).held_by(holders);
        let sink = Arc::new(FakeEventDispatcher::new());

        delete(tenant.ports(), &sink, editor_id, Some(viewer_id)).unwrap();

        assert_eq!(tenant.stores.roles.count(), 1);
        assert_eq!(tenant.holders_of(&editor_id), 0);
        assert_eq!(tenant.holders_of(&viewer_id), 2);
        assert_eq!(
            sink.records.lock().unwrap().as_slice(),
            [
                "authorization.role_reassigned",
                "authorization.role_deleted"
            ]
        );
    }

    /// Sam, an owner of Acme working in this tenant as an organization
    /// member, deletes "editor" and moves Bob onto "viewer". The move goes
    /// through, and Bob's new assignment says Sam gave it.
    #[test]
    fn an_organization_member_moves_holders_and_is_named_as_giving_them() {
        let (editor, viewer) = (role("editor", Vec::new()), role("viewer", Vec::new()));
        let (editor_id, viewer_id) = (*editor.id(), *viewer.id());
        let bob = given(UserId::new(), &editor);
        let tenant = Tenant::with(vec![editor, viewer]).held_by(vec![bob]);
        let sam = OrgUserId::new();
        let caller = CallerContext::new(
            CallerIdentity::OrgUser(sam),
            Credential::OrgSession(test_session_id()),
            test_ctx().organization_id(),
            test_ctx().tenant_id(),
            test_ctx().plan_limits().clone(),
        )
        .unwrap();

        block_on(DeleteUseCase::new(tenant.ports()).execute(
            &caller,
            &test_auditor(Arc::new(FakeEventDispatcher::new())),
            DeleteRequest {
                role_id: editor_id,
                replacement_role_id: Some(viewer_id),
            },
        ))
        .unwrap();

        let moved = tenant
            .stores
            .assignments
            .of_tenant(test_ctx().tenant_id())
            .unwrap();
        assert_eq!(moved.len(), 1);
        assert_eq!(moved[0].role_id(), &viewer_id);
        assert!(matches!(moved[0].assigned_by(), ActorRef::OrgUser(id) if *id == sam));
    }

    /// The record of moving Bob from "editor" onto "viewer" names both
    /// roles, and the delete names "editor".
    #[test]
    fn the_records_name_the_vacated_and_the_receiving_role() {
        let (editor, viewer) = (role("editor", Vec::new()), role("viewer", Vec::new()));
        let (editor_id, viewer_id) = (*editor.id(), *viewer.id());
        let bob = given(UserId::new(), &editor);
        let tenant = Tenant::with(vec![editor, viewer]).held_by(vec![bob]);
        let sink = Arc::new(FakeEventDispatcher::new());

        delete(tenant.ports(), &sink, editor_id, Some(viewer_id)).unwrap();

        let moved = "authorization.role_reassigned";
        assert_eq!(sink.label_of(moved, "from_role").as_deref(), Some("editor"));
        assert_eq!(sink.label_of(moved, "to_role").as_deref(), Some("viewer"));
        assert_eq!(
            sink.label_of("authorization.role_deleted", "role")
                .as_deref(),
            Some("editor")
        );
    }

    /// Ann names "editor" as its own replacement. She is told the
    /// replacement must be another role, and "editor" stays.
    #[test]
    fn a_role_cannot_replace_itself() {
        let editor = role("editor", Vec::new());
        let id = *editor.id();
        let tenant = Tenant::with(vec![editor]);

        let result = delete(
            tenant.ports(),
            &Arc::new(FakeEventDispatcher::new()),
            id,
            Some(id),
        );

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert_eq!(tenant.stores.roles.count(), 1);
    }

    /// Ann names a replacement the tenant does not have. It is not found and
    /// "editor" stays.
    #[test]
    fn an_unknown_replacement_is_not_found() {
        let editor = role("editor", Vec::new());
        let id = *editor.id();
        let tenant = Tenant::with(vec![editor]);

        let result = delete(
            tenant.ports(),
            &Arc::new(FakeEventDispatcher::new()),
            id,
            Some(RoleId::new()),
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(tenant.stores.roles.count(), 1);
    }

    /// Sam's delete permission cannot grant admin through a replacement.
    /// Deletion is forbidden: both roles remain, nobody gains admin and
    /// no event is recorded.
    #[test]
    fn a_replacement_beyond_the_callers_rights_is_refused() {
        let (editor, admin) = (role("editor", Vec::new()), admin_role());
        let (editor_id, admin_id) = (*editor.id(), *admin.id());
        let bob = given(UserId::new(), &editor);
        let tenant = Tenant::with(vec![editor, admin]).held_by(vec![bob]);
        let sam = DeletePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
                SystemPermission::Roles(RoleAction::Delete),
            ])),
            ..tenant.ports()
        };
        let sink = Arc::new(FakeEventDispatcher::new());

        let result = delete(sam, &sink, editor_id, Some(admin_id));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(tenant.stores.roles.count(), 2);
        assert_eq!(tenant.holders_of(&admin_id), 0);
        assert!(sink.records.lock().unwrap().is_empty());
    }

    /// Replacing the last administrator's role with viewer conflicts.
    /// Ann retains her admin assignment.
    #[test]
    fn moving_the_last_administrator_onto_a_lesser_role_is_refused() {
        let (admin, viewer) = (admin_role(), role("viewer", Vec::new()));
        let (admin_id, viewer_id) = (*admin.id(), *viewer.id());
        let ann = given(UserId::new(), &admin);
        let tenant = Tenant::with(vec![admin, viewer]).held_by(vec![ann]);

        let result = delete(
            tenant.ports(),
            &Arc::new(FakeEventDispatcher::new()),
            admin_id,
            Some(viewer_id),
        );

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert_eq!(tenant.holders_of(&admin_id), 1);
    }

    /// Admins still references the admin role even though no user holds it
    /// directly. Deleting that role conflicts and leaves it stored.
    #[test]
    fn deleting_the_role_a_group_makes_its_last_administrator_is_refused() {
        let admin = admin_role();
        let id = *admin.id();
        let grouped = group_carrying(&admin, UserId::new());
        let tenant = Tenant::with(vec![admin]).grouped(grouped);

        let result = delete(
            tenant.ports(),
            &Arc::new(FakeEventDispatcher::new()),
            id,
            None,
        );

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert_eq!(tenant.stores.roles.count(), 1);
    }

    /// Support's reference to editor blocks its deletion with or without
    /// a replacement. Both roles remain and no event is recorded.
    #[test]
    fn a_role_a_group_carries_is_kept() {
        let replacements: [fn(RoleId) -> Option<RoleId>; 2] = [|_| None, Some];
        for replacement_of in replacements {
            let (editor, viewer) = (role("editor", Vec::new()), role("viewer", Vec::new()));
            let (id, replacement) = (*editor.id(), replacement_of(*viewer.id()));
            let grouped = group_carrying(&editor, UserId::new());
            let tenant = Tenant::with(vec![editor, viewer]).grouped(grouped);
            let sink = Arc::new(FakeEventDispatcher::new());

            let result = delete(tenant.ports(), &sink, id, replacement);

            assert!(matches!(result, Err(AppError::Conflict(_))), "{result:?}");
            assert_eq!(tenant.stores.roles.count(), 2);
            assert!(sink.records.lock().unwrap().is_empty());
        }
    }

    /// A pending invitation still names editor. Deletion conflicts with or
    /// without a replacement, keeping both roles and recording no event.
    #[test]
    fn a_role_a_pending_invitation_gives_is_kept() {
        let replacements: [fn(RoleId) -> Option<RoleId>; 2] = [|_| None, Some];
        for replacement_of in replacements {
            let (editor, viewer) = (role("editor", Vec::new()), role("viewer", Vec::new()));
            let (id, replacement) = (*editor.id(), replacement_of(*viewer.id()));
            let invitation =
                InvitationSeed::for_user(UserId::new(), "ana@acme.com", id, "ana").stored();
            let tenant = Tenant::with(vec![editor, viewer]);
            let ann = DeletePorts {
                invitation_store: Arc::new(FakeInvitationStore::holding(invitation)),
                ..tenant.ports()
            };
            let sink = Arc::new(FakeEventDispatcher::new());

            let result = delete(ann, &sink, id, replacement);

            assert!(matches!(result, Err(AppError::Conflict(_))), "{result:?}");
            assert_eq!(tenant.stores.roles.count(), 2);
            assert!(sink.records.lock().unwrap().is_empty());
        }
    }

    /// The federation mapping from engineering to editor blocks deletion.
    /// The request conflicts and both stored roles remain.
    #[test]
    fn a_role_a_federation_connection_hands_out_is_kept() {
        let (editor, viewer) = (role("editor", Vec::new()), role("viewer", Vec::new()));
        let id = *editor.id();
        let okta = test_connection_mapping_to(MappedGrant::Role(id));
        let tenant = Tenant::with(vec![editor, viewer]);
        let ann = DeletePorts {
            connection_store: Arc::new(FakeConnectionStore::holding(&test_ctx().tenant(), [okta])),
            ..tenant.ports()
        };

        let result = delete(ann, &Arc::new(FakeEventDispatcher::new()), id, None);

        assert!(matches!(result, Err(AppError::Conflict(_))), "{result:?}");
        assert_eq!(tenant.stores.roles.count(), 2);
    }

    /// Editor is the SCIM default role. Deleting it conflicts and leaves
    /// the role stored for provisioning.
    #[test]
    fn a_role_scim_gives_new_accounts_is_kept() {
        let editor = role("editor", Vec::new());
        let id = *editor.id();
        let endpoint = ScimEndpoint::reconstitute(ScimEndpointRow {
            bearer_token_hash: TokenHash::from_stored("scim-hash".to_owned()),
            enabled: Enablement::Enabled,
            default_role_id: Setting::Set(id),
            auto_activate: ScimActivation::Immediate,
            deactivate_on_remove: ScimRemoval::Deactivate,
            last_sync_at: None,
            created_at: clock::now(),
        })
        .unwrap();
        let tenant = Tenant::with(vec![editor]);
        let ann = DeletePorts {
            scim_store: Arc::new(FakeScimStore::holding(&test_ctx().tenant(), endpoint)),
            ..tenant.ports()
        };

        let result = delete(ann, &Arc::new(FakeEventDispatcher::new()), id, None);

        assert!(matches!(result, Err(AppError::Conflict(_))), "{result:?}");
        assert_eq!(tenant.stores.roles.count(), 1);
    }

    /// Delete permission alone cannot remove a role granting user
    /// management. Sam lacks that right, so deletion is forbidden and
    /// admin remains stored.
    #[test]
    fn a_role_granting_more_than_the_caller_holds_is_kept() {
        let admin = admin_role();
        let id = *admin.id();
        let tenant = Tenant::with(vec![admin]);
        let sam = DeletePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
                SystemPermission::Roles(RoleAction::Delete),
            ])),
            ..tenant.ports()
        };

        let result = delete(sam, &Arc::new(FakeEventDispatcher::new()), id, None);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(tenant.stores.roles.count(), 1);
    }

    /// Mallory lacks role-delete permission. Her request is forbidden and
    /// editor remains stored.
    #[test]
    fn a_caller_who_may_not_delete_roles_is_refused() {
        let editor = role("editor", Vec::new());
        let id = *editor.id();
        let tenant = Tenant::with(vec![editor]);
        let ports = DeletePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[])),
            ..tenant.ports()
        };

        let result = delete(ports, &Arc::new(FakeEventDispatcher::new()), id, None);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(tenant.stores.roles.count(), 1);
    }

    /// Deleting an unknown role without role-delete permission returns
    /// forbidden rather than disclosing that the role is missing.
    #[test]
    fn a_caller_who_may_not_delete_roles_is_refused_for_an_unknown_role_too() {
        let tenant = Tenant::with(vec![role("editor", Vec::new())]);
        let ports = DeletePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[])),
            ..tenant.ports()
        };

        let result = delete(
            ports,
            &Arc::new(FakeEventDispatcher::new()),
            RoleId::new(),
            None,
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// Signed-out authority cannot delete editor: the result is
    /// unauthenticated and the role remains stored.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let editor = role("editor", Vec::new());
        let id = *editor.id();
        let tenant = Tenant::with(vec![editor]);
        let ports = DeletePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..tenant.ports()
        };

        let result = delete(ports, &Arc::new(FakeEventDispatcher::new()), id, None);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(tenant.stores.roles.count(), 1);
    }
}
