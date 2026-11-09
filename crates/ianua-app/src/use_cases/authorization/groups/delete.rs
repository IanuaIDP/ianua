//! Delete group: remove a group from the tenant, and with it what its
//! members held through it.

use std::sync::Arc;

use ianua_domain::domains::authorization::authority::TenantAuthority;
use ianua_domain::domains::authorization::group::{Group, GroupPlace};
use ianua_domain::domains::authorization::group_tree::GroupTree;
use ianua_domain::domains::authorization::permission::{RoleAction, SystemPermission};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::GroupId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::authorization::{AccessRecordStore, GroupStore};
use crate::ports::federation::ConnectionStore;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::authorization::groups::placement::conferred_at;
use crate::use_cases::authorization::lookup::{access_records, existing_group};
use crate::use_cases::authorization::stewardship::{Withdrawal, ensure_still_administered};

/// The ports [`DeleteUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct DeletePorts {
    /// Loads and deletes groups.
    pub group_store: Arc<dyn GroupStore>,
    /// Reads the tenant's groups, roles and who holds what.
    pub access_records: Arc<dyn AccessRecordStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
    /// Counts the federation connections putting people in the group.
    pub connection_store: Arc<dyn ConnectionStore>,
}

/// Deletes a group of the caller's tenant.
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
    type Input = GroupId;
    type Output = Result<(), AppError>;

    /// Deletes `group_id`, for the caller.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `Forbidden` without role-deletion rights, before reading the group.
    /// - `AppError::NotFound` for a missing group; `Forbidden` when the caller could not grant its members' inherited access.
    /// - `AppError::Conflict` for child groups, federation mappings or removal of the last administrator.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        group_id: GroupId,
    ) -> Result<(), AppError> {
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        authority
            .standing()
            .ensure_holds(SystemPermission::Roles(RoleAction::Delete))
            .map_err(AppError::from_domain)?;
        let mut group = existing_group(self.ports.group_store.as_ref(), &tenant, &group_id).await?;
        ensure_no_connection_fills(self.ports.connection_store.as_ref(), &tenant, &group_id)
            .await?;
        delete(&self.ports, &tenant, &authority, &mut group).await?;

        self.ports
            .group_store
            .delete(&tenant, &group_id)
            .await
            .or_internal()?;
        auditor
            .dispatch_by(&authority.actor(), group.take_events(&tenant))
            .await
            .or_internal()?;
        Ok(())
    }
}

/// Refuses deleting a group a federation connection puts people in: the
/// connection would go on mapping its provider's group to a group that is
/// gone.
async fn ensure_no_connection_fills(
    store: &dyn ConnectionStore,
    tenant: &ScopedTenant,
    group_id: &GroupId,
) -> Result<(), AppError> {
    let mapping = store
        .count_naming_group(tenant, group_id)
        .await
        .or_internal()?;
    if mapping > 0 {
        return Err(AppError::Conflict(message!(
            "authorization-cannot-delete-a-group-a-federation",
            "cannot delete a group a federation connection still maps people into; change the mapping first"
        )));
    }
    Ok(())
}

/// Deletes `group` for `authority`, once it may, the group has no
/// subgroups, and the tenant keeps an administrator without it.
async fn delete(
    ports: &DeletePorts,
    tenant: &ScopedTenant,
    authority: &TenantAuthority,
    group: &mut Group<ResolvedTenant>,
) -> Result<(), AppError> {
    let store = ports.access_records.as_ref();
    let records = access_records(store, tenant).await?;
    let conferred = conferred_at(&records, GroupPlace::Under(*group.id()))?;
    group
        .delete(
            &GroupTree::new(&records.groups),
            &conferred,
            &authority.standing(),
        )
        .map_err(AppError::from_domain)?;
    ensure_still_administered(tenant, records, Withdrawal::GroupDeleted(group.id()))
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::role::Role;
    use ianua_domain::domains::federation::connection::MappedGrant;
    use ianua_domain::types::{PrincipalRef, UserId};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authorization::{
        AccessSources, FakeAccessRecordStore, FakeGroupMembershipStore, FakeGroupStore,
        FakeRoleStore, stored_group, stored_membership, stored_role,
    };
    use crate::test_support::federation::{FakeConnectionStore, test_connection_mapping_to};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    fn admin_role() -> Role<ResolvedTenant> {
        stored_role(
            "admin",
            vec![SystemPermission::ManageUsers, SystemPermission::ManageRoles],
            Vec::new(),
        )
    }

    /// A tenant's groups, roles and members, read by every port.
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

        fn joined(self, member: UserId, group: GroupId) -> Self {
            let membership = stored_membership(PrincipalRef::User(member), group);
            let memberships =
                FakeGroupMembershipStore::holding(test_ctx().tenant_id(), [membership]);
            Self {
                stores: AccessSources {
                    memberships: Arc::new(memberships),
                    ..self.stores
                },
            }
        }

        fn ports(&self) -> DeletePorts {
            DeletePorts {
                group_store: self.stores.groups.clone(),
                access_records: Arc::new(FakeAccessRecordStore::reading(self.stores.clone())),
                ..DeletePorts::fakes()
            }
        }

        fn ports_holding(&self, system: &[SystemPermission]) -> DeletePorts {
            DeletePorts {
                tenant_authorities: Arc::new(FakeTenantAuthorities::holding(system)),
                ..self.ports()
            }
        }
    }

    fn top(name: &str) -> Group<ResolvedTenant> {
        stored_group(name, GroupPlace::TopLevel, Vec::new())
    }

    fn delete(
        ports: DeletePorts,
        sink: &Arc<FakeEventDispatcher>,
        group_id: GroupId,
    ) -> Result<(), AppError> {
        block_on(DeleteUseCase::new(ports).execute(
            &test_ctx(),
            &test_auditor(sink.clone()),
            group_id,
        ))
    }

    /// Ann deletes "Engineering". It is gone and the delete is recorded.
    #[test]
    fn a_group_is_deleted_and_recorded() {
        let engineering = top("Engineering");
        let id = *engineering.id();
        let tenant = Tenant::with(vec![engineering], Vec::new());
        let sink = Arc::new(FakeEventDispatcher::new());

        delete(tenant.ports(), &sink, id).unwrap();

        assert_eq!(tenant.stores.groups.count(), 0);
        assert_eq!(
            sink.records.lock().unwrap().as_slice(),
            ["authorization.group_deleted"]
        );
    }

    /// A federation mapping prevents deleting Engineering. The group stays
    /// stored and no deletion is recorded.
    #[test]
    fn a_group_a_federation_connection_maps_into_is_kept() {
        let engineering = top("Engineering");
        let id = *engineering.id();
        let okta = test_connection_mapping_to(MappedGrant::Group(id));
        let tenant = Tenant::with(vec![engineering], Vec::new());
        let ports = DeletePorts {
            connection_store: Arc::new(FakeConnectionStore::holding(&test_ctx().tenant(), [okta])),
            ..tenant.ports()
        };
        let sink = Arc::new(FakeEventDispatcher::new());

        let result = delete(ports, &sink, id);

        assert!(matches!(result, Err(AppError::Conflict(_))), "{result:?}");
        assert_eq!(tenant.stores.groups.count(), 1);
        assert!(sink.records.lock().unwrap().is_empty());
    }

    /// Ann deletes a group the tenant does not have. It is not found and
    /// nothing is recorded.
    #[test]
    fn an_unknown_group_is_not_found_and_not_recorded() {
        let tenant = Tenant::with(Vec::new(), Vec::new());
        let sink = Arc::new(FakeEventDispatcher::new());

        let result = delete(tenant.ports(), &sink, GroupId::new());

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(sink.records.lock().unwrap().is_empty());
    }

    /// Ann deletes "Engineering" while "Backend" sits under it. She is
    /// refused, so "Backend" is not left under a group that is gone.
    #[test]
    fn a_group_with_subgroups_is_kept() {
        let engineering = top("Engineering");
        let id = *engineering.id();
        let backend = stored_group("Backend", GroupPlace::Under(id), Vec::new());
        let tenant = Tenant::with(vec![engineering, backend], Vec::new());

        let result = delete(tenant.ports(), &Arc::new(FakeEventDispatcher::new()), id);

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert_eq!(tenant.stores.groups.count(), 2);
    }

    /// Role deletion permission cannot remove a group carrying rights the
    /// caller could not grant. The admin group stays stored.
    #[test]
    fn a_group_bringing_more_than_the_caller_holds_is_kept() {
        let admin = admin_role();
        let admins = stored_group("Admins", GroupPlace::TopLevel, vec![*admin.id()]);
        let id = *admins.id();
        let tenant = Tenant::with(vec![admins], vec![admin]);
        let sam = tenant.ports_holding(&[SystemPermission::Roles(RoleAction::Delete)]);

        let result = delete(sam, &Arc::new(FakeEventDispatcher::new()), id);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(tenant.stores.groups.count(), 1);
    }

    /// Deleting the last administrator's group is a conflict and preserves it.
    #[test]
    fn deleting_the_group_of_the_last_administrator_is_refused() {
        let admin = admin_role();
        let admins = stored_group("Admins", GroupPlace::TopLevel, vec![*admin.id()]);
        let id = *admins.id();
        let tenant = Tenant::with(vec![admins], vec![admin]).joined(UserId::new(), id);

        let result = delete(tenant.ports(), &Arc::new(FakeEventDispatcher::new()), id);

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert_eq!(tenant.stores.groups.count(), 1);
    }

    /// Without role deletion permission, Engineering cannot be deleted and stays stored.
    #[test]
    fn a_caller_who_may_not_delete_roles_is_refused() {
        let engineering = top("Engineering");
        let id = *engineering.id();
        let tenant = Tenant::with(vec![engineering], Vec::new());

        let result = delete(
            tenant.ports_holding(&[]),
            &Arc::new(FakeEventDispatcher::new()),
            id,
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(tenant.stores.groups.count(), 1);
    }

    /// A signed-out session cannot delete Engineering; the group stays stored.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let engineering = top("Engineering");
        let id = *engineering.id();
        let tenant = Tenant::with(vec![engineering], Vec::new());
        let ports = DeletePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..tenant.ports()
        };

        let result = delete(ports, &Arc::new(FakeEventDispatcher::new()), id);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(tenant.stores.groups.count(), 1);
    }
}
