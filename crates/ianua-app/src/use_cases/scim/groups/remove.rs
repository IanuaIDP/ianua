//! Remove SCIM group: the directory deletes a group it keeps. Its members
//! lose what it gave them.

use std::sync::Arc;

use ianua_domain::domains::authorization::group_tree::GroupTree;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::GroupId;

use crate::acting::ScimAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::ScimCaller;
use crate::error::{AppError, OrInternal};
use crate::ports::authorization::{AccessRecordStore, GroupMembershipStore, GroupStore};
use crate::ports::federation::ScimStore;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::scim::groups::roster::{
    Withdrawn, directory_group, ensure_leaves_an_administrator, user_members,
};
use crate::use_cases::scim::sync::record_synced;

/// The ports [`RemoveScimUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RemoveScimPorts {
    /// Signs the directory in with its token.
    pub scim_authorities: Arc<dyn ScimAuthorities>,
    /// Records when the directory last synced.
    pub scim_store: Arc<dyn ScimStore>,
    /// Loads and deletes groups.
    pub group_store: Arc<dyn GroupStore>,
    /// Who is in the group deleted.
    pub membership_store: Arc<dyn GroupMembershipStore>,
    /// What the group's members hold, to keep an administrator.
    pub access_records: Arc<dyn AccessRecordStore>,
}

/// Deletes groups a tenant's directory keeps.
pub struct RemoveScimUseCase {
    ports: RemoveScimPorts,
}

impl RemoveScimUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: RemoveScimPorts) -> Self {
        Self { ports }
    }

    /// Refuses deleting `group_id` when its users leaving it takes the
    /// tenant's last administrator away. A group with no group under it
    /// reaches only its own members, so only their records are read, with
    /// the tenant's count of administrators.
    async fn ensure_members_leave_an_administrator(
        &self,
        tenant: &ScopedTenant,
        group_id: &GroupId,
    ) -> Result<(), AppError> {
        let members = self
            .ports
            .membership_store
            .find_by_group(tenant, group_id)
            .await
            .or_internal()?;
        let leaving = user_members(&members);
        let withdrawn = Withdrawn {
            group: group_id,
            leaving: &leaving,
        };
        ensure_leaves_an_administrator(self.ports.access_records.as_ref(), tenant, withdrawn).await
    }
}

impl Command for RemoveScimUseCase {
    type Caller = ScimCaller;
    type Input = GroupId;
    type Output = Result<(), AppError>;

    /// Deletes the group with `group_id`, records
    /// `authorization.group_deleted` by the system, and the sync.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the directory's token is missing,
    ///   not the tenant's current one, or SCIM is switched off.
    /// - `AppError::NotFound` when the tenant has no such group, or a person
    ///   keeps it in the dashboard.
    /// - `AppError::Conflict` when another group sits under it, or deleting
    ///   it leaves the tenant nobody to administer it.
    /// - `AppError::Internal` on persistence or audit failure.
    async fn execute(
        &self,
        caller: &ScimCaller,
        auditor: &RequestAuditor,
        group_id: GroupId,
    ) -> Result<(), AppError> {
        let tenant = caller.tenant();
        let endpoint = self.ports.scim_authorities.endpoint(caller).await?;
        let groups = self.ports.group_store.as_ref();
        let mut group = directory_group(groups, tenant, &group_id).await?;
        let under = groups
            .list_children(tenant, &group_id)
            .await
            .or_internal()?;
        group
            .delete_by_directory(&GroupTree::new(&under), &endpoint)
            .map_err(AppError::from_domain)?;
        self.ensure_members_leave_an_administrator(tenant, &group_id)
            .await?;

        groups.delete(tenant, &group_id).await.or_internal()?;
        record_synced(
            self.ports.scim_store.as_ref(),
            tenant,
            endpoint,
            auditor,
            group.take_events(tenant),
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::group::{Group, GroupOrigin, GroupPlace, GroupRow};
    use ianua_domain::domains::authorization::permission::SystemPermission;
    use ianua_domain::isolation::scope::ResolvedTenant;
    use ianua_domain::shared::clock;
    use ianua_domain::types::{Label, PrincipalRef, TenantId, UserId};

    use super::*;
    use crate::test_support::authorization::{
        AccessSources, FakeAccessRecordStore, FakeGroupMembershipStore, FakeGroupStore,
        FakeRoleStore, stored_membership, stored_role,
    };
    use crate::test_support::scim::{
        SignInRefusal, kept_group, refused_sign_in, scim_caller, signed_in,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    fn group_row(name: &str, place: GroupPlace) -> GroupRow {
        let now = clock::now();
        GroupRow {
            id: GroupId::new(),
            name: Label::new("displayName", name).unwrap(),
            origin: GroupOrigin::Directory,
            place,
            role_ids: Vec::new(),
            created_at: now,
            updated_at: now,
        }
    }

    struct Acme {
        groups: Arc<FakeGroupStore>,
        sources: AccessSources,
        records: Arc<FakeAccessRecordStore>,
    }

    fn acme_holding(groups: Vec<Group<ResolvedTenant>>) -> Acme {
        let groups = Arc::new(FakeGroupStore::holding(test_ctx().tenant_id(), groups));
        let sources = AccessSources {
            groups: groups.clone(),
            ..AccessSources::default()
        };
        Acme::reading(groups, sources)
    }

    impl Acme {
        /// Acme with `groups`, its records read from `sources`.
        fn reading(groups: Arc<FakeGroupStore>, sources: AccessSources) -> Self {
            Self {
                groups,
                records: Arc::new(FakeAccessRecordStore::reading(sources.clone())),
                sources,
            }
        }

        fn remove_with(
            &self,
            scim_authorities: Arc<dyn ScimAuthorities>,
            caller: &ScimCaller,
            group_id: GroupId,
        ) -> Result<(), AppError> {
            let use_case = RemoveScimUseCase::new(RemoveScimPorts {
                scim_authorities,
                group_store: self.groups.clone(),
                membership_store: self.sources.memberships.clone(),
                access_records: self.records.clone(),
                ..RemoveScimPorts::fakes()
            });
            let auditor = test_auditor(Arc::new(FakeEventDispatcher::new()));
            block_on(use_case.execute(caller, &auditor, group_id))
        }

        fn remove(&self, group_id: GroupId) -> Result<(), AppError> {
            self.remove_with(signed_in(), &scim_caller(), group_id)
        }
    }

    /// Okta deletes Engineering, a group it keeps. It is gone.
    #[test]
    fn a_group_is_deleted() {
        let engineering = kept_group("Engineering", GroupOrigin::Directory);
        let id = *engineering.id();
        let acme = acme_holding(vec![engineering]);

        acme.remove(id).unwrap();

        assert_eq!(acme.groups.count(), 0);
    }

    /// Deleting a group maintained through the dashboard returns not found
    /// to the directory and leaves the group stored.
    #[test]
    fn a_group_the_directory_does_not_keep_is_not_found() {
        let admins = kept_group("Admins", GroupOrigin::Dashboard);
        let id = *admins.id();
        let acme = acme_holding(vec![admins]);

        let result = acme.remove(id);

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(acme.groups.count(), 1);
    }

    /// Deleting another tenant's group returns not found and leaves the
    /// group stored.
    #[test]
    fn a_group_of_another_tenant_is_not_found() {
        let globex = kept_group("Engineering", GroupOrigin::Directory);
        let id = *globex.id();
        let acme = acme_holding(Vec::new());
        let groups = FakeGroupStore::holding(TenantId::new(), [globex]);
        let acme = Acme {
            groups: Arc::new(groups),
            ..acme
        };

        let result = acme.remove(id);

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(acme.groups.count(), 1);
    }

    /// Ann put a group of her own under Engineering. Okta deletes
    /// Engineering, and it stays until the group under it moves.
    #[test]
    fn a_group_with_groups_under_it_is_kept() {
        let engineering =
            Group::reconstitute(group_row("Engineering", GroupPlace::TopLevel)).unwrap();
        let id = *engineering.id();
        let platform = Group::reconstitute(group_row("Platform", GroupPlace::Under(id))).unwrap();
        let acme = acme_holding(vec![engineering, platform]);

        let result = acme.remove(id);

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert_eq!(acme.groups.count(), 2);
    }

    /// Deleting the group that grants the sole administrator their owner
    /// role returns a conflict and leaves the group stored.
    #[test]
    fn a_group_holding_the_last_administrator_is_kept() {
        let owner = stored_role("Owner", SystemPermission::all().to_vec(), Vec::new());
        let engineering = Group::reconstitute(GroupRow {
            role_ids: vec![*owner.id()],
            ..group_row("Engineering", GroupPlace::TopLevel)
        })
        .unwrap();
        let id = *engineering.id();
        let tenant = test_ctx().tenant_id();
        let ada_in = stored_membership(PrincipalRef::User(UserId::new()), id);
        let acme = acme_holding(vec![engineering]);
        let sources = AccessSources {
            roles: Arc::new(FakeRoleStore::holding(tenant, [owner])),
            memberships: Arc::new(FakeGroupMembershipStore::holding(tenant, [ada_in])),
            ..acme.sources.clone()
        };
        let acme = Acme::reading(acme.groups, sources);

        let result = acme.remove(id);

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert_eq!(acme.groups.count(), 1);
    }

    /// Okta deletes Engineering, where Ada and Grace sit. Whether Acme keeps
    /// an administrator is worked out from their records and the tenant's
    /// count; the rest of Acme's records are never read.
    #[test]
    fn deleting_a_group_reads_only_its_members_records() {
        let engineering = kept_group("Engineering", GroupOrigin::Directory);
        let id = *engineering.id();
        let tenant = test_ctx().tenant_id();
        let members = [UserId::new(), UserId::new()]
            .map(|user| stored_membership(PrincipalRef::User(user), id));
        let acme = acme_holding(vec![engineering]);
        let sources = AccessSources {
            memberships: Arc::new(FakeGroupMembershipStore::holding(tenant, members)),
            ..acme.sources.clone()
        };
        let acme = Acme::reading(acme.groups, sources);

        acme.remove(id).unwrap();

        assert_eq!(acme.groups.count(), 0);
        assert_eq!(acme.records.whole_reads(), 0);
    }

    /// Missing, invalid or rotated tokens and disabled SCIM each return an
    /// unauthenticated error without deleting the group.
    #[test]
    fn a_directory_that_is_not_signed_in_is_refused() {
        for refusal in SignInRefusal::ALL {
            let engineering = kept_group("Engineering", GroupOrigin::Directory);
            let id = *engineering.id();
            let acme = acme_holding(vec![engineering]);
            let (scim_authorities, caller) = refused_sign_in(refusal);

            let result = acme.remove_with(scim_authorities, &caller, id);

            assert!(
                matches!(result, Err(AppError::Unauthenticated)),
                "{refusal:?}"
            );
            assert_eq!(acme.groups.count(), 1);
        }
    }
}
