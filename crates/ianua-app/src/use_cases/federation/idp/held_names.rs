//! The names of the roles and groups a person holds, which a SAML app's
//! attribute statements may send.

use std::collections::HashMap;

use ianua_domain::shared::clock;
use ianua_domain::types::{Label, PrincipalRef, UserId};

use crate::error::{AppError, OrInternal};
use crate::ports::authorization::{GroupMembershipStore, GroupStore, RoleStore};
use crate::tenancy::ScopedTenant;

/// The names a person's roles and groups go by.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(super) struct Held {
    /// Every role they hold, given straight or through a group.
    pub(super) roles: Vec<Label>,
    /// Every group they sit in now.
    pub(super) groups: Vec<Label>,
}

/// Where a person's roles and groups are read.
pub(super) struct HeldNameSources<'a> {
    /// The roles each person holds.
    pub(super) roles: &'a dyn RoleStore,
    /// Who sits in which group.
    pub(super) memberships: &'a dyn GroupMembershipStore,
    /// The tenant's groups, for their names.
    pub(super) groups: &'a dyn GroupStore,
}

impl HeldNameSources<'_> {
    /// The names of what `user` holds in `tenant` now.
    ///
    /// # Errors
    ///
    /// - `AppError::Internal` on storage failure.
    pub(super) async fn of(&self, tenant: &ScopedTenant, user: UserId) -> Result<Held, AppError> {
        let principal = PrincipalRef::User(user);
        let roles = self
            .roles
            .find_effective_by_principal(tenant, &principal)
            .await
            .or_internal()?
            .iter()
            .map(|role| role.name().clone())
            .collect();
        Ok(Held {
            roles,
            groups: self.group_names(tenant, &principal).await?,
        })
    }

    /// The names of the groups `principal` sits in now. A group gone since
    /// is left out.
    async fn group_names(
        &self,
        tenant: &ScopedTenant,
        principal: &PrincipalRef,
    ) -> Result<Vec<Label>, AppError> {
        let now = clock::now();
        let memberships = self
            .memberships
            .find_by_principal(tenant, principal)
            .await
            .or_internal()?;
        let ids: Vec<_> = memberships
            .iter()
            .filter(|held| held.is_in_force(now))
            .map(|held| *held.group_id())
            .collect();
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let groups = self.groups.find_by_ids(tenant, &ids).await.or_internal()?;
        let names: HashMap<_, _> = groups
            .iter()
            .map(|group| (*group.id(), group.name()))
            .collect();
        Ok(ids
            .iter()
            .filter_map(|id| names.get(id).copied().cloned())
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::group::{GroupMembership, GroupPlace};
    use ianua_domain::isolation::scope::ResolvedTenant;
    use ianua_domain::types::{Expiry, GroupId};
    use time::Duration;

    use super::*;
    use crate::test_support::authorization::{
        FakeGroupMembershipStore, FakeGroupStore, FakeRoleStore, stored_group, stored_membership,
        stored_membership_until,
    };
    use crate::test_support::{block_on, test_ctx};

    /// A membership that ended yesterday and cannot disclose a group name today.
    fn expired_membership(
        principal: PrincipalRef,
        group: GroupId,
    ) -> GroupMembership<ResolvedTenant> {
        stored_membership_until(principal, group, Expiry::At(clock::now() - Duration::DAY))
    }

    /// Current groups are read together and kept in membership order;
    /// expired memberships and groups gone since joining release no name.
    #[test]
    fn current_group_names_share_one_read() {
        let tenant = test_ctx().tenant();
        let user = UserId::new();
        let principal = PrincipalRef::User(user);
        let first = stored_group("First", GroupPlace::TopLevel, vec![]);
        let second = stored_group("Second", GroupPlace::TopLevel, vec![]);
        let ended = stored_group("Ended", GroupPlace::TopLevel, vec![]);
        let memberships = FakeGroupMembershipStore::holding(
            *tenant,
            [
                stored_membership(principal, *second.id()),
                stored_membership(principal, *first.id()),
                stored_membership(principal, GroupId::new()),
                expired_membership(principal, *ended.id()),
            ],
        );
        let groups = FakeGroupStore::holding(*tenant, [first, second, ended]);
        let roles = FakeRoleStore::empty();
        let sources = HeldNameSources {
            roles: &roles,
            memberships: &memberships,
            groups: &groups,
        };

        let held = block_on(sources.of(&tenant, user)).unwrap();

        assert_eq!(
            held.groups.iter().map(Label::as_str).collect::<Vec<_>>(),
            ["Second", "First"]
        );
        assert_eq!(groups.id_reads().len(), 1);
    }
}
