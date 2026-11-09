//! Reading the directory: the tenant's users and groups as LDAP shows them,
//! the same for a person bound and for a service account, and only in the
//! part of the directory the bind named.

use std::collections::HashMap;
use std::sync::Arc;

use ianua_domain::message;
use ianua_domain::types::{GroupId, UserId};

use crate::error::{AppError, OrInternal};
use crate::listing::{Limit, PageRequest, SortOrder};
use crate::ports::authorization::{GroupMembershipStore, GroupStore};
use crate::ports::identity::{UserFilter, UserOrdering, UserStore};
use crate::tenancy::ScopedTenant;
use crate::use_cases::directory::principal::DirectoryBase;
use crate::use_cases::directory::{
    DirectoryGroup, DirectoryListing, DirectoryUser, MAX_DIRECTORY_ENTRIES,
};

/// The ports the directory's entries are read through.
#[derive(ianua_macros::Fakes)]
pub struct EntryPorts {
    /// Lists the tenant's users.
    pub users: Arc<dyn UserStore>,
    /// Lists the tenant's groups.
    pub groups: Arc<dyn GroupStore>,
    /// Reads who is in each group.
    pub memberships: Arc<dyn GroupMembershipStore>,
}

/// Refuses a search aimed at `base` when the connection bound to
/// `bound_to`: a search reads only the tenant its bind named.
///
/// # Errors
///
/// Returns `AppError::Forbidden` when `base` is not `bound_to`.
pub(super) fn ensure_aimed_at_bind(
    bound_to: &DirectoryBase,
    base: &DirectoryBase,
) -> Result<(), AppError> {
    if base == bound_to {
        return Ok(());
    }
    Err(AppError::Forbidden(message!(
        "directory-a-search-reads-only-the-directory",
        "a search reads only the directory you bound to"
    )))
}

impl EntryPorts {
    /// The tenant's users and groups, each up to the cap.
    ///
    /// # Errors
    ///
    /// - `AppError::Internal` on storage failure.
    pub(super) async fn listing(
        &self,
        tenant: &ScopedTenant,
    ) -> Result<DirectoryListing, AppError> {
        Ok(DirectoryListing {
            users: self.listed_users(tenant).await?,
            groups: self.listed_groups(tenant).await?,
        })
    }

    /// The tenant's users as the directory shows them, up to the cap.
    async fn listed_users(&self, tenant: &ScopedTenant) -> Result<Vec<DirectoryUser>, AppError> {
        let page = PageRequest::first(Limit::internal(MAX_DIRECTORY_ENTRIES));
        let users = self
            .users
            .list(tenant, &UserFilter::all(), &UserOrdering::default(), &page)
            .await
            .or_internal()?;
        Ok(users
            .items
            .into_iter()
            .map(|user| DirectoryUser {
                id: *user.id(),
                email: user.email().as_str().to_owned(),
                display_name: user.display_name().as_str().to_owned(),
            })
            .collect())
    }

    /// The tenant's groups with the users directly in them, up to the cap.
    async fn listed_groups(&self, tenant: &ScopedTenant) -> Result<Vec<DirectoryGroup>, AppError> {
        let page = PageRequest::first(Limit::internal(MAX_DIRECTORY_ENTRIES));
        let groups = self
            .groups
            .list_all(tenant, &SortOrder::default(), &page)
            .await
            .or_internal()?
            .items;
        let ids: Vec<GroupId> = groups.iter().map(|group| *group.id()).collect();
        let mut members = self.user_members(tenant, &ids).await?;
        Ok(groups
            .into_iter()
            .map(|group| DirectoryGroup {
                id: *group.id(),
                name: group.name().as_str().to_owned(),
                members: members.remove(group.id()).unwrap_or_default(),
            })
            .collect())
    }

    /// The direct users of the listed groups, read together and kept in
    /// membership order. Agents and consumers have no directory entry.
    async fn user_members(
        &self,
        tenant: &ScopedTenant,
        group_ids: &[GroupId],
    ) -> Result<HashMap<GroupId, Vec<UserId>>, AppError> {
        if group_ids.is_empty() {
            return Ok(HashMap::new());
        }
        let memberships = self
            .memberships
            .find_by_groups(tenant, group_ids)
            .await
            .or_internal()?;
        let mut members: HashMap<GroupId, Vec<UserId>> = HashMap::new();
        for membership in memberships {
            let Some(user) = membership.principal().as_user() else {
                continue;
            };
            members
                .entry(*membership.group_id())
                .or_default()
                .push(user);
        }
        Ok(members)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::group::GroupPlace;
    use ianua_domain::types::{AgentId, PrincipalRef};

    use super::*;
    use crate::test_support::authorization::{
        FakeGroupMembershipStore, FakeGroupStore, stored_group, stored_membership,
    };
    use crate::test_support::{block_on, test_ctx};

    /// Checks that each listed group exposes only its own direct users.
    fn assert_group_members(groups: &[DirectoryGroup], ada: UserId, bob: UserId) {
        assert_eq!(groups.len(), 3);
        for group in groups {
            let expected = match group.name.as_str() {
                "Engineering" => vec![ada],
                "Ops" => vec![bob],
                "Empty" => vec![],
                name => panic!("unexpected group {name}"),
            };
            assert_eq!(group.members, expected);
        }
    }

    /// Several groups are returned with their own direct users, including
    /// an empty group, using one membership read for the whole page.
    #[test]
    fn a_directory_page_reads_memberships_once() {
        let tenant = test_ctx().tenant();
        let engineering = stored_group("Engineering", GroupPlace::TopLevel, vec![]);
        let ops = stored_group("Ops", GroupPlace::TopLevel, vec![]);
        let empty = stored_group("Empty", GroupPlace::TopLevel, vec![]);
        let ada = UserId::new();
        let bob = UserId::new();
        let memberships = Arc::new(FakeGroupMembershipStore::holding(
            *tenant,
            [
                stored_membership(PrincipalRef::User(ada), *engineering.id()),
                stored_membership(PrincipalRef::User(bob), *ops.id()),
                stored_membership(PrincipalRef::Agent(AgentId::new()), *ops.id()),
            ],
        ));
        let entries = EntryPorts {
            groups: Arc::new(FakeGroupStore::holding(*tenant, [engineering, ops, empty])),
            memberships: memberships.clone(),
            ..EntryPorts::fakes()
        };

        let listing = block_on(entries.listing(&tenant)).unwrap();

        assert_group_members(&listing.groups, ada, bob);
        let reads = memberships.group_reads();
        assert_eq!(reads.len(), 1);
        assert_eq!(reads[0].len(), 3);
    }

    /// An empty directory does no membership lookup at all.
    #[test]
    fn an_empty_directory_reads_no_memberships() {
        let memberships = Arc::new(FakeGroupMembershipStore::empty());
        let entries = EntryPorts {
            memberships: memberships.clone(),
            ..EntryPorts::fakes()
        };

        let listing = block_on(entries.listing(&test_ctx().tenant())).unwrap();

        assert!(listing.groups.is_empty());
        assert!(memberships.group_reads().is_empty());
    }
}
