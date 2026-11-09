//! The person behind an account, read back from the stored account.
//!
//! A record keeps who did something as an account. Rules that compare
//! people, such as "not the same person who asked", need the person behind
//! it: the account together with the address that identifies them.

use std::collections::{HashMap, HashSet};

use ianua_domain::types::{Human, HumanAccount, OrgUserId, PersonKey, PrincipalRef, UserId};

use crate::error::{AppError, OrInternal};
use crate::ports::identity::UserStore;
use crate::ports::organization::OrgUserStore;
use crate::tenancy::ScopedTenant;

/// Where people's accounts are read.
#[derive(Clone, Copy)]
pub(crate) struct PeopleSources<'a> {
    /// The tenant's users.
    pub(crate) users: &'a dyn UserStore,
    /// The organization's members.
    pub(crate) members: &'a dyn OrgUserStore,
}

/// The person acting through `principal` in `tenant`, when it is a person's
/// account that still exists. An agent or a consumer is no person.
///
/// # Errors
///
/// - `AppError::Internal` when an account cannot be read.
pub(crate) async fn person_behind(
    sources: PeopleSources<'_>,
    tenant: &ScopedTenant,
    principal: &PrincipalRef,
) -> Result<Option<Human>, AppError> {
    match principal {
        PrincipalRef::User(id) => Ok(sources
            .users
            .find_by_id(tenant, id)
            .await
            .or_internal()?
            .map(|user| Human::new(HumanAccount::User(*id), PersonKey::of(user.email())))),
        PrincipalRef::OrgUser(id) => Ok(sources
            .members
            .find_by_id(id)
            .await
            .or_internal()?
            .map(|member| Human::new(HumanAccount::OrgUser(*id), PersonKey::of(member.email())))),
        PrincipalRef::Agent(_) | PrincipalRef::Consumer(_) => Ok(None),
    }
}

/// Reads each account kind once and keeps the principals' order and repetitions.
/// Missing accounts and principals that are not people contribute no person.
///
/// # Errors
///
/// - `AppError::Internal` when either account store cannot be read.
pub(crate) async fn people_behind_all(
    sources: PeopleSources<'_>,
    tenant: &ScopedTenant,
    principals: &[PrincipalRef],
) -> Result<Vec<Human>, AppError> {
    let mut named = HashMap::new();
    let mut read = HashSet::new();
    for principal in principals {
        let people = match principal {
            PrincipalRef::User(_) if read.insert(AccountKind::User) => {
                users_behind(sources, tenant, principals).await?
            }
            PrincipalRef::OrgUser(_) if read.insert(AccountKind::Member) => {
                members_behind(sources, principals).await?
            }
            _ => continue,
        };
        named.extend(
            people
                .into_iter()
                .map(|person| (person.principal(), person)),
        );
    }
    Ok(principals
        .iter()
        .filter_map(|principal| named.get(principal).cloned())
        .collect())
}

/// Distinguishes the two stores so each is first read in principal order.
#[derive(PartialEq, Eq, Hash)]
enum AccountKind {
    User,
    Member,
}

/// Loads the distinct tenant accounts while retaining their stored person keys.
async fn users_behind(
    sources: PeopleSources<'_>,
    tenant: &ScopedTenant,
    principals: &[PrincipalRef],
) -> Result<Vec<Human>, AppError> {
    let ids = principals
        .iter()
        .filter_map(|principal| match principal {
            PrincipalRef::User(id) => Some(*id),
            _ => None,
        })
        .collect::<HashSet<UserId>>()
        .into_iter()
        .collect::<Vec<_>>();
    Ok(sources
        .users
        .find_by_ids(tenant, &ids)
        .await
        .or_internal()?
        .into_iter()
        .map(|user| Human::new(HumanAccount::User(*user.id()), PersonKey::of(user.email())))
        .collect())
}

/// Loads the distinct organization accounts using their global account ids.
async fn members_behind(
    sources: PeopleSources<'_>,
    principals: &[PrincipalRef],
) -> Result<Vec<Human>, AppError> {
    let ids = principals
        .iter()
        .filter_map(|principal| match principal {
            PrincipalRef::OrgUser(id) => Some(*id),
            _ => None,
        })
        .collect::<HashSet<OrgUserId>>()
        .into_iter()
        .collect::<Vec<_>>();
    Ok(sources
        .members
        .find_by_ids(&ids)
        .await
        .or_internal()?
        .into_iter()
        .map(|member| {
            Human::new(
                HumanAccount::OrgUser(*member.id()),
                PersonKey::of(member.email()),
            )
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use ianua_domain::types::{AgentId, OrgUserId, UserId};

    use super::*;
    use crate::test_support::identity::FakeUserStore;
    use crate::test_support::organization::FakeOrgUserStore;
    use crate::test_support::{block_on, test_ctx};

    /// Reads one principal with an empty member store for the single-account checks.
    fn read(users: &FakeUserStore, principal: PrincipalRef) -> Option<Human> {
        let members = FakeOrgUserStore::empty();
        let sources = PeopleSources {
            users,
            members: &members,
        };
        block_on(person_behind(sources, &test_ctx().tenant(), &principal)).unwrap()
    }

    /// A failed member lookup aborts the batch with its storage error,
    /// before reading the next principal's user account.
    #[test]
    fn batched_people_preserve_storage_failure_and_first_kind_order() {
        let users = FakeUserStore::empty();
        let members = FakeOrgUserStore::empty();
        members.fail_identity_reads();
        let sources = PeopleSources {
            users: &users,
            members: &members,
        };
        let principals = [
            PrincipalRef::OrgUser(OrgUserId::new()),
            PrincipalRef::User(UserId::new()),
        ];

        let result = block_on(people_behind_all(
            sources,
            &test_ctx().tenant(),
            &principals,
        ));

        assert!(matches!(result, Err(AppError::Internal(_))));
        assert_eq!(members.id_reads().len(), 1);
        assert!(users.id_reads().is_empty());
    }

    /// Nonhuman principals and an empty list need neither identity store,
    /// even when a store would fail if consulted.
    #[test]
    fn principals_without_people_do_not_read_accounts() {
        let users = FakeUserStore::empty();
        let members = FakeOrgUserStore::empty();
        members.fail_identity_reads();
        let sources = PeopleSources {
            users: &users,
            members: &members,
        };

        assert!(
            block_on(people_behind_all(sources, &test_ctx().tenant(), &[]))
                .unwrap()
                .is_empty()
        );
        assert!(
            block_on(people_behind_all(
                sources,
                &test_ctx().tenant(),
                &[PrincipalRef::Agent(AgentId::new())]
            ))
            .unwrap()
            .is_empty()
        );
        assert!(users.id_reads().is_empty());
        assert!(members.id_reads().is_empty());
    }

    /// Ann's user account is read back as Ann, with her address.
    #[test]
    fn a_users_account_is_read_back_as_its_person() {
        let ann = UserId::new();
        let users = FakeUserStore::with_user(ann, "ann@acme.test");

        let person = read(&users, PrincipalRef::User(ann)).unwrap();

        assert_eq!(person.account(), HumanAccount::User(ann));
    }

    /// An account that no longer exists names nobody.
    #[test]
    fn a_deleted_account_names_nobody() {
        let users = FakeUserStore::empty();

        assert!(read(&users, PrincipalRef::User(UserId::new())).is_none());
        assert!(read(&users, PrincipalRef::OrgUser(OrgUserId::new())).is_none());
    }

    /// Looking up an agent principal returns no person for approval checks.
    #[test]
    fn an_agent_is_no_person() {
        let users = FakeUserStore::empty();

        assert!(read(&users, PrincipalRef::Agent(AgentId::new())).is_none());
    }
}
