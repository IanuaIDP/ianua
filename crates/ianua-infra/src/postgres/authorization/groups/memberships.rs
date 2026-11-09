//! Who is in which group of a tenant, and until when.
//!
//! Joining and leaving many at once is one statement each, the rows given
//! as lists side by side.

pub(crate) mod record;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::listing::{Page, PageRequest, SortOrder};
use ianua_app::ports::TenantScoped;
use ianua_app::ports::authorization::{
    GroupMemberSortField, GroupMembershipStore, HoldingBatch, MembershipPosition,
};
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::authorization::group::GroupMembership;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{GroupId, PrincipalRef};
use sqlx::PgConnection;
use time::OffsetDateTime;
use uuid::Uuid;

use self::record::{MembershipColumns, MembershipRecord, memberships_from};
use crate::postgres::authorization::principals::kind_word;
use crate::postgres::foundation::paging::{Nullable, PageQuery, SortColumns, in_page_order};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The Postgres store of group memberships.
pub struct PgGroupMembershipStore {
    databases: Arc<Databases>,
}

impl PgGroupMembershipStore {
    /// A store keeping memberships in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }

    /// The memberships of `tenant_id` the query `read` finds.
    async fn read(
        &self,
        tenant_id: &ScopedTenant,
        read: impl AsyncFnOnce(&mut PgConnection) -> Result<Vec<MembershipRecord>, sqlx::Error>,
    ) -> Result<Vec<GroupMembership<ResolvedTenant>>, DomainError> {
        let records = scoped(&self.databases, RowScope::from(tenant_id), read).await?;
        memberships_from(records)
    }
}

impl TenantScoped for PgGroupMembershipStore {}

/// Principals as the two lists a query takes them in: their kinds, and
/// their ids at the same places.
fn principal_lists(principals: &[PrincipalRef]) -> (Vec<&'static str>, Vec<Uuid>) {
    principals
        .iter()
        .map(|principal| (kind_word(principal), principal.id()))
        .unzip()
}

impl SortColumns for GroupMemberSortField {
    fn column(self) -> &'static str {
        match self {
            Self::JoinedAt => "joined_at",
        }
    }

    fn nullable(self) -> Nullable {
        Nullable::Never
    }
}

/// Reads one bounded expired-membership batch using a direct composite seek
/// after the first batch, so prepared query plans can use the complete index.
async fn lapsed_memberships(
    connection: &mut PgConnection,
    tenant: &ScopedTenant,
    batch: &HoldingBatch<MembershipPosition>,
) -> Result<Vec<MembershipRecord>, sqlx::Error> {
    let Some(last) = batch.after else {
        return sqlx::query_file_as!(
            MembershipRecord,
            "queries/group_memberships/lapsed.sql",
            tenant.as_uuid(),
            batch.now
        )
        .fetch_all(connection)
        .await;
    };
    sqlx::query_file_as!(
        MembershipRecord,
        "queries/group_memberships/lapsed_after.sql",
        tenant.as_uuid(),
        batch.now,
        last.expires_at,
        last.group_id.as_uuid(),
        kind_word(&last.principal),
        last.principal.id()
    )
    .fetch_all(connection)
    .await
}

#[async_trait]
impl GroupMembershipStore for PgGroupMembershipStore {
    async fn find_by_principal(
        &self,
        tenant_id: &ScopedTenant,
        principal: &PrincipalRef,
    ) -> Result<Vec<GroupMembership<ResolvedTenant>>, DomainError> {
        self.read(tenant_id, async |connection| {
            sqlx::query_file_as!(
                MembershipRecord,
                "queries/group_memberships/of_principal.sql",
                tenant_id.as_uuid(),
                kind_word(principal),
                principal.id()
            )
            .fetch_all(connection)
            .await
        })
        .await
    }

    async fn find_by_group(
        &self,
        tenant_id: &ScopedTenant,
        group_id: &GroupId,
    ) -> Result<Vec<GroupMembership<ResolvedTenant>>, DomainError> {
        self.find_by_groups(tenant_id, std::slice::from_ref(group_id))
            .await
    }

    async fn find_by_groups(
        &self,
        tenant_id: &ScopedTenant,
        group_ids: &[GroupId],
    ) -> Result<Vec<GroupMembership<ResolvedTenant>>, DomainError> {
        let ids: Vec<Uuid> = group_ids.iter().map(|id| *id.as_uuid()).collect();
        self.read(tenant_id, async |connection| {
            sqlx::query_file_as!(
                MembershipRecord,
                "queries/group_memberships/of_groups.sql",
                tenant_id.as_uuid(),
                &ids
            )
            .fetch_all(connection)
            .await
        })
        .await
    }

    async fn list_by_group(
        &self,
        tenant_id: &ScopedTenant,
        group_id: &GroupId,
        page: &PageRequest,
    ) -> Result<Page<GroupMembership<ResolvedTenant>>, DomainError> {
        let order = SortOrder::<GroupMemberSortField>::default();
        let keyset = page.keyset(&order)?;
        let listed = PageQuery::ids("principal_id", "group_memberships")
            .filter("tenant_id = ?", *tenant_id.as_uuid())
            .filter("group_id = ?", *group_id.as_uuid());
        let members = self
            .read(tenant_id, async |connection| {
                let ids = listed.fetch(&keyset, &mut *connection).await?;
                let records = sqlx::query_file_as!(
                    MembershipRecord,
                    "queries/group_memberships/of_group_by_ids.sql",
                    tenant_id.as_uuid(),
                    group_id.as_uuid(),
                    &ids
                )
                .fetch_all(connection)
                .await?;
                Ok(in_page_order(&ids, records, |record| record.principal_id))
            })
            .await?;
        Ok(keyset.seal(members))
    }

    async fn exists(
        &self,
        tenant_id: &ScopedTenant,
        principal: &PrincipalRef,
        group_id: &GroupId,
    ) -> Result<bool, DomainError> {
        let now = clock::now();
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_scalar!(
                    "queries/group_memberships/held.sql",
                    tenant_id.as_uuid(),
                    group_id.as_uuid(),
                    kind_word(principal),
                    principal.id(),
                    now
                )
                .fetch_one(connection)
                .await
            },
        )
        .await
    }

    async fn remove_lapsed(
        &self,
        tenant_id: &ScopedTenant,
        membership: &GroupMembership<ResolvedTenant>,
        now: OffsetDateTime,
    ) -> Result<bool, DomainError> {
        let principal = membership.principal();
        let removed = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/group_memberships/delete_lapsed.sql",
                    tenant_id.as_uuid(),
                    membership.group_id().as_uuid(),
                    kind_word(principal),
                    principal.id(),
                    now
                )
                .execute(connection)
                .await
            },
        )
        .await?;
        Ok(removed.rows_affected() > 0)
    }

    async fn find_lapsed(
        &self,
        tenant_id: &ScopedTenant,
        batch: &HoldingBatch<MembershipPosition>,
    ) -> Result<Vec<GroupMembership<ResolvedTenant>>, DomainError> {
        self.read(tenant_id, async |connection| {
            lapsed_memberships(connection, tenant_id, batch).await
        })
        .await
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        membership: &GroupMembership<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        self.save_all(tenant_id, std::slice::from_ref(membership))
            .await
    }

    async fn save_all(
        &self,
        tenant_id: &ScopedTenant,
        memberships: &[GroupMembership<ResolvedTenant>],
    ) -> Result<(), DomainError> {
        let columns = MembershipColumns::of(memberships);
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/group_memberships/save.sql",
                    tenant_id.as_uuid(),
                    &columns.group_ids,
                    &columns.principal_kinds as &[&str],
                    &columns.principal_ids,
                    &columns.joined_at,
                    &columns.expires_at as &[Option<OffsetDateTime>],
                )
                .execute(connection)
                .await?;
                Ok(())
            },
        )
        .await
    }

    async fn delete(
        &self,
        tenant_id: &ScopedTenant,
        principal: &PrincipalRef,
        group_id: &GroupId,
    ) -> Result<(), DomainError> {
        self.delete_all(tenant_id, group_id, std::slice::from_ref(principal))
            .await
    }

    async fn delete_all(
        &self,
        tenant_id: &ScopedTenant,
        group_id: &GroupId,
        principals: &[PrincipalRef],
    ) -> Result<(), DomainError> {
        let (kinds, ids) = principal_lists(principals);
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/group_memberships/delete.sql",
                    tenant_id.as_uuid(),
                    group_id.as_uuid(),
                    &kinds as &[&str],
                    &ids
                )
                .execute(connection)
                .await?;
                Ok(())
            },
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::listing::Limit;
    use ianua_app::ports::authorization::GroupStore;
    use ianua_domain::domains::authorization::group::Group;
    use ianua_domain::types::{AgentId, Expiry, UserId};

    use super::*;
    use crate::postgres::authorization::PgGroupStore;
    use crate::test_support::TestDb;
    use crate::test_support::rows::at;
    use crate::test_support::rows::authorization::{
        ended_membership, group, joined_at, membership, membership_until, tenant,
    };

    struct Fixture {
        db: TestDb,
        store: PgGroupMembershipStore,
        acme: ScopedTenant,
    }

    /// A fresh database, the store on it, and a tenant to keep groups in.
    async fn fixture() -> Fixture {
        let db = TestDb::fresh().await;
        let store = PgGroupMembershipStore::new(Arc::clone(&db.databases));
        Fixture {
            db,
            store,
            acme: tenant(),
        }
    }

    /// Saves a group called `name` in `tenant_id` through the group store.
    async fn hold_group(
        db: &TestDb,
        tenant_id: &ScopedTenant,
        name: &str,
    ) -> Group<ResolvedTenant> {
        let held = group(name, Vec::new());
        PgGroupStore::new(Arc::clone(&db.databases))
            .save(tenant_id, &held)
            .await
            .unwrap();
        held
    }

    fn person() -> PrincipalRef {
        PrincipalRef::User(UserId::new())
    }

    /// Saves two principal kinds sharing a UUID and expiry in each of two groups.
    async fn tied_memberships(f: &Fixture) -> [PrincipalRef; 2] {
        let first = hold_group(&f.db, &f.acme, "first").await;
        let second = hold_group(&f.db, &f.acme, "second").await;
        let id = *UserId::new().as_uuid();
        let people = [
            PrincipalRef::Agent(AgentId::from_uuid(id)),
            PrincipalRef::User(UserId::from_uuid(id)),
        ];
        let rows: Vec<_> = [&first, &second]
            .into_iter()
            .flat_map(|group| {
                people.into_iter().map(move |principal| {
                    membership_until(principal, *group.id(), Expiry::At(at(10)))
                })
            })
            .collect();
        f.store.save_all(&f.acme, &rows).await.unwrap();
        people
    }

    /// Reads complete expiry cursors from the returned membership order.
    fn positions(rows: &[GroupMembership<ResolvedTenant>]) -> Vec<MembershipPosition> {
        rows.iter()
            .map(|held| MembershipPosition::of(held).unwrap())
            .collect()
    }

    /// Ann's expired Engineering membership does not count as held. A
    /// fresh membership replaces it and restores her place without expiry.
    #[tokio::test]
    async fn a_place_that_ran_out_is_not_held_and_a_fresh_one_replaces_it() {
        let f = fixture().await;
        let engineering = hold_group(&f.db, &f.acme, "Engineering").await;
        let ann = person();
        f.store
            .save(&f.acme, &ended_membership(ann, *engineering.id()))
            .await
            .unwrap();
        let held_when_ended = f
            .store
            .exists(&f.acme, &ann, engineering.id())
            .await
            .unwrap();

        f.store
            .save_all(&f.acme, &[joined_at(ann, *engineering.id(), clock::now())])
            .await
            .unwrap();

        let hers = f.store.find_by_principal(&f.acme, &ann).await.unwrap();
        assert!(!held_when_ended);
        assert_eq!(hers.len(), 1);
        assert_eq!(hers[0].expires(), Expiry::Never);
        assert!(
            f.store
                .exists(&f.acme, &ann, engineering.id())
                .await
                .unwrap()
        );
    }

    /// After Ann rejoins Engineering, a sweep using her expired membership
    /// reports no removal and leaves the renewed membership held.
    #[tokio::test]
    async fn the_sweep_leaves_a_place_given_again_since_it_read_it() {
        let f = fixture().await;
        let engineering = hold_group(&f.db, &f.acme, "Engineering").await;
        let ann = person();
        let ended = ended_membership(ann, *engineering.id());
        f.store.save(&f.acme, &ended).await.unwrap();
        f.store
            .save(&f.acme, &joined_at(ann, *engineering.id(), clock::now()))
            .await
            .unwrap();

        let removed = f
            .store
            .remove_lapsed(&f.acme, &ended, clock::now())
            .await
            .unwrap();

        assert!(!removed);
        assert!(
            f.store
                .exists(&f.acme, &ann, engineering.id())
                .await
                .unwrap()
        );
    }

    /// The sweep clears a place whose end has still come, and hears that
    /// it did.
    #[tokio::test]
    async fn the_sweep_clears_a_place_that_ran_out() {
        let f = fixture().await;
        let engineering = hold_group(&f.db, &f.acme, "Engineering").await;
        let ann = person();
        let ended = ended_membership(ann, *engineering.id());
        f.store.save(&f.acme, &ended).await.unwrap();

        let removed = f
            .store
            .remove_lapsed(&f.acme, &ended, clock::now())
            .await
            .unwrap();

        assert!(removed);
        assert!(
            f.store
                .find_by_principal(&f.acme, &ann)
                .await
                .unwrap()
                .is_empty()
        );
    }

    /// Ann joins Engineering: she is found among its members and it among
    /// her groups, and joining again changes nothing.
    #[tokio::test]
    async fn a_member_is_found_by_group_and_by_principal() {
        let f = fixture().await;
        let engineering = hold_group(&f.db, &f.acme, "Engineering").await;
        let ann = person();
        let joined = membership_until(ann, *engineering.id(), Expiry::At(at(100)));

        f.store.save(&f.acme, &joined).await.unwrap();
        f.store
            .save(&f.acme, &membership(ann, *engineering.id()))
            .await
            .unwrap();

        let hers = f.store.find_by_principal(&f.acme, &ann).await.unwrap();
        let members = f
            .store
            .find_by_group(&f.acme, engineering.id())
            .await
            .unwrap();
        assert_eq!(hers.len(), 1);
        assert_eq!(hers[0].expires(), Expiry::At(at(100)));
        assert_eq!(members.len(), 1);
        assert!(
            f.store
                .exists(&f.acme, &ann, engineering.id())
                .await
                .unwrap()
        );
        assert!(
            !f.store
                .exists(&f.acme, &person(), engineering.id())
                .await
                .unwrap()
        );
    }

    /// Members of several groups are read together, and of no others.
    #[tokio::test]
    async fn the_members_of_several_groups_are_read_together() {
        let f = fixture().await;
        let a = hold_group(&f.db, &f.acme, "A").await;
        let b = hold_group(&f.db, &f.acme, "B").await;
        let c = hold_group(&f.db, &f.acme, "C").await;
        let joined: Vec<_> = [&a, &b, &c]
            .into_iter()
            .map(|held| membership(person(), *held.id()))
            .collect();
        f.store.save_all(&f.acme, &joined).await.unwrap();

        let found = f
            .store
            .find_by_groups(&f.acme, &[*a.id(), *b.id()])
            .await
            .unwrap();

        assert_eq!(found.len(), 2);
        assert!(found.iter().all(|held| held.group_id() != c.id()));
    }

    /// A group's members are paged oldest first, each page after the last.
    #[tokio::test]
    async fn a_groups_members_are_paged_oldest_first() {
        let f = fixture().await;
        let engineering = hold_group(&f.db, &f.acme, "Engineering").await;
        let (first, second, third) = (person(), person(), person());
        let joined = [
            joined_at(third, *engineering.id(), at(3)),
            joined_at(first, *engineering.id(), at(1)),
            joined_at(second, *engineering.id(), at(2)),
        ];
        f.store.save_all(&f.acme, &joined).await.unwrap();

        let page_one = f
            .store
            .list_by_group(
                &f.acme,
                engineering.id(),
                &PageRequest::first(Limit::new(2).unwrap()),
            )
            .await
            .unwrap();
        let after = PageRequest::new(page_one.next.clone(), Limit::new(2).unwrap());
        let page_two = f
            .store
            .list_by_group(&f.acme, engineering.id(), &after)
            .await
            .unwrap();

        let members = |page: &Page<GroupMembership<ResolvedTenant>>| -> Vec<PrincipalRef> {
            page.items.iter().map(|held| *held.principal()).collect()
        };
        assert_eq!(members(&page_one), [first, second]);
        assert_eq!(members(&page_two), [third]);
        assert!(!page_two.has_next());
    }

    /// The sweep finds the memberships whose end has come, and no others.
    #[tokio::test]
    async fn the_memberships_that_ran_out_are_found() {
        let f = fixture().await;
        let engineering = hold_group(&f.db, &f.acme, "Engineering").await;
        let ended = person();
        let joined = [
            membership_until(ended, *engineering.id(), Expiry::At(at(10))),
            membership_until(person(), *engineering.id(), Expiry::At(at(1000))),
            membership(person(), *engineering.id()),
        ];
        f.store.save_all(&f.acme, &joined).await.unwrap();

        let lapsed = f
            .store
            .find_lapsed(
                &f.acme,
                &HoldingBatch {
                    now: at(500),
                    after: None,
                },
            )
            .await
            .unwrap();

        assert_eq!(lapsed.len(), 1);
        assert_eq!(*lapsed[0].principal(), ended);
    }

    /// An agent and a user share a UUID and expiry in two groups. The complete
    /// cursor keeps both memberships and both kinds, remains usable after a
    /// removal, and cannot read memberships from another tenant.
    #[tokio::test]
    async fn membership_sweep_cursor_keeps_every_composite_key_component() {
        let f = fixture().await;
        let people = tied_memberships(&f).await;
        let batch = HoldingBatch {
            now: at(10),
            after: None,
        };
        let all = f.store.find_lapsed(&f.acme, &batch).await.unwrap();
        assert_eq!(all.len(), 4);
        let cursors = positions(&all);
        assert_eq!(cursors[0].principal, people[0]);
        assert_eq!(cursors[1].principal, people[1]);
        assert_eq!(cursors[2].principal, people[0]);
        assert_eq!(cursors[3].principal, people[1]);
        assert!(cursors[0].group_id.as_uuid() < cursors[2].group_id.as_uuid());
        assert!(
            f.store
                .remove_lapsed(&f.acme, &all[0], at(10))
                .await
                .unwrap()
        );
        let after = HoldingBatch {
            after: Some(cursors[0]),
            ..batch
        };

        let remaining = f.store.find_lapsed(&f.acme, &after).await.unwrap();
        let elsewhere = f.store.find_lapsed(&tenant(), &after).await.unwrap();

        assert_eq!(positions(&remaining), cursors[1..]);
        assert!(elsewhere.is_empty());
    }

    /// Leaving takes exactly the named members out, of every kind, and
    /// passes over someone not in the group.
    #[tokio::test]
    async fn members_leave_one_or_many_at_once() {
        let f = fixture().await;
        let engineering = hold_group(&f.db, &f.acme, "Engineering").await;
        let (ann, bot, bob) = (person(), PrincipalRef::Agent(AgentId::new()), person());
        let joined: Vec<_> = [ann, bot, bob]
            .into_iter()
            .map(|member| membership(member, *engineering.id()))
            .collect();
        f.store.save_all(&f.acme, &joined).await.unwrap();

        f.store
            .delete(&f.acme, &ann, engineering.id())
            .await
            .unwrap();
        f.store
            .delete_all(&f.acme, engineering.id(), &[bot, person()])
            .await
            .unwrap();

        let left = f
            .store
            .find_by_group(&f.acme, engineering.id())
            .await
            .unwrap();
        assert_eq!(left.len(), 1);
        assert_eq!(*left[0].principal(), bob);
    }

    /// Globex cannot read Ann's Acme membership or add a member to Acme's group.
    #[tokio::test]
    async fn another_tenants_memberships_are_out_of_reach() {
        let f = fixture().await;
        let engineering = hold_group(&f.db, &f.acme, "Engineering").await;
        let ann = person();
        f.store
            .save(&f.acme, &membership(ann, *engineering.id()))
            .await
            .unwrap();
        let globex = tenant();

        let theirs = f.store.find_by_principal(&globex, &ann).await.unwrap();
        let joined = f
            .store
            .save(&globex, &membership(person(), *engineering.id()))
            .await;

        assert!(theirs.is_empty());
        assert!(matches!(joined, Err(DomainError::Infrastructure(_))));
    }

    /// An unknown principal kind written directly into a membership makes
    /// the group's membership read fail as corrupt storage.
    #[tokio::test]
    async fn a_row_with_an_unknown_kind_of_member_is_refused() {
        let f = fixture().await;
        let engineering = hold_group(&f.db, &f.acme, "Engineering").await;
        let ann = person();
        f.store
            .save(&f.acme, &membership(ann, *engineering.id()))
            .await
            .unwrap();
        f.db.tamper(
            "ALTER TABLE group_memberships DROP CONSTRAINT group_memberships_principal_kind_known; \
             UPDATE group_memberships SET principal_kind = 'robot'",
        )
        .await;

        let read = f.store.find_by_group(&f.acme, engineering.id()).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
