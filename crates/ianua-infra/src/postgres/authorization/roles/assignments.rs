//! The roles given straight to principals, and deleting a role with its
//! holders moved onto another, in one transaction.

mod expiry;
pub(crate) mod record;

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::listing::{Page, PageRequest, SortOrder};
use ianua_app::ports::TenantScoped;
use ianua_app::ports::authorization::{
    AssignmentPosition, HoldingBatch, RoleAssignmentStore, RoleDeletionUnitOfWork, RoleHolder,
    RoleHolderQueries, RoleHolderSortField,
};
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::authorization::role_assignment::RoleAssignment;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{ActorRef, PrincipalRef, RoleId};
use sqlx::PgConnection;
use time::OffsetDateTime;
use uuid::Uuid;

use self::record::{
    AssignmentColumns, AssignmentRecord, HolderRecord, Holders, actor_sealed, assignments_from,
};
use crate::postgres::authorization::principals::kind_word;
use crate::postgres::authorization::roles::assignments::expiry::lapsed_assignments;
use crate::postgres::foundation::paging::{Nullable, PageQuery, SortColumns, in_page_order};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The Postgres store of the roles given straight to principals.
pub struct PgRoleAssignmentStore {
    databases: Arc<Databases>,
}

impl PgRoleAssignmentStore {
    /// A store keeping assignments in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

impl TenantScoped for PgRoleAssignmentStore {}

/// A count as the port answers it.
fn counted(count: i64) -> Result<u64, DomainError> {
    u64::try_from(count).map_err(DomainError::infra)
}

#[async_trait]
impl RoleAssignmentStore for PgRoleAssignmentStore {
    async fn find_by_principal(
        &self,
        tenant_id: &ScopedTenant,
        principal: &PrincipalRef,
    ) -> Result<Vec<RoleAssignment<ResolvedTenant>>, DomainError> {
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    AssignmentRecord,
                    "queries/role_assignments/of_principal.sql",
                    tenant_id.as_uuid(),
                    kind_word(principal),
                    principal.id()
                )
                .fetch_all(connection)
                .await
            },
        )
        .await?;
        assignments_from(records)
    }

    async fn exists(
        &self,
        tenant_id: &ScopedTenant,
        principal: &PrincipalRef,
        role_id: &RoleId,
    ) -> Result<bool, DomainError> {
        let now = clock::now();
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_scalar!(
                    "queries/role_assignments/held.sql",
                    tenant_id.as_uuid(),
                    role_id.as_uuid(),
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

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        assignment: &RoleAssignment<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let columns = AssignmentColumns::of(assignment)?;
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/role_assignments/save.sql",
                    tenant_id.as_uuid(),
                    columns.role_id,
                    columns.principal_kind,
                    columns.principal_id,
                    columns.assigned_by,
                    columns.assigned_at,
                    columns.expires_at,
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
        role_id: &RoleId,
    ) -> Result<(), DomainError> {
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/role_assignments/delete.sql",
                    tenant_id.as_uuid(),
                    role_id.as_uuid(),
                    kind_word(principal),
                    principal.id()
                )
                .execute(connection)
                .await?;
                Ok(())
            },
        )
        .await
    }

    /// Deletes one role for the selected principals with tenant isolation.
    async fn delete_for_principals(
        &self,
        tenant_id: &ScopedTenant,
        role_id: &RoleId,
        principals: &[PrincipalRef],
    ) -> Result<(), DomainError> {
        let kinds: Vec<&str> = principals.iter().map(kind_word).collect();
        let ids: Vec<Uuid> = principals.iter().map(PrincipalRef::id).collect();
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/role_assignments/delete_for_principals.sql",
                    tenant_id.as_uuid(),
                    role_id.as_uuid(),
                    &kinds as &[&str],
                    &ids
                )
                .execute(connection)
                .await
                .map(|_| ())
            },
        )
        .await
    }

    async fn remove_lapsed(
        &self,
        tenant_id: &ScopedTenant,
        assignment: &RoleAssignment<ResolvedTenant>,
        now: OffsetDateTime,
    ) -> Result<bool, DomainError> {
        let principal = assignment.principal();
        let removed = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/role_assignments/delete_lapsed.sql",
                    tenant_id.as_uuid(),
                    assignment.role_id().as_uuid(),
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
        batch: &HoldingBatch<AssignmentPosition>,
    ) -> Result<Vec<RoleAssignment<ResolvedTenant>>, DomainError> {
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| lapsed_assignments(connection, tenant_id, batch).await,
        )
        .await?;
        assignments_from(records)
    }

    async fn count_by_role(
        &self,
        tenant_id: &ScopedTenant,
        role_id: &RoleId,
    ) -> Result<u64, DomainError> {
        let count = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_scalar!(
                    "queries/role_assignments/count_holders.sql",
                    tenant_id.as_uuid(),
                    role_id.as_uuid()
                )
                .fetch_one(connection)
                .await
            },
        )
        .await?;
        counted(count)
    }

    async fn count_by_roles(
        &self,
        tenant_id: &ScopedTenant,
        role_ids: &[RoleId],
    ) -> Result<HashMap<RoleId, u64>, DomainError> {
        let ids: Vec<Uuid> = role_ids.iter().map(|id| *id.as_uuid()).collect();
        let rows = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/role_assignments/count_holders_of_each.sql",
                    tenant_id.as_uuid(),
                    &ids
                )
                .fetch_all(connection)
                .await
            },
        )
        .await?;
        rows.into_iter()
            .map(|row| Ok((RoleId::from_uuid(row.role_id), counted(row.count)?)))
            .collect()
    }
}

/// The Postgres unit of work that deletes a role once its holders are
/// moved onto another.
pub struct PgRoleDeletionUnitOfWork {
    databases: Arc<Databases>,
}

impl PgRoleDeletionUnitOfWork {
    /// A unit of work over the roles and assignments in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

impl TenantScoped for PgRoleDeletionUnitOfWork {}

/// Withdraws the old assignments and role after its active holders have been copied.
async fn withdraw_role(
    connection: &mut PgConnection,
    tenant: &Uuid,
    target: &Uuid,
) -> Result<u64, sqlx::Error> {
    let withdrawn = sqlx::query_file!("queries/role_assignments/withdraw_role.sql", tenant, target)
        .execute(&mut *connection)
        .await?;
    sqlx::query_file!("queries/roles/delete.sql", tenant, target)
        .execute(connection)
        .await?;
    Ok(withdrawn.rows_affected())
}

#[async_trait]
impl RoleDeletionUnitOfWork for PgRoleDeletionUnitOfWork {
    async fn reassign_and_delete(
        &self,
        tenant_id: &ScopedTenant,
        target: &RoleId,
        replacement: &RoleId,
        reassigned_by: ActorRef,
    ) -> Result<u64, DomainError> {
        let by = actor_sealed(&reassigned_by)?;
        let now = clock::now();
        let removed = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/role_assignments/move_holders.sql",
                    tenant_id.as_uuid(),
                    target.as_uuid(),
                    replacement.as_uuid(),
                    by,
                    now
                )
                .execute(&mut *connection)
                .await?;
                withdraw_role(connection, tenant_id.as_uuid(), target.as_uuid()).await
            },
        )
        .await?;
        Ok(removed)
    }
}

/// The Postgres reader of who holds a role, a page at a time.
pub struct PgRoleHolderQueries {
    databases: Arc<Databases>,
}

impl PgRoleHolderQueries {
    /// A reader of the roles, assignments and groups in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

impl TenantScoped for PgRoleHolderQueries {}

impl SortColumns for RoleHolderSortField {
    fn column(self) -> &'static str {
        match self {
            Self::Kind => "kind",
        }
    }

    fn nullable(self) -> Nullable {
        Nullable::Never
    }
}

/// The ids of the holders of `role_id` in `tenant_id` at `now`: those
/// given it straight by an assignment still in force, and the groups
/// carrying it.
fn holders_listed(
    tenant_id: &ScopedTenant,
    role_id: &RoleId,
    now: OffsetDateTime,
) -> PageQuery<'static> {
    PageQuery::ids("holder_id", "role_holders")
        .filter("tenant_id = ?", *tenant_id.as_uuid())
        .filter("role_id = ?", *role_id.as_uuid())
        .filter("(expires_at IS NULL OR expires_at > ?)", now)
}

/// Hydrates selected holder rows and their direct assignments in page order.
async fn read_holders(
    connection: &mut PgConnection,
    tenant: &Uuid,
    role: &Uuid,
    ids: &[Uuid],
) -> Result<Holders, sqlx::Error> {
    let records = sqlx::query_file_as!(
        HolderRecord,
        "queries/role_assignments/holders.sql",
        tenant,
        role,
        ids
    )
    .fetch_all(&mut *connection)
    .await?;
    let assignments = sqlx::query_file_as!(
        AssignmentRecord,
        "queries/role_assignments/of_role_held_by.sql",
        tenant,
        role,
        ids
    )
    .fetch_all(connection)
    .await?;
    Ok(Holders {
        records: in_page_order(ids, records, |record| record.holder_id),
        assignments,
    })
}

#[async_trait]
impl RoleHolderQueries for PgRoleHolderQueries {
    async fn holders_of(
        &self,
        tenant_id: &ScopedTenant,
        role_id: &RoleId,
        now: OffsetDateTime,
        page: &PageRequest,
    ) -> Result<Page<RoleHolder>, DomainError> {
        let order = SortOrder::<RoleHolderSortField>::default();
        let keyset = page.keyset(&order)?;
        let listed = holders_listed(tenant_id, role_id, now);
        let holders = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                let ids = listed.fetch(&keyset, &mut *connection).await?;
                read_holders(connection, tenant_id.as_uuid(), role_id.as_uuid(), &ids).await
            },
        )
        .await?;
        Ok(keyset.seal(holders.into_holders()?))
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::listing::Limit;
    use ianua_app::ports::authorization::{GroupStore, RoleStore};
    use ianua_domain::domains::authorization::role::Role;
    use ianua_domain::domains::authorization::role_assignment::RoleAssignmentRow;
    use ianua_domain::types::{AgentId, Expiry, GroupId, UserId};
    use time::Duration;

    use super::*;
    use crate::postgres::authorization::{PgGroupStore, PgRoleStore};
    use crate::test_support::TestDb;
    use crate::test_support::rows::at;
    use crate::test_support::rows::authorization::{
        assignment, assignment_until, ended_assignment, group, role, tenant,
    };

    struct Fixture {
        db: TestDb,
        store: PgRoleAssignmentStore,
        acme: ScopedTenant,
    }

    /// A fresh database, the store on it, and a tenant to keep roles in.
    async fn fixture() -> Fixture {
        let db = TestDb::fresh().await;
        let store = PgRoleAssignmentStore::new(Arc::clone(&db.databases));
        Fixture {
            db,
            store,
            acme: tenant(),
        }
    }

    /// Saves a role called `name` in `tenant_id` through the role store.
    async fn hold_role(db: &TestDb, tenant_id: &ScopedTenant, name: &str) -> Role<ResolvedTenant> {
        let held = role(name);
        PgRoleStore::new(Arc::clone(&db.databases))
            .save(tenant_id, &held)
            .await
            .unwrap();
        held
    }

    fn ann() -> PrincipalRef {
        PrincipalRef::User(UserId::new())
    }

    impl Fixture {
        /// Gives one principal a direct role assignment with an explicit end.
        async fn give_until(&self, principal: PrincipalRef, role: &RoleId, expiry: Expiry) {
            self.store
                .save(&self.acme, &assignment_until(principal, *role, expiry))
                .await
                .unwrap();
        }

        /// Removes only the supplied principal pairs from one role in the fixture tenant.
        async fn remove_principals(&self, role: &RoleId, principals: &[PrincipalRef]) {
            self.store
                .delete_for_principals(&self.acme, role, principals)
                .await
                .unwrap();
        }

        /// Persists a group carrying one role for the holder-listing controls.
        async fn group_carrying(&self, name: &str, role: &RoleId) -> GroupId {
            let held = group(name, vec![*role]);
            PgGroupStore::new(Arc::clone(&self.db.databases))
                .save(&self.acme, &held)
                .await
                .unwrap();
            *held.id()
        }
    }

    /// Saves two principal kinds sharing one identifier and expiry in each of two roles.
    async fn tied_assignments(f: &Fixture) -> [PrincipalRef; 2] {
        let first = hold_role(&f.db, &f.acme, "first").await;
        let second = hold_role(&f.db, &f.acme, "second").await;
        let id = *UserId::new().as_uuid();
        let people = [
            PrincipalRef::Agent(AgentId::from_uuid(id)),
            PrincipalRef::User(UserId::from_uuid(id)),
        ];
        for role in [&first, &second] {
            for principal in people {
                f.give_until(principal, role.id(), Expiry::At(at(10))).await;
            }
        }
        people
    }

    /// Extracts complete expiry cursors without changing returned assignment order.
    fn positions(rows: &[RoleAssignment<ResolvedTenant>]) -> Vec<AssignmentPosition> {
        rows.iter()
            .map(|held| AssignmentPosition::of(held).unwrap())
            .collect()
    }

    /// Crossed user and agent identifiers whose kinds must remain paired during removal.
    struct PrincipalPairs {
        removed: [PrincipalRef; 2],
        retained: [PrincipalRef; 2],
    }

    /// Builds controls where retaining only identifiers would remove the wrong principals.
    fn principal_pairs() -> PrincipalPairs {
        let first = *UserId::new().as_uuid();
        let second = *UserId::new().as_uuid();
        PrincipalPairs {
            removed: [
                PrincipalRef::User(UserId::from_uuid(first)),
                PrincipalRef::Agent(AgentId::from_uuid(second)),
            ],
            retained: [
                PrincipalRef::Agent(AgentId::from_uuid(first)),
                PrincipalRef::User(UserId::from_uuid(second)),
            ],
        }
    }

    /// A role given to Ann is found among hers, with who gave it and when
    /// it ends; giving it again changes nothing.
    #[tokio::test]
    async fn a_given_role_is_found_and_giving_it_again_changes_nothing() {
        let f = fixture().await;
        let admin = hold_role(&f.db, &f.acme, "admin").await;
        let ann = ann();
        let given = assignment_until(ann, *admin.id(), Expiry::At(at(100)));

        f.store.save(&f.acme, &given).await.unwrap();
        f.store
            .save(&f.acme, &assignment(ann, *admin.id()))
            .await
            .unwrap();

        let held = f.store.find_by_principal(&f.acme, &ann).await.unwrap();
        assert_eq!(held.len(), 1);
        assert_eq!(held[0].role_id(), admin.id());
        assert_eq!(held[0].expires(), Expiry::At(at(100)));
        assert_eq!(held[0].assigned_at(), given.assigned_at());
        assert!(f.store.exists(&f.acme, &ann, admin.id()).await.unwrap());
    }

    /// A role taken away is no longer held, and someone never given it
    /// does not hold it.
    #[tokio::test]
    async fn a_role_taken_away_is_no_longer_held() {
        let f = fixture().await;
        let admin = hold_role(&f.db, &f.acme, "admin").await;
        let ann = ann();
        f.store
            .save(&f.acme, &assignment(ann, *admin.id()))
            .await
            .unwrap();

        f.store.delete(&f.acme, &ann, admin.id()).await.unwrap();

        assert!(!f.store.exists(&f.acme, &ann, admin.id()).await.unwrap());
        assert!(
            !f.store
                .exists(&f.acme, &self::ann(), admin.id())
                .await
                .unwrap()
        );
    }

    /// Another tenant sees no assignments for the principal, reports that the
    /// assignment does not exist, and counts no holders of the role.
    #[tokio::test]
    async fn another_tenants_assignments_are_invisible() {
        let f = fixture().await;
        let admin = hold_role(&f.db, &f.acme, "admin").await;
        let ann = ann();
        f.store
            .save(&f.acme, &assignment(ann, *admin.id()))
            .await
            .unwrap();
        let globex = tenant();

        let held = f.store.find_by_principal(&globex, &ann).await.unwrap();
        let exists = f.store.exists(&globex, &ann, admin.id()).await.unwrap();
        let count = f.store.count_by_role(&globex, admin.id()).await.unwrap();

        assert!(held.is_empty());
        assert!(!exists);
        assert_eq!(count, 0);
    }

    /// Saving an assignment to another tenant's role fails with an
    /// infrastructure error from the foreign key constraint.
    #[tokio::test]
    async fn a_role_of_another_tenant_cannot_be_given() {
        let f = fixture().await;
        let theirs = hold_role(&f.db, &tenant(), "admin").await;

        let given = f
            .store
            .save(&f.acme, &assignment(ann(), *theirs.id()))
            .await;

        assert!(matches!(given, Err(DomainError::Infrastructure(_))));
    }

    /// The sweep finds the assignments whose end has come, and leaves the
    /// running and the endless ones.
    #[tokio::test]
    async fn the_assignments_that_ran_out_are_found() {
        let f = fixture().await;
        let admin = hold_role(&f.db, &f.acme, "admin").await;
        let (ended, running, endless) = (ann(), ann(), ann());
        for (holder, expires) in [
            (ended, Expiry::At(at(10))),
            (running, Expiry::At(at(1000))),
            (endless, Expiry::Never),
        ] {
            f.store
                .save(&f.acme, &assignment_until(holder, *admin.id(), expires))
                .await
                .unwrap();
        }

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

    /// An agent and a user share a UUID and expiry while holding two roles.
    /// The complete cursor keeps every role and principal kind distinct, remains
    /// usable after a row is removed, and never crosses tenant scope.
    #[tokio::test]
    async fn assignment_sweep_cursor_keeps_every_composite_key_component() {
        let f = fixture().await;
        let people = tied_assignments(&f).await;
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
        assert!(cursors[0].role_id.as_uuid() < cursors[2].role_id.as_uuid());
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

    /// `role_id` given to `principal` by the platform just now, with no end.
    fn given_now(principal: PrincipalRef, role_id: RoleId) -> RoleAssignment<ResolvedTenant> {
        RoleAssignment::reconstitute(RoleAssignmentRow {
            principal,
            role_id,
            assigned_by: ActorRef::System,
            assigned_at: clock::now(),
            expires: Expiry::Never,
        })
        .unwrap()
    }

    /// Ann's expired assignment no longer counts as held. Granting the role
    /// again replaces that assignment with a single grant that has no end.
    #[tokio::test]
    async fn a_role_that_ran_out_is_not_held_and_a_fresh_grant_replaces_it() {
        let f = fixture().await;
        let admin = hold_role(&f.db, &f.acme, "admin").await;
        let ann = ann();
        f.store
            .save(&f.acme, &ended_assignment(ann, *admin.id()))
            .await
            .unwrap();
        let held_when_ended = f.store.exists(&f.acme, &ann, admin.id()).await.unwrap();

        f.store
            .save(&f.acme, &given_now(ann, *admin.id()))
            .await
            .unwrap();

        let held = f.store.find_by_principal(&f.acme, &ann).await.unwrap();
        assert!(!held_when_ended);
        assert_eq!(held.len(), 1);
        assert_eq!(held[0].expires(), Expiry::Never);
        assert!(f.store.exists(&f.acme, &ann, admin.id()).await.unwrap());
    }

    /// When Ann receives a fresh grant after the sweep reads her expired one,
    /// removing the expired grant returns false and leaves her role held.
    #[tokio::test]
    async fn the_sweep_leaves_a_role_given_again_since_it_read_it() {
        let f = fixture().await;
        let admin = hold_role(&f.db, &f.acme, "admin").await;
        let ann = ann();
        let ended = ended_assignment(ann, *admin.id());
        f.store.save(&f.acme, &ended).await.unwrap();
        f.store
            .save(&f.acme, &given_now(ann, *admin.id()))
            .await
            .unwrap();

        let removed = f
            .store
            .remove_lapsed(&f.acme, &ended, clock::now())
            .await
            .unwrap();

        assert!(!removed);
        assert!(f.store.exists(&f.acme, &ann, admin.id()).await.unwrap());
    }

    /// The sweep clears a role whose end has still come, and hears that it
    /// did.
    #[tokio::test]
    async fn the_sweep_clears_a_role_that_ran_out() {
        let f = fixture().await;
        let admin = hold_role(&f.db, &f.acme, "admin").await;
        let ann = ann();
        let ended = ended_assignment(ann, *admin.id());
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

    /// Holders are counted per role in one read, and a role nobody holds
    /// is left out.
    #[tokio::test]
    async fn holders_are_counted_per_role() {
        let f = fixture().await;
        let admin = hold_role(&f.db, &f.acme, "admin").await;
        let viewer = hold_role(&f.db, &f.acme, "viewer").await;
        let unheld = hold_role(&f.db, &f.acme, "unheld").await;
        for (holder, held) in [(ann(), &admin), (ann(), &admin), (ann(), &viewer)] {
            f.store
                .save(&f.acme, &assignment(holder, *held.id()))
                .await
                .unwrap();
        }

        let one = f.store.count_by_role(&f.acme, admin.id()).await.unwrap();
        let each = f
            .store
            .count_by_roles(&f.acme, &[*admin.id(), *viewer.id(), *unheld.id()])
            .await
            .unwrap();

        assert_eq!(one, 2);
        assert_eq!(each.get(admin.id()), Some(&2));
        assert_eq!(each.get(viewer.id()), Some(&1));
        assert_eq!(each.get(unheld.id()), None);
    }

    /// Deleting "old" moves its holders onto "new": Ann gets "new", Bob,
    /// who already held it, keeps his own, and "old" is gone. Both of
    /// theirs count as removed.
    #[tokio::test]
    async fn deleting_a_role_moves_its_holders_onto_the_replacement() {
        let f = fixture().await;
        let old = hold_role(&f.db, &f.acme, "old").await;
        let new = hold_role(&f.db, &f.acme, "new").await;
        let (ann, bob) = (ann(), PrincipalRef::Agent(AgentId::new()));
        let bobs_own = assignment_until(bob, *new.id(), Expiry::At(at(900)));
        for given in [
            assignment(ann, *old.id()),
            assignment(bob, *old.id()),
            bobs_own,
        ] {
            f.store.save(&f.acme, &given).await.unwrap();
        }
        let deletion = PgRoleDeletionUnitOfWork::new(Arc::clone(&f.db.databases));

        let removed = deletion
            .reassign_and_delete(&f.acme, old.id(), new.id(), ActorRef::System)
            .await
            .unwrap();

        assert_eq!(removed, 2);
        let roles = PgRoleStore::new(Arc::clone(&f.db.databases));
        assert!(roles.find_by_id(&f.acme, old.id()).await.unwrap().is_none());
        assert!(f.store.exists(&f.acme, &ann, new.id()).await.unwrap());
        let bobs = f.store.find_by_principal(&f.acme, &bob).await.unwrap();
        assert_eq!(bobs.len(), 1);
        assert_eq!(bobs[0].expires(), Expiry::At(at(900)));
    }

    /// Replacing a deleted role preserves the end of Ann's active grant.
    /// Cy's expired grant produces no assignment to the replacement role.
    #[tokio::test]
    async fn deleting_a_role_moves_each_holder_with_their_end() {
        let f = fixture().await;
        let old = hold_role(&f.db, &f.acme, "old").await;
        let new = hold_role(&f.db, &f.acme, "new").await;
        let (ann, cy) = (ann(), ann());
        let now = OffsetDateTime::from_unix_timestamp(OffsetDateTime::now_utc().unix_timestamp())
            .unwrap();
        let ends = Expiry::At(now.saturating_add(Duration::days(30)));
        let for_a_while = RoleAssignment::reconstitute(RoleAssignmentRow {
            principal: ann,
            role_id: *old.id(),
            assigned_by: ActorRef::System,
            assigned_at: now.saturating_sub(Duration::days(1)),
            expires: ends,
        })
        .unwrap();
        for given in [for_a_while, ended_assignment(cy, *old.id())] {
            f.store.save(&f.acme, &given).await.unwrap();
        }
        let deletion = PgRoleDeletionUnitOfWork::new(Arc::clone(&f.db.databases));

        let removed = deletion
            .reassign_and_delete(&f.acme, old.id(), new.id(), ActorRef::System)
            .await
            .unwrap();

        let anns = f.store.find_by_principal(&f.acme, &ann).await.unwrap();
        let cys = f.store.find_by_principal(&f.acme, &cy).await.unwrap();
        assert_eq!(removed, 2);
        assert_eq!(anns.len(), 1);
        assert_eq!(anns[0].role_id(), new.id());
        assert_eq!(anns[0].expires(), ends);
        assert!(cys.is_empty());
    }

    /// The holders of "admin" are paged: Ann, given it straight, first,
    /// then the group carrying it. Bob, whose assignment ran out, is not
    /// listed, nor is a group carrying another role.
    #[tokio::test]
    async fn the_holders_of_a_role_are_paged_direct_ones_first() {
        let f = fixture().await;
        let admin = hold_role(&f.db, &f.acme, "admin").await;
        let viewer = hold_role(&f.db, &f.acme, "viewer").await;
        let (ann, bob) = (ann(), ann());
        f.give_until(ann, admin.id(), Expiry::Never).await;
        f.give_until(bob, admin.id(), Expiry::At(at(10))).await;
        let admins = f.group_carrying("Admins", admin.id()).await;
        f.group_carrying("Viewers", viewer.id()).await;
        let reader = PgRoleHolderQueries::new(Arc::clone(&f.db.databases));

        let first = reader
            .holders_of(
                &f.acme,
                admin.id(),
                at(500),
                &PageRequest::first(Limit::new(1).unwrap()),
            )
            .await
            .unwrap();
        let after = PageRequest::new(first.next.clone(), Limit::new(5).unwrap());
        let rest = reader
            .holders_of(&f.acme, admin.id(), at(500), &after)
            .await
            .unwrap();
        let elsewhere = reader
            .holders_of(&tenant(), admin.id(), at(500), &after)
            .await;

        assert_eq!(first.items, [RoleHolder::Direct(ann)]);
        assert_eq!(rest.items, [RoleHolder::Group(admins)]);
        assert!(!rest.has_next());
        assert!(elsewhere.unwrap().items.is_empty());
    }

    /// A bounded removal matches principal kind and ID as pairs, preserves
    /// other roles and tenants, and tolerates missing or repeated principals.
    #[tokio::test]
    async fn batch_removal_preserves_scope_and_principal_pairs() {
        let f = fixture().await;
        let own = hold_role(&f.db, &f.acme, "own").await;
        let other = hold_role(&f.db, &f.acme, "other").await;
        let PrincipalPairs { removed, retained } = principal_pairs();
        for role in [&own, &other] {
            for principal in removed.iter().chain(&retained) {
                f.give_until(*principal, role.id(), Expiry::Never).await;
            }
        }
        f.store
            .delete_for_principals(&tenant(), own.id(), &removed)
            .await
            .unwrap();
        assert_eq!(f.store.count_by_role(&f.acme, own.id()).await.unwrap(), 4);
        let request = [removed[0], removed[1], removed[0], ann()];
        f.remove_principals(own.id(), &request).await;
        f.remove_principals(own.id(), &[]).await;

        assert_eq!(f.store.count_by_role(&f.acme, own.id()).await.unwrap(), 2);
        assert_eq!(f.store.count_by_role(&f.acme, other.id()).await.unwrap(), 4);
        for principal in retained {
            assert!(f.store.exists(&f.acme, &principal, own.id()).await.unwrap());
        }
        for principal in removed {
            assert!(!f.store.exists(&f.acme, &principal, own.id()).await.unwrap());
        }
    }

    /// An assignment whose stored giver is a number is rejected as corrupt.
    #[tokio::test]
    async fn a_row_whose_giver_does_not_read_is_refused() {
        let f = fixture().await;
        let admin = hold_role(&f.db, &f.acme, "admin").await;
        let ann = ann();
        f.store
            .save(&f.acme, &assignment(ann, *admin.id()))
            .await
            .unwrap();
        f.db.tamper("UPDATE role_assignments SET assigned_by = '{\"v\": 1, \"value\": 7}'")
            .await;

        let read = f.store.find_by_principal(&f.acme, &ann).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
