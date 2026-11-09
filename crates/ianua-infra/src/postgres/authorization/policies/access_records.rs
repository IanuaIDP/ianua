//! A tenant's access records, read together: whole, for some holders, or
//! narrowed to what can make someone an administrator.
//!
//! Every read is a fixed handful of queries in one transaction, whatever
//! the tenant's size, so what one person holds is never worked out from
//! the whole tenant.

mod record;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::listing::{Page, PageRequest, SortOrder};
use ianua_app::ports::TenantScoped;
use ianua_app::ports::authorization::{
    AccessRecordStore, AccessRecords, AdministratorSortField, HeldRecords, Holder, Holders,
};
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::authorization::permission::SystemPermission;
use ianua_domain::domains::authorization::stewardship::{AdministratorCount, TenantGrants};
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{GroupId, PrincipalRef, RoleId, UserId};
use sqlx::PgConnection;
use time::OffsetDateTime;
use uuid::Uuid;

use self::record::RecordsRead;
use crate::postgres::authentication::sign_in::break_glass::record::BreakGlassRecord;
use crate::postgres::authorization::groups::memberships::record::MembershipRecord;
use crate::postgres::authorization::groups::tree::record::GroupRecord;
use crate::postgres::authorization::principals::kind_word;
use crate::postgres::authorization::resource_types::catalogue_of;
use crate::postgres::authorization::roles::assignments::record::AssignmentRecord;
use crate::postgres::authorization::roles::definitions::record::RoleRecord;
use crate::postgres::authorization::roles::definitions::roles_of;
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::{scoped, scoped_holding};

/// The Postgres store of a tenant's access records.
pub struct PgAccessRecordStore {
    databases: Arc<Databases>,
}

impl PgAccessRecordStore {
    /// A store reading the access records kept in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }

    /// The tenant's users who administer it now, each once.
    async fn administrators(&self, tenant_id: &ScopedTenant) -> Result<Vec<UserId>, DomainError> {
        let now = clock::now();
        let words = administering_words();
        let read = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| administering(connection, tenant_id.as_uuid(), &words, now).await,
        )
        .await?;
        let records = read.into_records(**tenant_id)?;
        TenantGrants {
            roles: &records.roles,
            assignments: &records.assignments,
            groups: &records.groups,
            memberships: &records.memberships,
        }
        .administrators()
    }

    /// The users of `tenant_id` whose roles give `right` now, worked out
    /// by the domain over the tenant's records read whole: a right can come
    /// from any role, so no narrower read holds every holder.
    async fn holders_of(
        &self,
        tenant_id: &ScopedTenant,
        right: SystemPermission,
    ) -> Result<Vec<UserId>, DomainError> {
        let records = self.load(tenant_id).await?;
        TenantGrants {
            roles: &records.roles,
            assignments: &records.assignments,
            groups: &records.groups,
            memberships: &records.memberships,
        }
        .holders_of_right(right)
    }

    /// The share of the records of `tenant_id` that decides what `wanted`
    /// holds now.
    async fn held_by(
        &self,
        tenant_id: &ScopedTenant,
        wanted: Wanted<'_>,
    ) -> Result<HeldRecords, DomainError> {
        let now = clock::now();
        let read = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| held(connection, tenant_id.as_uuid(), &wanted, now).await,
        )
        .await?;
        Ok(HeldRecords::new(read.into_records(**tenant_id)?))
    }
}

impl TenantScoped for PgAccessRecordStore {}

/// Whose records a narrowed read keeps.
struct Wanted<'a> {
    principals: &'a [PrincipalRef],
    groups: &'a [GroupId],
    roles: &'a [RoleId],
}

/// The built-in permissions that can make someone an administrator, as a
/// role stores them: every action of the roles and of the users areas.
fn administering_words() -> Vec<String> {
    SystemPermission::ALL_VARIANTS
        .iter()
        .filter(|right| {
            matches!(
                right,
                SystemPermission::Roles(_) | SystemPermission::Users(_)
            )
        })
        .map(ToString::to_string)
        .collect()
}

/// Every access record of `tenant_id`.
async fn whole(
    connection: &mut PgConnection,
    tenant_id: &Uuid,
) -> Result<RecordsRead, sqlx::Error> {
    Ok(RecordsRead {
        roles: sqlx::query_file_as!(RoleRecord, "queries/roles/of_tenant.sql", tenant_id)
            .fetch_all(&mut *connection)
            .await?,
        assignments: sqlx::query_file_as!(
            AssignmentRecord,
            "queries/role_assignments/of_tenant.sql",
            tenant_id
        )
        .fetch_all(&mut *connection)
        .await?,
        groups: sqlx::query_file_as!(GroupRecord, "queries/groups/of_tenant.sql", tenant_id)
            .fetch_all(&mut *connection)
            .await?,
        memberships: sqlx::query_file_as!(
            MembershipRecord,
            "queries/group_memberships/of_tenant.sql",
            tenant_id
        )
        .fetch_all(&mut *connection)
        .await?,
        catalogue: catalogue_of(&mut *connection, tenant_id).await?,
        break_glass: all_break_glass(connection, tenant_id).await?,
    })
}

/// Reads the tenant's break-glass records after the ordinary grant catalogue.
async fn all_break_glass(
    connection: &mut PgConnection,
    tenant_id: &Uuid,
) -> Result<Vec<BreakGlassRecord>, sqlx::Error> {
    sqlx::query_file_as!(
        BreakGlassRecord,
        "queries/break_glass_grants/of_tenant.sql",
        tenant_id
    )
    .fetch_all(connection)
    .await
}

/// Parallel principal columns used by both direct-grant queries.
struct PrincipalKeys {
    kinds: Vec<&'static str>,
    ids: Vec<Uuid>,
}

impl PrincipalKeys {
    /// Preserves principal order and kind alongside each identifier.
    fn of(principals: &[PrincipalRef]) -> Self {
        let (kinds, ids) = principals
            .iter()
            .map(|principal| (kind_word(principal), principal.id()))
            .unzip();
        Self { kinds, ids }
    }
}

/// Reads direct role grants for exactly the requested principal pairs.
async fn assignments_for(
    connection: &mut PgConnection,
    tenant_id: &Uuid,
    keys: &PrincipalKeys,
) -> Result<Vec<AssignmentRecord>, sqlx::Error> {
    sqlx::query_file_as!(
        AssignmentRecord,
        "queries/role_assignments/of_principals.sql",
        tenant_id,
        &keys.kinds as &[&str],
        &keys.ids
    )
    .fetch_all(connection)
    .await
}

/// Reads direct group memberships for exactly the requested principal pairs.
async fn memberships_for(
    connection: &mut PgConnection,
    tenant_id: &Uuid,
    keys: &PrincipalKeys,
) -> Result<Vec<MembershipRecord>, sqlx::Error> {
    sqlx::query_file_as!(
        MembershipRecord,
        "queries/group_memberships/of_principals.sql",
        tenant_id,
        &keys.kinds as &[&str],
        &keys.ids
    )
    .fetch_all(connection)
    .await
}

/// Expands memberships and explicitly requested groups to their complete ancestry.
async fn groups_with_ancestors(
    connection: &mut PgConnection,
    tenant_id: &Uuid,
    memberships: &[MembershipRecord],
    wanted: &[GroupId],
) -> Result<Vec<GroupRecord>, sqlx::Error> {
    let starts: Vec<Uuid> = memberships
        .iter()
        .map(|membership| membership.group_id)
        .chain(wanted.iter().map(|group| *group.as_uuid()))
        .collect();
    sqlx::query_file_as!(
        GroupRecord,
        "queries/groups/with_ancestors.sql",
        tenant_id,
        &starts
    )
    .fetch_all(connection)
    .await
}

/// Names roles from direct assignments, expanded groups and explicitly granted roles.
fn named_roles(
    assignments: &[AssignmentRecord],
    groups: &[GroupRecord],
    wanted: &[RoleId],
) -> Vec<Uuid> {
    assignments
        .iter()
        .map(|assignment| assignment.role_id)
        .chain(
            groups
                .iter()
                .flat_map(|group| group.role_ids.iter().copied()),
        )
        .chain(wanted.iter().map(|role| *role.as_uuid()))
        .collect()
}

/// Reads currently running break-glass grants only for tenant-user principals.
async fn break_glass_for(
    connection: &mut PgConnection,
    tenant_id: &Uuid,
    principals: &[PrincipalRef],
    now: OffsetDateTime,
) -> Result<Vec<BreakGlassRecord>, sqlx::Error> {
    let users: Vec<Uuid> = principals
        .iter()
        .filter_map(PrincipalRef::as_user)
        .map(|user| *user.as_uuid())
        .collect();
    sqlx::query_file_as!(
        BreakGlassRecord,
        "queries/break_glass_grants/running_for_users.sql",
        tenant_id,
        &users,
        now
    )
    .fetch_all(connection)
    .await
}

/// The share of `tenant_id`'s records that decides what `wanted` holds at
/// `now`: the principals' own assignments and memberships, the groups those
/// and `wanted.groups` name with every group above, the roles all of them
/// and `wanted.roles` name, the catalogue, and the principals' break-glass
/// grants still running.
async fn held(
    connection: &mut PgConnection,
    tenant_id: &Uuid,
    wanted: &Wanted<'_>,
    now: OffsetDateTime,
) -> Result<RecordsRead, sqlx::Error> {
    let keys = PrincipalKeys::of(wanted.principals);
    let assignments = assignments_for(&mut *connection, tenant_id, &keys).await?;
    let memberships = memberships_for(&mut *connection, tenant_id, &keys).await?;
    let groups =
        groups_with_ancestors(&mut *connection, tenant_id, &memberships, wanted.groups).await?;
    let named = named_roles(&assignments, &groups, wanted.roles);
    Ok(RecordsRead {
        roles: roles_of(&mut *connection, tenant_id, &named).await?,
        assignments,
        groups,
        memberships,
        catalogue: catalogue_of(&mut *connection, tenant_id).await?,
        break_glass: break_glass_for(connection, tenant_id, wanted.principals, now).await?,
    })
}

/// The share of `tenant_id`'s records that can make someone an
/// administrator at `now`: the roles holding any of `words`, the tenant
/// users given them straight, every group with only those of its roles,
/// and the tenant users in a group at or below one carrying them.
async fn administering(
    connection: &mut PgConnection,
    tenant_id: &Uuid,
    words: &[String],
    now: OffsetDateTime,
) -> Result<RecordsRead, sqlx::Error> {
    let roles = administering_roles(&mut *connection, tenant_id, words).await?;
    let ids: Vec<Uuid> = roles.iter().map(|role| role.id).collect();
    Ok(RecordsRead {
        roles,
        assignments: administering_assignments(&mut *connection, tenant_id, &ids, now).await?,
        groups: sqlx::query_file_as!(
            GroupRecord,
            "queries/groups/carrying_only.sql",
            tenant_id,
            &ids
        )
        .fetch_all(&mut *connection)
        .await?,
        memberships: sqlx::query_file_as!(
            MembershipRecord,
            "queries/group_memberships/administering.sql",
            tenant_id,
            &ids,
            now
        )
        .fetch_all(connection)
        .await?,
        ..RecordsRead::default()
    })
}

/// Reads roles carrying one of the permissions used to determine administrators.
async fn administering_roles(
    connection: &mut PgConnection,
    tenant_id: &Uuid,
    words: &[String],
) -> Result<Vec<RoleRecord>, sqlx::Error> {
    sqlx::query_file_as!(
        RoleRecord,
        "queries/roles/administering.sql",
        tenant_id,
        words
    )
    .fetch_all(connection)
    .await
}

/// Reads active direct user assignments to the candidate administrator roles.
async fn administering_assignments(
    connection: &mut PgConnection,
    tenant_id: &Uuid,
    roles: &[Uuid],
    now: OffsetDateTime,
) -> Result<Vec<AssignmentRecord>, sqlx::Error> {
    sqlx::query_file_as!(
        AssignmentRecord,
        "queries/role_assignments/administering.sql",
        tenant_id,
        roles,
        now
    )
    .fetch_all(connection)
    .await
}

#[async_trait]
impl AccessRecordStore for PgAccessRecordStore {
    async fn load(&self, tenant_id: &ScopedTenant) -> Result<AccessRecords, DomainError> {
        let read = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| whole(connection, tenant_id.as_uuid()).await,
        )
        .await?;
        read.into_records(**tenant_id)
    }

    async fn load_held_by(
        &self,
        tenant_id: &ScopedTenant,
        holder: Holder<'_>,
    ) -> Result<HeldRecords, DomainError> {
        let wanted = Wanted {
            principals: std::slice::from_ref(&holder.principal),
            groups: &[],
            roles: holder.granted_roles,
        };
        self.held_by(tenant_id, wanted).await
    }

    async fn load_held_by_all(
        &self,
        tenant_id: &ScopedTenant,
        holders: Holders<'_>,
    ) -> Result<HeldRecords, DomainError> {
        let wanted = Wanted {
            principals: holders.principals,
            groups: holders.groups,
            roles: holders.roles,
        };
        self.held_by(tenant_id, wanted).await
    }

    async fn count_administrators(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<AdministratorCount, DomainError> {
        let found = self.administrators(tenant_id).await?;
        Ok(AdministratorCount::new(
            u64::try_from(found.len()).unwrap_or(u64::MAX),
        ))
    }

    async fn list_administrators(
        &self,
        tenant_id: &ScopedTenant,
        page: &PageRequest,
    ) -> Result<Page<UserId>, DomainError> {
        let order = SortOrder::<AdministratorSortField>::default();
        let keyset = page.keyset(&order)?;
        let found = self.administrators(tenant_id).await?;
        Ok(keyset.cut(found))
    }

    async fn list_holders_of(
        &self,
        tenant_id: &ScopedTenant,
        right: SystemPermission,
        page: &PageRequest,
    ) -> Result<Page<UserId>, DomainError> {
        let order = SortOrder::<AdministratorSortField>::default();
        let keyset = page.keyset(&order)?;
        let found = self.holders_of(tenant_id, right).await?;
        Ok(keyset.cut(found))
    }

    async fn hold_grants(&self, tenant_id: &ScopedTenant) -> Result<(), DomainError> {
        scoped_holding(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_scalar!(
                    "queries/role_assignments/hold_grants.sql",
                    tenant_id.as_uuid()
                )
                .fetch_one(connection)
                .await
                .map(|_| ())
            },
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::listing::Limit;
    use ianua_app::ports::authentication::BreakGlassStore;
    use ianua_app::ports::authorization::{
        GroupMembershipStore, GroupStore, ResourceTypeStore, RoleAssignmentStore, RoleStore,
    };
    use ianua_app::ports::identity::UserStore;
    use ianua_app::ports::runtime::{Settlement, atomically};
    use ianua_domain::domains::authorization::break_glass::{BreakGlassGrant, BreakGlassGrantRow};
    use ianua_domain::domains::authorization::group::{Group, GroupPlace};
    use ianua_domain::domains::authorization::permission::{
        BrandingAction, RoleAction, UserAction,
    };
    use ianua_domain::domains::authorization::role::{Role, RoleRow};
    use ianua_domain::domains::identity::account::user::{User, UserRow};
    use ianua_domain::isolation::scope::ResolvedTenant;
    use ianua_domain::shared::config::DomainLimits;
    use ianua_domain::types::AgentId;

    use super::*;
    use crate::postgres::authentication::PgBreakGlassStore;
    use crate::postgres::authorization::{
        PgGroupMembershipStore, PgGroupStore, PgResourceTypeStore, PgRoleAssignmentStore,
        PgRoleStore,
    };
    use crate::postgres::foundation::unit::PgUnitOfWork;
    use crate::postgres::identity::PgUserStore;
    use crate::test_support::TestDb;
    use crate::test_support::rows::authentication::grant_row;
    use crate::test_support::rows::authorization::{
        assignment, ended_assignment, group, group_under, membership, resource_type, role,
        role_row, tenant,
    };
    use crate::test_support::rows::identity::{from_now, user_row};

    /// The stores the records are arranged through, on one fresh database.
    struct Fixture {
        db: TestDb,
        store: PgAccessRecordStore,
        roles: PgRoleStore,
        assignments: PgRoleAssignmentStore,
        groups: PgGroupStore,
        memberships: PgGroupMembershipStore,
        acme: ScopedTenant,
    }

    /// A fresh database, the store on it, the stores that write what it
    /// reads, and a tenant to keep records in.
    async fn fixture() -> Fixture {
        let db = TestDb::fresh().await;
        let databases = || Arc::clone(&db.databases);
        Fixture {
            store: PgAccessRecordStore::new(databases()),
            roles: PgRoleStore::new(databases()),
            assignments: PgRoleAssignmentStore::new(databases()),
            groups: PgGroupStore::new(databases()),
            memberships: PgGroupMembershipStore::new(databases()),
            acme: tenant(),
            db,
        }
    }

    impl Fixture {
        async fn role(&self, held: Role<ResolvedTenant>) -> Role<ResolvedTenant> {
            self.roles.save(&self.acme, &held).await.unwrap();
            held
        }

        async fn group(&self, held: Group<ResolvedTenant>) -> Group<ResolvedTenant> {
            self.groups.save(&self.acme, &held).await.unwrap();
            held
        }

        async fn give(&self, principal: PrincipalRef, role: &Role<ResolvedTenant>) {
            self.assignments
                .save(&self.acme, &assignment(principal, *role.id()))
                .await
                .unwrap();
        }

        async fn join(&self, principal: PrincipalRef, group: &Group<ResolvedTenant>) {
            self.memberships
                .save(&self.acme, &membership(principal, *group.id()))
                .await
                .unwrap();
        }

        /// Persists an expired direct assignment as a control for active-holder queries.
        async fn give_ended(&self, principal: PrincipalRef, role: &Role<ResolvedTenant>) {
            self.assignments
                .save(&self.acme, &ended_assignment(principal, *role.id()))
                .await
                .unwrap();
        }

        /// Reads one page of users holding the requested system permission.
        async fn holders_of(&self, right: SystemPermission, page: &PageRequest) -> Page<UserId> {
            self.store
                .list_holders_of(&self.acme, right, page)
                .await
                .unwrap()
        }

        /// Gives `user` a running break-glass grant of "view users" through
        /// the break-glass store, the user saved first through their own.
        async fn break_glass(&self, user: UserId) {
            let account = User::reconstitute(UserRow {
                id: user,
                ..user_row(&format!("u{}@acme.example", user.as_uuid().simple()))
            })
            .unwrap();
            PgUserStore::new(Arc::clone(&self.db.databases), DomainLimits::default())
                .save(&self.acme, &account)
                .await
                .unwrap();
            let grant = BreakGlassGrant::reconstitute(BreakGlassGrantRow {
                created_at: from_now(-60),
                expires_at: from_now(3600),
                ..grant_row(*self.acme, user, 0)
            })
            .unwrap();
            PgBreakGlassStore::new(Arc::clone(&self.db.databases))
                .save(&self.acme, &grant)
                .await
                .unwrap();
        }
    }

    fn admin_role() -> Role<ResolvedTenant> {
        Role::reconstitute(RoleRow {
            system_permissions: vec![
                SystemPermission::Roles(RoleAction::Manage),
                SystemPermission::Users(UserAction::Manage),
            ],
            ..role_row("admin")
        })
        .unwrap()
    }

    fn user() -> (UserId, PrincipalRef) {
        let id = UserId::new();
        (id, PrincipalRef::User(id))
    }

    /// Constructs a role carrying exactly the permission whose holders are queried.
    fn role_with_right(name: &str, right: SystemPermission) -> Role<ResolvedTenant> {
        Role::reconstitute(RoleRow {
            system_permissions: vec![right],
            ..role_row(name)
        })
        .unwrap()
    }

    /// Proves the narrowed read includes Ann's direct and inherited grants and no Bob records.
    fn assert_anns_share(records: &AccessRecords, ann: UserId) {
        let mut roles: Vec<&str> = records
            .roles
            .iter()
            .map(|held| held.name().as_str())
            .collect();
        roles.sort_unstable();
        let mut groups: Vec<&str> = records
            .groups
            .iter()
            .map(|held| held.name().as_str())
            .collect();
        groups.sort_unstable();
        assert_eq!(roles, ["admin", "viewer"]);
        assert_eq!(groups, ["Backend", "Engineering"]);
        assert_eq!(records.assignments.len(), 1);
        assert_eq!(records.memberships.len(), 1);
        assert_eq!(records.break_glass.len(), 1);
        assert_eq!(*records.break_glass[0].user_id(), ann);
    }

    /// The whole read holds every role, assignment, group, membership,
    /// resource type and break-glass grant of the tenant.
    #[tokio::test]
    async fn the_whole_records_hold_every_record_of_the_tenant() {
        let f = fixture().await;
        let viewer = f.role(role("viewer")).await;
        let engineering = f.group(group("Engineering", vec![*viewer.id()])).await;
        let (ann_id, ann) = user();
        f.give(ann, &viewer).await;
        f.join(ann, &engineering).await;
        PgResourceTypeStore::new(Arc::clone(&f.db.databases))
            .save(&f.acme, &resource_type("project"))
            .await
            .unwrap();
        f.break_glass(ann_id).await;

        let records = f.store.load(&f.acme).await.unwrap();

        assert_eq!(records.roles.len(), 1);
        assert_eq!(records.assignments.len(), 1);
        assert_eq!(records.groups.len(), 1);
        assert_eq!(records.memberships.len(), 1);
        assert_eq!(records.catalogue.len(), 1);
        assert_eq!(records.break_glass.len(), 1);
    }

    /// Ann's share holds her assignment, her group and the one above it,
    /// the roles those name and her running break-glass grant, and nothing
    /// of Bob's.
    #[tokio::test]
    async fn one_holders_share_is_hers_alone() {
        let f = fixture().await;
        let (viewer, admin, bobs) = (
            f.role(role("viewer")).await,
            f.role(role("admin")).await,
            f.role(role("bobs")).await,
        );
        let engineering = f.group(group("Engineering", vec![*admin.id()])).await;
        let backend = f
            .group(group_under("Backend", GroupPlace::Under(*engineering.id())))
            .await;
        let sales = f.group(group("Sales", Vec::new())).await;
        let (ann_id, ann) = user();
        let (bob_id, bob) = user();
        f.give(ann, &viewer).await;
        f.join(ann, &backend).await;
        f.give(bob, &bobs).await;
        f.join(bob, &sales).await;
        f.break_glass(ann_id).await;
        f.break_glass(bob_id).await;

        let share = f
            .store
            .load_held_by(&f.acme, Holder::of(ann))
            .await
            .unwrap();

        assert_anns_share(share.records(), ann_id);
    }

    /// A second unit of work waits for the first unit's grant hold, then reads
    /// the payments assignment that the first unit saved for Bob.
    #[tokio::test]
    async fn a_check_under_the_hold_sees_the_grant_held_before_it() {
        let f = fixture().await;
        let payments = f.role(role("payments")).await;
        let (_, bob) = user();
        let (store, assignments, acme) = (&f.store, &f.assignments, &f.acme);
        let (held, first_held) = tokio::sync::oneshot::channel();
        let first = atomically(
            &PgUnitOfWork,
            async {
                store.hold_grants(acme).await.unwrap();
                held.send(()).unwrap();
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                assignments
                    .save(acme, &assignment(bob, *payments.id()))
                    .await
                    .unwrap();
            },
            |()| Settlement::Commit,
        );
        let second = atomically(
            &PgUnitOfWork,
            async {
                first_held.await.unwrap();
                store.hold_grants(acme).await.unwrap();
                store.load_held_by(acme, Holder::of(bob)).await.unwrap()
            },
            |_| Settlement::Commit,
        );

        let (first, second) = tokio::join!(first, second);

        first.unwrap();
        assert_eq!(second.unwrap().records().assignments.len(), 1);
    }

    /// A read for several holders keeps a group asked about with the ones
    /// above it, and a role named besides their records.
    #[tokio::test]
    async fn a_share_of_several_holders_keeps_the_groups_and_roles_asked_about() {
        let f = fixture().await;
        let (admin, granted) = (f.role(role("admin")).await, f.role(role("granted")).await);
        let engineering = f.group(group("Engineering", vec![*admin.id()])).await;
        let backend = f
            .group(group_under("Backend", GroupPlace::Under(*engineering.id())))
            .await;
        let (_, ann) = user();
        let (_, cy) = user();

        let share = f
            .store
            .load_held_by_all(
                &f.acme,
                Holders {
                    principals: &[ann, cy],
                    groups: &[*backend.id()],
                    roles: &[*granted.id()],
                },
            )
            .await
            .unwrap();

        let records = share.records();
        assert_eq!(records.groups.len(), 2);
        assert_eq!(records.roles.len(), 2);
        assert!(records.assignments.is_empty());
    }

    /// Ann administers through her role, Bob through a group under one
    /// carrying it. Cy's admin role ran out, an agent never counts, and a
    /// viewer does not administer. Two are counted, and listed by id.
    #[tokio::test]
    async fn the_administrators_are_counted_and_listed() {
        let f = fixture().await;
        let admin = f.role(admin_role()).await;
        let viewer = f.role(role("viewer")).await;
        let admins = f.group(group("Admins", vec![*admin.id()])).await;
        let on_call = f
            .group(group_under("On call", GroupPlace::Under(*admins.id())))
            .await;
        let (ann_id, ann) = user();
        let (bob_id, bob) = user();
        let (_, cy) = user();
        let (_, dee) = user();
        f.give(ann, &admin).await;
        f.join(bob, &on_call).await;
        f.give_ended(cy, &admin).await;
        f.give(PrincipalRef::Agent(AgentId::new()), &admin).await;
        f.give(dee, &viewer).await;

        let count = f.store.count_administrators(&f.acme).await.unwrap();
        let page_one = f
            .store
            .list_administrators(&f.acme, &PageRequest::first(Limit::new(1).unwrap()))
            .await
            .unwrap();
        let after = PageRequest::new(page_one.next.clone(), Limit::new(5).unwrap());
        let page_two = f.store.list_administrators(&f.acme, &after).await.unwrap();

        let mut expected = [ann_id, bob_id];
        expected.sort_by_key(|id| *id.as_uuid());
        assert_eq!(count.get(), 2);
        assert_eq!(page_one.items, expected[..1]);
        assert_eq!(page_two.items, expected[1..]);
        assert!(!page_two.has_next());
    }

    /// Mia views branding through the group Mail, Ann holds it herself, and
    /// Dee only views users. The holders of `branding: view` are Mia and
    /// Ann, by id, one page at a time; Dee is not among them.
    #[tokio::test]
    async fn the_holders_of_a_right_are_listed() {
        let view_branding = SystemPermission::Branding(BrandingAction::View);
        let f = fixture().await;
        let branding = f.role(role_with_right("branding", view_branding)).await;
        let users_viewer = f
            .role(role_with_right(
                "users",
                SystemPermission::Users(UserAction::View),
            ))
            .await;
        let mail = f.group(group("Mail", vec![*branding.id()])).await;
        let (mia_id, mia) = user();
        let (ann_id, ann) = user();
        let (dee_id, dee) = user();
        f.join(mia, &mail).await;
        f.give(ann, &branding).await;
        f.give(dee, &users_viewer).await;

        let page_one = f
            .holders_of(view_branding, &PageRequest::first(Limit::new(1).unwrap()))
            .await;
        let after = PageRequest::new(page_one.next.clone(), Limit::new(5).unwrap());
        let page_two = f.holders_of(view_branding, &after).await;

        let mut expected = [mia_id, ann_id];
        expected.sort_by_key(|id| *id.as_uuid());
        assert_eq!(page_one.items, expected[..1]);
        assert_eq!(page_two.items, expected[1..]);
        assert!(!page_two.items.contains(&dee_id) && !page_one.items.contains(&dee_id));
    }

    /// Globex reads no Acme roles or assignments, finds no roles for Ann, and
    /// counts no administrators.
    #[tokio::test]
    async fn another_tenants_records_are_invisible() {
        let f = fixture().await;
        let admin = f.role(admin_role()).await;
        let (_, ann) = user();
        f.give(ann, &admin).await;
        let globex = tenant();

        let whole = f.store.load(&globex).await.unwrap();
        let share = f
            .store
            .load_held_by(&globex, Holder::of(ann))
            .await
            .unwrap();
        let count = f.store.count_administrators(&globex).await.unwrap();

        assert!(whole.roles.is_empty() && whole.assignments.is_empty());
        assert!(share.records().roles.is_empty());
        assert_eq!(count.get(), 0);
    }

    /// Reading Ann's records rejects a stored break-glass grant with no
    /// permissions as corrupt.
    #[tokio::test]
    async fn a_grant_that_grants_nothing_is_refused() {
        let f = fixture().await;
        let (ann_id, ann) = user();
        f.break_glass(ann_id).await;
        f.db.tamper(
            "ALTER TABLE break_glass_grants DROP CONSTRAINT break_glass_grants_grants_something; \
             UPDATE break_glass_grants SET system_permissions = ARRAY[]::text[]",
        )
        .await;

        let read = f.store.load_held_by(&f.acme, Holder::of(ann)).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
