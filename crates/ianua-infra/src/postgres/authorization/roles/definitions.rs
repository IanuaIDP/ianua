//! A tenant's roles: what each grants, and which ones a principal holds.
//!
//! Every read of a role goes through one mapping into the aggregate. A list
//! first reads the ids of its page, then those rows by id.

pub(crate) mod record;

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::listing::{Page, PageRequest, SortOrder};
use ianua_app::ports::TenantScoped;
use ianua_app::ports::authorization::{RoleSortField, RoleStore};
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::authorization::role::Role;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{Label, PrincipalRef, RoleId};
use sqlx::PgConnection;
use uuid::Uuid;

use self::record::{DirectRoleRecord, RoleColumns, RoleRecord, direct_roles_from, roles_from};
use crate::postgres::authorization::principals::kind_word;
use crate::postgres::foundation::errors::{Uniqueness, unique_on};
use crate::postgres::foundation::paging::{Nullable, PageQuery, SortColumns, in_page_order};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The constraint that keeps a name to one role of a tenant.
const NAME_KEY: &str = "roles_name_key";

/// The Postgres role store.
pub struct PgRoleStore {
    databases: Arc<Databases>,
}

impl PgRoleStore {
    /// A store keeping roles in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }

    /// The roles of `tenant_id` with the ids `ids`, in no order.
    async fn by_ids(
        &self,
        tenant_id: &ScopedTenant,
        ids: &[Uuid],
    ) -> Result<Vec<Role<ResolvedTenant>>, DomainError> {
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| roles_of(connection, tenant_id.as_uuid(), ids).await,
        )
        .await?;
        roles_from(records)
    }
}

impl TenantScoped for PgRoleStore {}

/// The records of the roles of `tenant_id` that `ids` names, in no order.
pub(crate) async fn roles_of(
    connection: &mut PgConnection,
    tenant_id: &Uuid,
    ids: &[Uuid],
) -> Result<Vec<RoleRecord>, sqlx::Error> {
    sqlx::query_file_as!(RoleRecord, "queries/roles/by_ids.sql", tenant_id, ids)
        .fetch_all(connection)
        .await
}

impl SortColumns for RoleSortField {
    fn column(self) -> &'static str {
        match self {
            Self::CreatedAt => "created_at",
            Self::UpdatedAt => "updated_at",
            Self::Name => "name",
        }
    }

    fn nullable(self) -> Nullable {
        Nullable::Never
    }
}

#[async_trait]
impl RoleStore for PgRoleStore {
    async fn find_by_principals(
        &self,
        tenant_id: &ScopedTenant,
        principals: &[PrincipalRef],
    ) -> Result<HashMap<PrincipalRef, Vec<Role<ResolvedTenant>>>, DomainError> {
        if principals.is_empty() {
            return Ok(HashMap::new());
        }
        let kinds: Vec<_> = principals
            .iter()
            .map(|principal| kind_word(principal).to_owned())
            .collect();
        let ids: Vec<_> = principals.iter().map(PrincipalRef::id).collect();
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    DirectRoleRecord,
                    "queries/roles/given_to_principals.sql",
                    tenant_id.as_uuid(),
                    &kinds,
                    &ids
                )
                .fetch_all(connection)
                .await
            },
        )
        .await?;
        direct_roles_from(records)
    }

    async fn find_by_names(
        &self,
        tenant_id: &ScopedTenant,
        names: &[Label],
    ) -> Result<Vec<Role<ResolvedTenant>>, DomainError> {
        if names.is_empty() {
            return Ok(Vec::new());
        }
        let names: Vec<_> = names.iter().map(|name| name.as_str().to_owned()).collect();
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    RoleRecord,
                    "queries/roles/by_names.sql",
                    tenant_id.as_uuid(),
                    &names
                )
                .fetch_all(connection)
                .await
            },
        )
        .await?;
        roles_from(records)
    }

    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &RoleId,
    ) -> Result<Option<Role<ResolvedTenant>>, DomainError> {
        Ok(self.by_ids(tenant_id, &[*id.as_uuid()]).await?.pop())
    }

    async fn find_by_ids(
        &self,
        tenant_id: &ScopedTenant,
        ids: &[RoleId],
    ) -> Result<Vec<Role<ResolvedTenant>>, DomainError> {
        let ids: Vec<Uuid> = ids.iter().map(|id| *id.as_uuid()).collect();
        self.by_ids(tenant_id, &ids).await
    }

    async fn find_by_name(
        &self,
        tenant_id: &ScopedTenant,
        name: &Label,
    ) -> Result<Option<Role<ResolvedTenant>>, DomainError> {
        let record = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    RoleRecord,
                    "queries/roles/by_name.sql",
                    tenant_id.as_uuid(),
                    name.as_str()
                )
                .fetch_optional(connection)
                .await
            },
        )
        .await?;
        record.map(RoleRecord::into_role).transpose()
    }

    async fn list_all(
        &self,
        tenant_id: &ScopedTenant,
        sort: &SortOrder<RoleSortField>,
        page: &PageRequest,
    ) -> Result<Page<Role<ResolvedTenant>>, DomainError> {
        let keyset = page.keyset(sort)?;
        let listed = PageQuery::ids("id", "roles").filter("tenant_id = ?", *tenant_id.as_uuid());
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                let ids = listed.fetch(&keyset, &mut *connection).await?;
                let records = roles_of(connection, tenant_id.as_uuid(), &ids).await?;
                Ok(in_page_order(&ids, records, |record| record.id))
            },
        )
        .await?;
        Ok(keyset.seal(roles_from(records)?))
    }

    async fn find_defaults(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<Vec<Role<ResolvedTenant>>, DomainError> {
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    RoleRecord,
                    "queries/roles/given_to_new_users.sql",
                    tenant_id.as_uuid()
                )
                .fetch_all(connection)
                .await
            },
        )
        .await?;
        roles_from(records)
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        role: &Role<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let columns = RoleColumns::of(role);
        let written = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                let attempt = sqlx::query_file!(
                    "queries/roles/save.sql",
                    columns.id,
                    tenant_id.as_uuid(),
                    columns.name,
                    &columns.system_permissions,
                    &columns.custom_permissions,
                    columns.is_default,
                    columns.created_at,
                    columns.updated_at,
                )
                .execute(connection)
                .await;
                unique_on(attempt, NAME_KEY)
            },
        )
        .await?;
        match written {
            Uniqueness::Kept => Ok(()),
            Uniqueness::Taken => Err(DomainError::conflict(message!(
                "infra-another-role-of-this-tenant-already",
                "another role of this tenant already has this name"
            ))),
        }
    }

    async fn delete(&self, tenant_id: &ScopedTenant, id: &RoleId) -> Result<(), DomainError> {
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/roles/delete.sql",
                    tenant_id.as_uuid(),
                    id.as_uuid()
                )
                .execute(connection)
                .await?;
                Ok(())
            },
        )
        .await
    }

    async fn find_by_principal(
        &self,
        tenant_id: &ScopedTenant,
        principal: &PrincipalRef,
    ) -> Result<Vec<Role<ResolvedTenant>>, DomainError> {
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    RoleRecord,
                    "queries/roles/given_to_principal.sql",
                    tenant_id.as_uuid(),
                    kind_word(principal),
                    principal.id()
                )
                .fetch_all(connection)
                .await
            },
        )
        .await?;
        roles_from(records)
    }

    async fn find_effective_by_principal(
        &self,
        tenant_id: &ScopedTenant,
        principal: &PrincipalRef,
    ) -> Result<Vec<Role<ResolvedTenant>>, DomainError> {
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    RoleRecord,
                    "queries/roles/held_by_principal.sql",
                    tenant_id.as_uuid(),
                    kind_word(principal),
                    principal.id(),
                    clock::now()
                )
                .fetch_all(connection)
                .await
            },
        )
        .await?;
        roles_from(records)
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::listing::{Limit, Sort};
    use ianua_app::ports::authorization::{GroupMembershipStore, GroupStore, RoleAssignmentStore};
    use ianua_domain::domains::authorization::group::{Group, GroupPlace};
    use ianua_domain::domains::authorization::role::RoleRow;
    use ianua_domain::types::{AgentId, UserId};

    use super::*;
    use crate::postgres::authorization::{
        PgGroupMembershipStore, PgGroupStore, PgRoleAssignmentStore,
    };
    use crate::test_support::TestDb;
    use crate::test_support::rows::at;
    use crate::test_support::rows::authorization::{
        assignment, default_role, ended_assignment, ended_membership, group, group_under,
        membership, role, role_row, tenant,
    };

    /// A fresh database, the store on it, and a tenant to keep roles in.
    async fn fixture() -> (TestDb, PgRoleStore, ScopedTenant) {
        let db = TestDb::fresh().await;
        let store = PgRoleStore::new(Arc::clone(&db.databases));
        (db, store, tenant())
    }

    fn by(field: RoleSortField) -> SortOrder<RoleSortField> {
        SortOrder::single(Sort::ascending(field))
    }

    fn first(limit: u32) -> PageRequest {
        PageRequest::first(Limit::new(limit).unwrap())
    }

    fn names(roles: &[Role<ResolvedTenant>]) -> Vec<&str> {
        roles.iter().map(|role| role.name().as_str()).collect()
    }

    /// Persists a group and its direct members through their ordinary stores.
    async fn save_group_members(
        db: &TestDb,
        tenant: &ScopedTenant,
        group: &Group<ResolvedTenant>,
        members: &[PrincipalRef],
    ) {
        PgGroupStore::new(Arc::clone(&db.databases))
            .save(tenant, group)
            .await
            .unwrap();
        let memberships = PgGroupMembershipStore::new(Arc::clone(&db.databases));
        for member in members {
            memberships
                .save(tenant, &membership(*member, *group.id()))
                .await
                .unwrap();
        }
    }

    /// Roles for direct, expired, inherited and foreign batch controls, in that order.
    async fn batch_roles(
        store: &PgRoleStore,
        acme: &ScopedTenant,
        other: &ScopedTenant,
    ) -> [Role<ResolvedTenant>; 4] {
        let viewer = role("viewer");
        let expired = role("expired");
        let inherited = role("inherited");
        let foreign = role("foreign");
        for item in [&viewer, &expired, &inherited] {
            store.save(acme, item).await.unwrap();
        }
        store.save(other, &foreign).await.unwrap();
        [viewer, expired, inherited, foreign]
    }

    /// The tenant and principal controls for a direct-role batch lookup.
    struct DirectBatch {
        other: ScopedTenant,
        ann: PrincipalRef,
        agent: PrincipalRef,
        absent: PrincipalRef,
    }

    /// Creates direct and expired grants, a foreign grant and an inherited-role control.
    async fn direct_batch(db: &TestDb, store: &PgRoleStore, acme: &ScopedTenant) -> DirectBatch {
        let other = tenant();
        let [viewer, expired, inherited, foreign] = batch_roles(store, acme, &other).await;
        let user = UserId::new();
        let ann = PrincipalRef::User(user);
        let agent = PrincipalRef::Agent(AgentId::from_uuid(*user.as_uuid()));
        let absent = PrincipalRef::User(UserId::new());
        let assignments = PgRoleAssignmentStore::new(Arc::clone(&db.databases));
        assignments
            .save(acme, &assignment(ann, *viewer.id()))
            .await
            .unwrap();
        assignments
            .save(acme, &ended_assignment(agent, *expired.id()))
            .await
            .unwrap();
        assignments
            .save(&other, &assignment(ann, *foreign.id()))
            .await
            .unwrap();
        let team = group("Team", vec![*inherited.id()]);
        save_group_members(db, acme, &team, &[ann]).await;
        DirectBatch {
            other,
            ann,
            agent,
            absent,
        }
    }

    /// Gives a user a direct role and puts both user and agent beneath a role-carrying parent group.
    async fn inherited_roles(
        db: &TestDb,
        store: &PgRoleStore,
        acme: &ScopedTenant,
    ) -> [PrincipalRef; 2] {
        let (viewer, admin, unused) = (role("viewer"), role("admin"), role("unused"));
        for held in [&viewer, &admin, &unused] {
            store.save(acme, held).await.unwrap();
        }
        let groups = PgGroupStore::new(Arc::clone(&db.databases));
        let engineering = group("Engineering", vec![*admin.id()]);
        let backend = group_under("Backend", GroupPlace::Under(*engineering.id()));
        groups.save(acme, &engineering).await.unwrap();
        groups.save(acme, &backend).await.unwrap();
        let ann = PrincipalRef::User(UserId::new());
        let agent = PrincipalRef::Agent(AgentId::new());
        let memberships = PgGroupMembershipStore::new(Arc::clone(&db.databases));
        for member in [ann, agent] {
            memberships
                .save(acme, &membership(member, *backend.id()))
                .await
                .unwrap();
        }
        PgRoleAssignmentStore::new(Arc::clone(&db.databases))
            .save(acme, &assignment(ann, *viewer.id()))
            .await
            .unwrap();
        [ann, agent]
    }

    /// A saved role is found by its id, by its name and among several ids,
    /// with everything it grants.
    #[tokio::test]
    async fn a_saved_role_is_found_by_its_id_and_its_name() {
        let (_db, store, acme) = fixture().await;
        let admin = role("admin");

        store.save(&acme, &admin).await.unwrap();

        let by_id = store.find_by_id(&acme, admin.id()).await.unwrap().unwrap();
        let by_name = store
            .find_by_name(&acme, admin.name())
            .await
            .unwrap()
            .unwrap();
        let by_ids = store.find_by_ids(&acme, &[*admin.id()]).await.unwrap();
        for found in [&by_id, &by_name, &by_ids[0]] {
            assert_eq!(found.id(), admin.id());
            assert_eq!(found.system_permissions(), admin.system_permissions());
            assert_eq!(found.custom_permissions(), admin.custom_permissions());
            assert_eq!(found.created_at(), admin.created_at());
        }
    }

    /// Name batches return each requested role once, omit unknown and foreign
    /// names, and keep the tenant's version of a name shared by two tenants.
    #[tokio::test]
    async fn role_name_batches_keep_the_tenant_boundary() {
        let (_db, store, acme) = fixture().await;
        let globex = tenant();
        let admin = role("admin");
        let foreign = role("foreign");
        store.save(&acme, &admin).await.unwrap();
        store.save(&acme, &role("omitted")).await.unwrap();
        store.save(&globex, &role("admin")).await.unwrap();
        store.save(&globex, &foreign).await.unwrap();
        let missing = Label::new("name", "missing").unwrap();

        let found = store
            .find_by_names(
                &acme,
                &[
                    admin.name().clone(),
                    foreign.name().clone(),
                    missing,
                    admin.name().clone(),
                ],
            )
            .await
            .unwrap();

        assert_eq!(found.len(), 1);
        assert_eq!(found[0].id(), admin.id());
        assert_eq!(found[0].system_permissions(), admin.system_permissions());
        assert!(store.find_by_names(&acme, &[]).await.unwrap().is_empty());
    }

    /// Direct role batches keep each principal kind and tenant separate, retain
    /// expired direct assignments for administration, and omit group inheritance.
    #[tokio::test]
    async fn direct_role_batches_preserve_principal_and_tenant_boundaries() {
        let (db, store, acme) = fixture().await;
        let DirectBatch {
            other,
            ann,
            agent,
            absent,
        } = direct_batch(&db, &store, &acme).await;

        let found = store
            .find_by_principals(&acme, &[ann, agent, absent, ann])
            .await
            .unwrap();
        let elsewhere = store
            .find_by_principals(&other, &[ann, agent])
            .await
            .unwrap();

        assert_eq!(names(&found[&ann]), ["viewer"]);
        assert_eq!(names(&found[&agent]), ["expired"]);
        assert!(!found.contains_key(&absent));
        assert_eq!(names(&elsewhere[&ann]), ["foreign"]);
        assert!(!elsewhere.contains_key(&agent));
        assert!(
            store
                .find_by_principals(&acme, &[])
                .await
                .unwrap()
                .is_empty()
        );
    }

    /// An id or a name the tenant has no role under finds nothing.
    #[tokio::test]
    async fn an_unknown_role_is_not_found() {
        let (_db, store, acme) = fixture().await;

        let by_id = store.find_by_id(&acme, &RoleId::new()).await.unwrap();
        let by_name = store
            .find_by_name(&acme, &Label::new("name", "nobody").unwrap())
            .await
            .unwrap();

        assert!(by_id.is_none());
        assert!(by_name.is_none());
    }

    /// Globex cannot find Acme's role by ID or name, or include it in a role page.
    #[tokio::test]
    async fn another_tenants_roles_are_invisible() {
        let (_db, store, acme) = fixture().await;
        let admin = role("admin");
        store.save(&acme, &admin).await.unwrap();
        let globex = tenant();

        let by_id = store.find_by_id(&globex, admin.id()).await.unwrap();
        let by_name = store.find_by_name(&globex, admin.name()).await.unwrap();
        let listed = store
            .list_all(&globex, &by(RoleSortField::Name), &first(10))
            .await
            .unwrap();

        assert!(by_id.is_none());
        assert!(by_name.is_none());
        assert!(listed.items.is_empty());
    }

    /// Saving a second role with the same tenant and name returns a conflict;
    /// another tenant can save a role with that name.
    #[tokio::test]
    async fn a_name_another_role_has_is_refused() {
        let (_db, store, acme) = fixture().await;
        store.save(&acme, &role("admin")).await.unwrap();

        let second = store.save(&acme, &role("admin")).await;
        let elsewhere = store.save(&tenant(), &role("admin")).await;

        assert!(matches!(second, Err(DomainError::Conflict(_))));
        assert!(elsewhere.is_ok());
    }

    /// Saving again keeps the new values and the creation time.
    #[tokio::test]
    async fn saving_again_keeps_the_new_values() {
        let (_db, store, acme) = fixture().await;
        let admin = role("admin");
        store.save(&acme, &admin).await.unwrap();
        let renamed = Role::reconstitute(RoleRow {
            id: *admin.id(),
            name: Label::new("name", "owner").unwrap(),
            updated_at: at(5),
            ..role_row("admin")
        })
        .unwrap();

        store.save(&acme, &renamed).await.unwrap();

        let found = store.find_by_id(&acme, admin.id()).await.unwrap().unwrap();
        assert_eq!(found.name().as_str(), "owner");
        assert_eq!(found.updated_at(), at(5));
        assert_eq!(found.created_at(), admin.created_at());
    }

    /// The roles are paged by name: each page follows the last, and the
    /// last says nothing follows.
    #[tokio::test]
    async fn a_list_is_read_page_by_page_in_its_order() {
        let (_db, store, acme) = fixture().await;
        for name in ["carol", "alice", "bob"] {
            store.save(&acme, &role(name)).await.unwrap();
        }
        let order = by(RoleSortField::Name);

        let page_one = store.list_all(&acme, &order, &first(2)).await.unwrap();
        let after = PageRequest::new(page_one.next.clone(), Limit::new(2).unwrap());
        let page_two = store.list_all(&acme, &order, &after).await.unwrap();

        assert_eq!(names(&page_one.items), ["alice", "bob"]);
        assert_eq!(names(&page_two.items), ["carol"]);
        assert!(!page_two.has_next());
    }

    /// Only the roles new users get are the defaults.
    #[tokio::test]
    async fn the_defaults_are_the_roles_new_users_get() {
        let (_db, store, acme) = fixture().await;
        store.save(&acme, &role("admin")).await.unwrap();
        store.save(&acme, &default_role("member")).await.unwrap();

        let defaults = store.find_defaults(&acme).await.unwrap();

        assert_eq!(names(&defaults), ["member"]);
    }

    /// A deleted role is gone, and so are the assignments of it.
    #[tokio::test]
    async fn a_deleted_role_is_gone_with_its_assignments() {
        let (db, store, acme) = fixture().await;
        let admin = role("admin");
        store.save(&acme, &admin).await.unwrap();
        let ann = PrincipalRef::User(UserId::new());
        let assignments = PgRoleAssignmentStore::new(Arc::clone(&db.databases));
        assignments
            .save(&acme, &assignment(ann, *admin.id()))
            .await
            .unwrap();

        store.delete(&acme, admin.id()).await.unwrap();

        assert!(store.find_by_id(&acme, admin.id()).await.unwrap().is_none());
        assert!(!assignments.exists(&acme, &ann, admin.id()).await.unwrap());
    }

    /// Ann is given "viewer" straight and is in "Backend", under
    /// "Engineering", which carries "admin": she holds "viewer" directly,
    /// and both through the tree. An agent in the same group holds none
    /// of the group's roles.
    #[tokio::test]
    async fn a_user_holds_the_roles_of_her_groups_and_those_above_them() {
        let (db, store, acme) = fixture().await;
        let [ann, agent] = inherited_roles(&db, &store, &acme).await;

        let direct = store.find_by_principal(&acme, &ann).await.unwrap();
        let mut effective = names(
            &store
                .find_effective_by_principal(&acme, &ann)
                .await
                .unwrap(),
        )
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
        effective.sort();
        let of_agent = store
            .find_effective_by_principal(&acme, &agent)
            .await
            .unwrap();

        assert_eq!(names(&direct), ["viewer"]);
        assert_eq!(effective, ["admin", "viewer"]);
        assert!(of_agent.is_empty());
    }

    /// Ann's expired admin grant and expired membership of the Auditors group
    /// contribute no effective roles. Her viewer grant remains effective.
    #[tokio::test]
    async fn a_grant_or_membership_that_ended_confers_nothing() {
        let (db, store, acme) = fixture().await;
        let (viewer, admin, auditor) = (role("viewer"), role("admin"), role("auditor"));
        for held in [&viewer, &admin, &auditor] {
            store.save(&acme, held).await.unwrap();
        }
        let auditors = group("Auditors", vec![*auditor.id()]);
        PgGroupStore::new(Arc::clone(&db.databases))
            .save(&acme, &auditors)
            .await
            .unwrap();
        let ann = PrincipalRef::User(UserId::new());
        PgGroupMembershipStore::new(Arc::clone(&db.databases))
            .save(&acme, &ended_membership(ann, *auditors.id()))
            .await
            .unwrap();
        let assignments = PgRoleAssignmentStore::new(Arc::clone(&db.databases));
        assignments
            .save(&acme, &ended_assignment(ann, *admin.id()))
            .await
            .unwrap();
        assignments
            .save(&acme, &assignment(ann, *viewer.id()))
            .await
            .unwrap();

        let effective = store
            .find_effective_by_principal(&acme, &ann)
            .await
            .unwrap();

        assert_eq!(names(&effective), ["viewer"]);
    }

    /// A stored role with a duplicate permission is rejected as corrupt.
    #[tokio::test]
    async fn a_row_that_breaks_a_rule_of_the_role_is_refused() {
        let (db, store, acme) = fixture().await;
        let admin = role("admin");
        store.save(&acme, &admin).await.unwrap();
        db.tamper("UPDATE roles SET system_permissions = system_permissions || system_permissions")
            .await;

        let read = store.find_by_id(&acme, admin.id()).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
