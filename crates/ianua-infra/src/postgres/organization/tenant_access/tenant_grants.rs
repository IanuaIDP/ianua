//! The roles organization members hold in the organization's tenants.
//!
//! A grant row belongs to its tenant, under row-level security: a read
//! inside one tenant sees only that tenant's grants, and a read across a
//! member's tenants is platform work, scoped as such.

mod record;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::organization::OrgTenantGrantStore;
use ianua_domain::domains::organization::members::tenant_grant::OrgTenantGrant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{OrgUserId, TenantId};
use uuid::Uuid;

use self::record::{GrantColumns, GrantRecord};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The Postgres store of organization members' tenant grants.
pub struct PgOrgTenantGrantStore {
    databases: Arc<Databases>,
}

impl PgOrgTenantGrantStore {
    /// A store keeping grants in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

fn rebuilt(records: Vec<GrantRecord>) -> Result<Vec<OrgTenantGrant>, DomainError> {
    records.into_iter().map(GrantRecord::into_grant).collect()
}

#[async_trait]
impl OrgTenantGrantStore for PgOrgTenantGrantStore {
    async fn list_by_user(
        &self,
        org_user_id: &OrgUserId,
    ) -> Result<Vec<OrgTenantGrant>, DomainError> {
        let records = scoped(&self.databases, RowScope::Platform, async |connection| {
            sqlx::query_file_as!(
                GrantRecord,
                "queries/org_tenant_grants/of_member.sql",
                org_user_id.as_uuid()
            )
            .fetch_all(connection)
            .await
        })
        .await?;
        rebuilt(records)
    }

    async fn list_by_user_in_tenant(
        &self,
        org_user_id: &OrgUserId,
        tenant_id: &TenantId,
    ) -> Result<Vec<OrgTenantGrant>, DomainError> {
        let records = scoped(
            &self.databases,
            RowScope::Tenant(*tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    GrantRecord,
                    "queries/org_tenant_grants/of_member_in_tenant.sql",
                    org_user_id.as_uuid(),
                    tenant_id.as_uuid()
                )
                .fetch_all(connection)
                .await
            },
        )
        .await?;
        rebuilt(records)
    }

    async fn list_tenant_ids(&self, org_user_id: &OrgUserId) -> Result<Vec<TenantId>, DomainError> {
        let ids = scoped(&self.databases, RowScope::Platform, async |connection| {
            sqlx::query_file_scalar!(
                "queries/org_tenant_grants/tenants_of_member.sql",
                org_user_id.as_uuid()
            )
            .fetch_all(connection)
            .await
        })
        .await?;
        Ok(ids.into_iter().map(TenantId::from_uuid).collect())
    }

    async fn replace_in_tenant(
        &self,
        org_user_id: &OrgUserId,
        tenant_id: &TenantId,
        grants: &[OrgTenantGrant],
    ) -> Result<(), DomainError> {
        let columns = GrantColumns::of(org_user_id, tenant_id, grants)?;
        scoped(
            &self.databases,
            RowScope::Tenant(*tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/org_tenant_grants/withdraw_in_tenant.sql",
                    org_user_id.as_uuid(),
                    tenant_id.as_uuid()
                )
                .execute(&mut *connection)
                .await?;
                sqlx::query_file!(
                    "queries/org_tenant_grants/grant_in_tenant.sql",
                    org_user_id.as_uuid(),
                    tenant_id.as_uuid(),
                    &columns.role_ids,
                    &columns.granted_by as &[Option<Uuid>],
                    &columns.granted_at
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
    use ianua_app::ports::organization::{OrgUserStore, OrganizationStore};
    use ianua_app::ports::tenant::TenantStore;
    use ianua_domain::domains::organization::lifecycle::Organization;
    use ianua_domain::domains::organization::members::org_user::OrgUser;
    use ianua_domain::domains::organization::members::tenant_grant::OrgTenantGrantRow;
    use ianua_domain::domains::tenant::lifecycle::Tenant;
    use ianua_domain::shared::config::DomainLimits;
    use ianua_domain::types::{ActedBy, RoleId};

    use super::*;
    use crate::postgres::organization::{PgOrgUserStore, PgOrganizationStore};
    use crate::postgres::tenant::PgTenantStore;
    use crate::test_support::TestDb;
    use crate::test_support::rows::at;
    use crate::test_support::rows::organization::{org_user_row, organization_row};
    use crate::test_support::rows::tenant::tenant_row;

    /// A fresh database holding Acme with two tenants and Ann, one of its
    /// members, and the store on it.
    async fn fixture() -> (TestDb, PgOrgTenantGrantStore, TenantId, TenantId, OrgUserId) {
        let db = TestDb::fresh().await;
        let acme = Organization::reconstitute(organization_row("acme", "Acme")).unwrap();
        PgOrganizationStore::new(Arc::clone(&db.databases), DomainLimits::default())
            .save(&acme)
            .await
            .unwrap();
        let tenants = PgTenantStore::new(Arc::clone(&db.databases), DomainLimits::default());
        let mut ids = Vec::new();
        for slug in ["sales", "design"] {
            let tenant = Tenant::reconstitute(tenant_row(*acme.id(), slug)).unwrap();
            tenants.save(&tenant).await.unwrap();
            ids.push(*tenant.id());
        }
        let ann = OrgUser::reconstitute(org_user_row(*acme.id(), "ann@acme.example")).unwrap();
        PgOrgUserStore::new(Arc::clone(&db.databases), DomainLimits::default())
            .save(&ann)
            .await
            .unwrap();
        let store = PgOrgTenantGrantStore::new(Arc::clone(&db.databases));
        let (sales, design) = (ids.remove(0), ids.remove(0));
        (db, store, sales, design, *ann.id())
    }

    fn grant(member: OrgUserId, tenant: TenantId) -> OrgTenantGrant {
        OrgTenantGrant::reconstitute(OrgTenantGrantRow {
            org_user_id: member,
            tenant_id: tenant,
            role_id: RoleId::new(),
            granted_by: ActedBy::Platform,
            granted_at: at(0),
        })
        .unwrap()
    }

    /// Replacing a member's grants in a tenant leaves exactly the new ones.
    #[tokio::test]
    async fn replacing_a_members_grants_keeps_only_the_new_ones() {
        let (_db, store, sales, _, ann) = fixture().await;
        let first = [grant(ann, sales), grant(ann, sales)];
        let second = [grant(ann, sales)];

        store.replace_in_tenant(&ann, &sales, &first).await.unwrap();
        store
            .replace_in_tenant(&ann, &sales, &second)
            .await
            .unwrap();

        let held = store.list_by_user_in_tenant(&ann, &sales).await.unwrap();
        assert_eq!(held, second);
    }

    /// Replacing in one tenant leaves the member's grants in another, and
    /// every grant and tenant of theirs is listed across tenants.
    #[tokio::test]
    async fn a_members_grants_are_listed_across_tenants() {
        let (_db, store, sales, design, ann) = fixture().await;
        store
            .replace_in_tenant(&ann, &sales, &[grant(ann, sales), grant(ann, sales)])
            .await
            .unwrap();
        store
            .replace_in_tenant(&ann, &design, &[grant(ann, design)])
            .await
            .unwrap();

        store.replace_in_tenant(&ann, &sales, &[]).await.unwrap();

        let held = store.list_by_user(&ann).await.unwrap();
        let tenants = store.list_tenant_ids(&ann).await.unwrap();
        assert_eq!(held.len(), 1);
        assert_eq!(tenants, [design]);
    }

    /// Replacing Ann's sales grants with a grant naming design returns a
    /// validation error.
    #[tokio::test]
    async fn a_grant_for_another_tenant_is_refused() {
        let (_db, store, sales, design, ann) = fixture().await;

        let replaced = store
            .replace_in_tenant(&ann, &sales, &[grant(ann, design)])
            .await;

        assert!(matches!(replaced, Err(DomainError::Validation(_))));
    }
}
