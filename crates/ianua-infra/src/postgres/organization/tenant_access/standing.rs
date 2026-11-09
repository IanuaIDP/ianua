//! Organization members who might hold rights in one tenant.
//!
//! Reads members and grants under the tenant's row-level security and
//! rebuilds both through the domain before answering.

mod record;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::organization::{MembersInTenant, TenantMemberRoster};
use ianua_domain::shared::config::DomainLimits;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{OrganizationId, TenantId};
use sqlx::PgConnection;
use uuid::Uuid;

use self::record::{HeldGrantRecord, members_in};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;
use crate::postgres::organization::members::OrgUserRecord;

/// The Postgres roster of who might hold rights in a tenant.
pub struct PgTenantMemberRoster {
    databases: Arc<Databases>,
    limits: DomainLimits,
}

impl PgTenantMemberRoster {
    /// A roster reading members and grants from `databases`, checking each
    /// stored name against `limits` as it is read back.
    #[must_use]
    pub fn new(databases: Arc<Databases>, limits: DomainLimits) -> Self {
        Self { databases, limits }
    }
}

/// The grants the members `org_user_ids` hold in `tenant_id`.
async fn grants_held(
    connection: &mut PgConnection,
    tenant_id: &TenantId,
    org_user_ids: &[Uuid],
) -> Result<Vec<HeldGrantRecord>, sqlx::Error> {
    sqlx::query_file_as!(
        HeldGrantRecord,
        "queries/org_tenant_grants/held_in_tenant.sql",
        tenant_id.as_uuid(),
        org_user_ids
    )
    .fetch_all(connection)
    .await
}

#[async_trait]
impl TenantMemberRoster for PgTenantMemberRoster {
    async fn members_in(
        &self,
        organization_id: &OrganizationId,
        tenant_id: &TenantId,
    ) -> Result<MembersInTenant, DomainError> {
        let (members, grants) = scoped(
            &self.databases,
            RowScope::Tenant(*tenant_id),
            async |connection| {
                let members = sqlx::query_file_as!(
                    OrgUserRecord,
                    "queries/org_users/reaching_tenant.sql",
                    organization_id.as_uuid(),
                    tenant_id.as_uuid()
                )
                .fetch_all(&mut *connection)
                .await?;
                let ids: Vec<Uuid> = members.iter().map(|member| member.id).collect();
                let grants = grants_held(connection, tenant_id, &ids).await?;
                Ok((members, grants))
            },
        )
        .await?;
        members_in(members, grants, *tenant_id, &self.limits)
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::ports::organization::{OrgTenantGrantStore, OrgUserStore, OrganizationStore};
    use ianua_app::ports::tenant::TenantStore;
    use ianua_domain::domains::organization::lifecycle::Organization;
    use ianua_domain::domains::organization::members::membership::OrgRole;
    use ianua_domain::domains::organization::members::org_user::{OrgUser, OrgUserRow};
    use ianua_domain::domains::organization::members::tenant_grant::{
        OrgTenantGrant, OrgTenantGrantRow,
    };
    use ianua_domain::domains::tenant::lifecycle::Tenant;
    use ianua_domain::types::{ActedBy, OrgUserId, RoleId};

    use super::*;
    use crate::postgres::organization::{
        PgOrgTenantGrantStore, PgOrgUserStore, PgOrganizationStore,
    };
    use crate::postgres::tenant::PgTenantStore;
    use crate::test_support::TestDb;
    use crate::test_support::rows::at;
    use crate::test_support::rows::organization::{org_user_row, organization_row};
    use crate::test_support::rows::tenant::tenant_row;

    struct Fixture {
        db: TestDb,
        acme: OrganizationId,
        sales: TenantId,
        design: TenantId,
    }

    /// A fresh database holding Acme with two tenants.
    async fn fixture() -> Fixture {
        let db = TestDb::fresh().await;
        let acme = an_organization(&db, "acme").await;
        let sales = a_tenant(&db, acme, "sales").await;
        let design = a_tenant(&db, acme, "design").await;
        Fixture {
            db,
            acme,
            sales,
            design,
        }
    }

    async fn an_organization(db: &TestDb, slug: &str) -> OrganizationId {
        let organization = Organization::reconstitute(organization_row(slug, slug)).unwrap();
        PgOrganizationStore::new(Arc::clone(&db.databases), DomainLimits::default())
            .save(&organization)
            .await
            .unwrap();
        *organization.id()
    }

    async fn a_tenant(db: &TestDb, organization: OrganizationId, slug: &str) -> TenantId {
        let tenant = Tenant::reconstitute(tenant_row(organization, slug)).unwrap();
        PgTenantStore::new(Arc::clone(&db.databases), DomainLimits::default())
            .save(&tenant)
            .await
            .unwrap();
        *tenant.id()
    }

    /// Saves an active member of `organization` at `email` in `role`.
    async fn a_member(
        fx: &Fixture,
        organization: OrganizationId,
        email: &str,
        role: OrgRole,
    ) -> OrgUser {
        let member = OrgUser::reconstitute(OrgUserRow {
            role,
            ..org_user_row(organization, email)
        })
        .unwrap();
        members(fx).save(&member).await.unwrap();
        member
    }

    fn members(fx: &Fixture) -> PgOrgUserStore {
        PgOrgUserStore::new(Arc::clone(&fx.db.databases), DomainLimits::default())
    }

    /// Grants `member` a fresh role in `tenant`, through the grant store.
    async fn grant(fx: &Fixture, member: &OrgUser, tenant: TenantId) -> RoleId {
        let role = RoleId::new();
        let grant = OrgTenantGrant::reconstitute(OrgTenantGrantRow {
            org_user_id: *member.id(),
            tenant_id: tenant,
            role_id: role,
            granted_by: ActedBy::Platform,
            granted_at: at(1),
        })
        .unwrap();
        PgOrgTenantGrantStore::new(Arc::clone(&fx.db.databases))
            .replace_in_tenant(member.id(), &tenant, &[grant])
            .await
            .unwrap();
        role
    }

    fn roster(fx: &Fixture) -> PgTenantMemberRoster {
        PgTenantMemberRoster::new(Arc::clone(&fx.db.databases), DomainLimits::default())
    }

    fn sorted(mut ids: Vec<OrgUserId>) -> Vec<OrgUserId> {
        ids.sort_by_key(|id| *id.as_uuid());
        ids
    }

    /// The roster of Acme's sales tenant holds its owners and admins, and
    /// the plain members granted there with those grants alone; not a
    /// member granted only elsewhere, nor a viewer, nor Globex's owner.
    #[tokio::test]
    async fn the_roster_holds_who_might_act_in_the_tenant() {
        let fx = fixture().await;
        let globex = an_organization(&fx.db, "globex").await;
        let ann = a_member(&fx, fx.acme, "ann@acme.example", OrgRole::Owner).await;
        let ada = a_member(&fx, fx.acme, "ada@acme.example", OrgRole::Admin).await;
        let sam = a_member(&fx, fx.acme, "sam@acme.example", OrgRole::Member).await;
        let dan = a_member(&fx, fx.acme, "dan@acme.example", OrgRole::Member).await;
        a_member(&fx, fx.acme, "vic@acme.example", OrgRole::Viewer).await;
        a_member(&fx, globex, "gus@globex.example", OrgRole::Owner).await;
        let in_sales = grant(&fx, &sam, fx.sales).await;
        grant(&fx, &dan, fx.design).await;

        let roster = roster(&fx).members_in(&fx.acme, &fx.sales).await.unwrap();

        let held = sorted(roster.members.iter().map(|member| *member.id()).collect());
        assert_eq!(held, sorted(vec![*ann.id(), *ada.id(), *sam.id()]));
        let grants: Vec<(OrgUserId, RoleId)> = roster
            .grants
            .iter()
            .map(|grant| (*grant.org_user_id(), *grant.role_id()))
            .collect();
        assert_eq!(grants, [(*sam.id(), in_sales)]);
    }

    /// Reading the tenant roster after a member's stored email is made
    /// invalid returns an infrastructure error.
    #[tokio::test]
    async fn a_corrupt_member_is_refused() {
        let fx = fixture().await;
        a_member(&fx, fx.acme, "ann@acme.example", OrgRole::Owner).await;
        fx.db
            .tamper("UPDATE org_users SET email = 'not an address'")
            .await;

        let listed = roster(&fx).members_in(&fx.acme, &fx.sales).await;

        assert!(matches!(listed, Err(DomainError::Infrastructure(_))));
    }
}
