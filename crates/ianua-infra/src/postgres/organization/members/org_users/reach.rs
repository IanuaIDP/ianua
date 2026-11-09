//! Organization members as a tenant reads them while they are signed out:
//! the store of `MemberStandings`, which the gateway's role answers too.
//!
//! It reads of a member only what their reach needs, never their address or
//! password hash, which the gateway's role may not read; their organization
//! and their grants in the tenant come through those stores, the grants
//! under the tenant's row-level security.

mod record;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::organization::{
    MemberStanding, MemberStandings, OrgTenantGrantStore as _, OrganizationStore as _,
};
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::organization::members::reach::MemberReach;
use ianua_domain::shared::config::DomainLimits;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::OrgUserId;

use self::record::ReachRecord;
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;
use crate::postgres::organization::organizations::PgOrganizationStore;
use crate::postgres::organization::tenant_access::PgOrgTenantGrantStore;

/// The Postgres store of members as a tenant reads them.
pub struct PgMemberStandings {
    databases: Arc<Databases>,
    organizations: PgOrganizationStore,
    grants: PgOrgTenantGrantStore,
}

impl PgMemberStandings {
    /// A store reading members, their organizations and grants from
    /// `databases`, checking stored names against `limits`.
    #[must_use]
    pub fn new(databases: Arc<Databases>, limits: DomainLimits) -> Self {
        Self {
            organizations: PgOrganizationStore::new(Arc::clone(&databases), limits),
            grants: PgOrgTenantGrantStore::new(Arc::clone(&databases)),
            databases,
        }
    }

    /// `member`'s reach, when they are there.
    async fn reach_of(&self, member: &OrgUserId) -> Result<Option<MemberReach>, DomainError> {
        let record = scoped(&self.databases, RowScope::Platform, async |connection| {
            sqlx::query_file_as!(ReachRecord, "queries/org_users/reach.sql", member.as_uuid())
                .fetch_optional(connection)
                .await
        })
        .await?;
        record.map(ReachRecord::into_reach).transpose()
    }
}

#[async_trait]
impl MemberStandings for PgMemberStandings {
    async fn member_in(
        &self,
        tenant: &ScopedTenant,
        member: &OrgUserId,
    ) -> Result<Option<MemberStanding>, DomainError> {
        let Some(reach) = self.reach_of(member).await? else {
            return Ok(None);
        };
        let Some(organization) = self
            .organizations
            .find_by_id(reach.organization_id())
            .await?
        else {
            return Ok(None);
        };
        let grants = self.grants.list_by_user_in_tenant(member, tenant).await?;
        Ok(Some(MemberStanding {
            member: reach,
            organization,
            grants,
        }))
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::ports::organization::OrgUserStore as _;
    use ianua_app::ports::tenant::TenantStore as _;
    use ianua_domain::domains::organization::members::org_user::OrgUser;
    use ianua_domain::domains::organization::members::tenant_grant::{
        OrgTenantGrant, OrgTenantGrantRow,
    };
    use ianua_domain::domains::tenant::lifecycle::Tenant;
    use ianua_domain::types::{ActedBy, RoleId};

    use super::*;
    use crate::postgres::organization::PgOrgUserStore;
    use crate::postgres::tenant::PgTenantStore;
    use crate::test_support::TestDb;
    use crate::test_support::rows::at;
    use crate::test_support::rows::domain::saved_tenant;
    use crate::test_support::rows::organization::org_user_row;
    use crate::test_support::rows::tenant::tenant_row;

    /// One member with a grant in each of two tenants, read as the gateway.
    struct Fixture {
        db: TestDb,
        store: PgMemberStandings,
        member: OrgUser,
        tenants: [ScopedTenant; 2],
        grants: [OrgTenantGrant; 2],
    }

    impl Fixture {
        /// Saves real organization, tenant, member and grant rows through their stores.
        async fn new() -> Self {
            let db = TestDb::fresh().await;
            let first = saved_tenant(&db.databases).await;
            let tenants = PgTenantStore::new(db.databases.clone(), DomainLimits::default());
            let tenant = tenants.find_by_id(&first).await.unwrap().unwrap();
            let second =
                Tenant::reconstitute(tenant_row(*tenant.organization_id(), "second")).unwrap();
            tenants.save(&second).await.unwrap();
            let member =
                OrgUser::reconstitute(org_user_row(*tenant.organization_id(), "ann@acme.example"))
                    .unwrap();
            PgOrgUserStore::new(db.databases.clone(), DomainLimits::default())
                .save(&member)
                .await
                .unwrap();
            let tenants = [first, ScopedTenant::for_background(*second.id())];
            let grants = save_grants(&db.databases, member.id(), &tenants).await;
            let store = PgMemberStandings::new(db.gateway.clone(), DomainLimits::default());
            Self {
                db,
                store,
                member,
                tenants,
                grants,
            }
        }
    }

    /// Gives the member one role in each tenant and returns the persisted grants.
    async fn save_grants(
        databases: &Arc<Databases>,
        member: &OrgUserId,
        tenants: &[ScopedTenant; 2],
    ) -> [OrgTenantGrant; 2] {
        let grants = tenants.each_ref().map(|tenant| {
            OrgTenantGrant::reconstitute(OrgTenantGrantRow {
                org_user_id: *member,
                tenant_id: **tenant,
                role_id: RoleId::new(),
                granted_by: ActedBy::Platform,
                granted_at: at(0),
            })
            .unwrap()
        });
        let writer = PgOrgTenantGrantStore::new(Arc::clone(databases));
        for (tenant, grant) in tenants.iter().zip(&grants) {
            writer
                .replace_in_tenant(member, tenant, std::slice::from_ref(grant))
                .await
                .unwrap();
        }
        grants
    }

    /// The gateway reads the member's reach, organization and only the
    /// requested tenant's grants; withdrawing one tenant's grant leaves the
    /// other tenant's grant in its standing.
    #[tokio::test]
    async fn the_gateway_reads_current_standing_with_only_this_tenants_grants() {
        let f = Fixture::new().await;
        for (tenant, grant) in f.tenants.iter().zip(&f.grants) {
            let standing = f
                .store
                .member_in(tenant, f.member.id())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(standing.member, f.member.reach());
            assert_eq!(standing.organization.id(), f.member.organization_id());
            assert_eq!(standing.grants, std::slice::from_ref(grant));
        }
        PgOrgTenantGrantStore::new(f.db.databases.clone())
            .replace_in_tenant(f.member.id(), &f.tenants[0], &[])
            .await
            .unwrap();
        let withdrawn = f
            .store
            .member_in(&f.tenants[0], f.member.id())
            .await
            .unwrap()
            .unwrap();
        let retained = f
            .store
            .member_in(&f.tenants[1], f.member.id())
            .await
            .unwrap()
            .unwrap();
        assert!(withdrawn.grants.is_empty());
        assert_eq!(retained.grants, [f.grants[1].clone()]);
    }

    /// Standing reads through the gateway's role return none for an unknown
    /// member and for the fixture member after deletion.
    #[tokio::test]
    async fn missing_and_deleted_members_have_no_standing() {
        let f = Fixture::new().await;
        assert!(
            f.store
                .member_in(&f.tenants[0], &OrgUserId::new())
                .await
                .unwrap()
                .is_none()
        );
        PgOrgUserStore::new(f.db.databases.clone(), DomainLimits::default())
            .delete(f.member.id())
            .await
            .unwrap();
        assert!(
            f.store
                .member_in(&f.tenants[0], f.member.id())
                .await
                .unwrap()
                .is_none()
        );
    }

    /// Reading a member standing through the gateway's role returns an
    /// infrastructure error when the stored role is unknown.
    #[tokio::test]
    async fn an_unknown_stored_role_is_refused_as_corrupt() {
        let f = Fixture::new().await;
        f.db.tamper("ALTER TABLE org_users DROP CONSTRAINT org_users_role_known")
            .await;
        f.db.tamper("UPDATE org_users SET role = 'unknown'").await;

        let read = f.store.member_in(&f.tenants[0], f.member.id()).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
