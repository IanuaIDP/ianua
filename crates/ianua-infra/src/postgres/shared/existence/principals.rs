//! Whether a principal exists within a tenant, each kind read with one
//! indexed query on its own table. The answer is a yes or a no, so nothing
//! is mapped.
//!
//! A user, an agent and a consumer are the tenant's own rows, read under
//! its row-level security in the database it lives in. An organization
//! member belongs to the tenant's organization, read from the platform
//! database.

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::shared::PrincipalExistenceChecker;
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{OrgUserId, PrincipalRef, TenantId};
use uuid::Uuid;

use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The Postgres check that a principal exists within a tenant.
pub struct PgPrincipalExistenceChecker {
    databases: Arc<Databases>,
}

impl TenantScoped for PgPrincipalExistenceChecker {}

impl PgPrincipalExistenceChecker {
    /// A check reading the principals in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }

    /// Whether `tenant` holds the row `id` of the table the kind names.
    async fn tenant_row(
        &self,
        tenant: TenantId,
        kind: TenantRow,
        id: Uuid,
    ) -> Result<bool, DomainError> {
        scoped(
            &self.databases,
            RowScope::Tenant(tenant),
            async |connection| {
                let tenant = tenant.as_uuid();
                match kind {
                    TenantRow::User => {
                        sqlx::query_file_scalar!("queries/users/exists.sql", tenant, id)
                            .fetch_one(connection)
                            .await
                    }
                    TenantRow::Agent => {
                        sqlx::query_file_scalar!("queries/agents/exists.sql", tenant, id)
                            .fetch_one(connection)
                            .await
                    }
                    TenantRow::Consumer => {
                        sqlx::query_file_scalar!("queries/consumers/exists.sql", tenant, id)
                            .fetch_one(connection)
                            .await
                    }
                }
            },
        )
        .await
    }

    /// Whether `member` belongs to the organization that owns `tenant`.
    async fn member(&self, tenant: TenantId, member: &OrgUserId) -> Result<bool, DomainError> {
        scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file_scalar!(
                "queries/org_users/member_of_tenant.sql",
                tenant.as_uuid(),
                member.as_uuid()
            )
            .fetch_one(connection)
            .await
        })
        .await
    }
}

/// The kinds of principal a tenant keeps as rows of its own.
#[derive(Debug, Clone, Copy)]
enum TenantRow {
    User,
    Agent,
    Consumer,
}

#[async_trait]
impl PrincipalExistenceChecker for PgPrincipalExistenceChecker {
    async fn principal_exists(
        &self,
        tenant_id: &ScopedTenant,
        principal: &PrincipalRef,
    ) -> Result<bool, DomainError> {
        let tenant = **tenant_id;
        match principal {
            PrincipalRef::User(id) => {
                self.tenant_row(tenant, TenantRow::User, *id.as_uuid())
                    .await
            }
            PrincipalRef::Agent(id) => {
                self.tenant_row(tenant, TenantRow::Agent, *id.as_uuid())
                    .await
            }
            PrincipalRef::Consumer(id) => {
                self.tenant_row(tenant, TenantRow::Consumer, *id.as_uuid())
                    .await
            }
            PrincipalRef::OrgUser(id) => self.member(tenant, id).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::ports::organization::OrgUserStore;
    use ianua_domain::domains::organization::members::org_user::OrgUser;
    use ianua_domain::shared::config::DomainLimits;
    use ianua_domain::types::{AgentId, ConsumerId, OrganizationId, UserId};

    use super::*;
    use crate::postgres::organization::PgOrgUserStore;
    use crate::test_support::TestDb;
    use crate::test_support::rows::agents::saved_agent;
    use crate::test_support::rows::audit::{saved_organization, saved_tenant_of};
    use crate::test_support::rows::messaging::a_consumer;
    use crate::test_support::rows::oauth::a_person;
    use crate::test_support::rows::organization::org_user_row;

    /// A member of `organization`, saved through the member store.
    async fn saved_member_of(db: &TestDb, organization: OrganizationId) -> OrgUserId {
        let member = OrgUser::reconstitute(org_user_row(organization, "ann@acme.example")).unwrap();
        PgOrgUserStore::new(Arc::clone(&db.databases), DomainLimits::default())
            .save(&member)
            .await
            .unwrap();
        *member.id()
    }

    struct Fixture {
        db: TestDb,
        organization: OrganizationId,
        tenant: ScopedTenant,
        check: PgPrincipalExistenceChecker,
    }

    /// A fresh database holding Acme and one of its tenants, and the check
    /// on it.
    async fn fixture() -> Fixture {
        let db = TestDb::fresh().await;
        let organization = saved_organization(&db.databases).await;
        let tenant = saved_tenant_of(&db.databases, organization).await;
        Fixture {
            check: PgPrincipalExistenceChecker::new(Arc::clone(&db.databases)),
            organization,
            tenant,
            db,
        }
    }

    impl Fixture {
        async fn exists(&self, principal: PrincipalRef) -> bool {
            self.check
                .principal_exists(&self.tenant, &principal)
                .await
                .unwrap()
        }
    }

    /// A user, an agent and a consumer of the tenant, and a member of its
    /// organization, all exist; the same kinds with fresh ids do not.
    #[tokio::test]
    async fn each_kind_exists_only_when_kept() {
        let fx = fixture().await;
        let user = a_person(&fx.db, &fx.tenant, "ann@acme.example").await;
        let agent = saved_agent(&fx.db.databases, &fx.tenant, "ledger").await;
        let consumer = a_consumer(&fx.db, &fx.tenant, "billing").await;
        let member = saved_member_of(&fx.db, fx.organization).await;

        assert!(fx.exists(PrincipalRef::User(user)).await);
        assert!(fx.exists(PrincipalRef::Agent(agent)).await);
        assert!(fx.exists(PrincipalRef::Consumer(consumer)).await);
        assert!(fx.exists(PrincipalRef::OrgUser(member)).await);
        assert!(!fx.exists(PrincipalRef::User(UserId::new())).await);
        assert!(!fx.exists(PrincipalRef::Agent(AgentId::new())).await);
        assert!(!fx.exists(PrincipalRef::Consumer(ConsumerId::new())).await);
        assert!(!fx.exists(PrincipalRef::OrgUser(OrgUserId::new())).await);
    }

    /// Acme's agent does not exist in another tenant's scope, and another
    /// organization's member does not exist in Acme's scope.
    #[tokio::test]
    async fn a_principal_of_elsewhere_does_not_exist_here() {
        let fx = fixture().await;
        let agent = saved_agent(&fx.db.databases, &fx.tenant, "ledger").await;
        let elsewhere = saved_organization(&fx.db.databases).await;
        let outsider = saved_member_of(&fx.db, elsewhere).await;
        let other = ScopedTenant::for_background(TenantId::new());

        let theirs = fx
            .check
            .principal_exists(&other, &PrincipalRef::Agent(agent))
            .await
            .unwrap();

        assert!(!theirs);
        assert!(!fx.exists(PrincipalRef::OrgUser(outsider)).await);
    }
}
