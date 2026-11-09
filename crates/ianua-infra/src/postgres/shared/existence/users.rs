//! Whether a user exists, read straight from one indexed query on the
//! tenant's users. The answer is a yes or a no, so nothing is mapped.
//!
//! Inside a tenant the read runs under that tenant's row-level security.
//! Across tenants, as the organization asks when it links an account in
//! another tenant, the read goes to the database the named tenant lives
//! in, under that tenant's scope, so it reaches a tenant with a database of
//! its own as well.

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::shared::{CrossTenantUserChecker, UserExistenceChecker};
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{TenantId, UserId};

use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// Whether `tenant` has the user `user`, read in `tenant`'s scope.
async fn exists(
    databases: &Databases,
    tenant: TenantId,
    user: &UserId,
) -> Result<bool, DomainError> {
    scoped(databases, RowScope::Tenant(tenant), async |connection| {
        sqlx::query_file_scalar!("queries/users/exists.sql", tenant.as_uuid(), user.as_uuid())
            .fetch_one(connection)
            .await
    })
    .await
}

/// The Postgres check that a user exists within a tenant.
pub struct PgUserExistenceChecker {
    databases: Arc<Databases>,
}

impl TenantScoped for PgUserExistenceChecker {}

impl PgUserExistenceChecker {
    /// A check reading the users in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

#[async_trait]
impl UserExistenceChecker for PgUserExistenceChecker {
    async fn user_exists(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<bool, DomainError> {
        exists(&self.databases, **tenant_id, user_id).await
    }
}

/// The Postgres check that a user exists in a tenant the caller names.
pub struct PgCrossTenantUserChecker {
    databases: Arc<Databases>,
}

impl PgCrossTenantUserChecker {
    /// A check reading the users in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

#[async_trait]
impl CrossTenantUserChecker for PgCrossTenantUserChecker {
    async fn exists_in_tenant(
        &self,
        tenant_id: &TenantId,
        user_id: &UserId,
    ) -> Result<bool, DomainError> {
        exists(&self.databases, *tenant_id, user_id).await
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::ports::identity::UserStore;
    use ianua_domain::domains::identity::account::user::User;
    use ianua_domain::isolation::scope::ResolvedTenant;
    use ianua_domain::shared::config::DomainLimits;

    use super::*;
    use crate::postgres::identity::PgUserStore;
    use crate::test_support::TestDb;
    use crate::test_support::rows::identity::user_row;

    /// Saves a user of `tenant` at `email` through their store.
    async fn a_user(db: &TestDb, tenant: &ScopedTenant, email: &str) -> UserId {
        let user: User<ResolvedTenant> = User::reconstitute(user_row(email)).unwrap();
        PgUserStore::new(Arc::clone(&db.databases), DomainLimits::default())
            .save(tenant, &user)
            .await
            .unwrap();
        *user.id()
    }

    /// A user of the tenant exists; an id nobody has does not.
    #[tokio::test]
    async fn a_user_of_the_tenant_exists() {
        let db = TestDb::fresh().await;
        let acme = ScopedTenant::for_background(TenantId::new());
        let ann = a_user(&db, &acme, "ann@acme.example").await;
        let checker = PgUserExistenceChecker::new(Arc::clone(&db.databases));

        assert!(checker.user_exists(&acme, &ann).await.unwrap());
        assert!(!checker.user_exists(&acme, &UserId::new()).await.unwrap());
    }

    /// Both existence checks report Ann absent from Globex while the
    /// cross-tenant check still finds her in Acme.
    #[tokio::test]
    async fn another_tenants_user_does_not_exist_here() {
        let db = TestDb::fresh().await;
        let acme = ScopedTenant::for_background(TenantId::new());
        let globex = ScopedTenant::for_background(TenantId::new());
        let ann = a_user(&db, &acme, "ann@acme.example").await;
        let within = PgUserExistenceChecker::new(Arc::clone(&db.databases));
        let across = PgCrossTenantUserChecker::new(Arc::clone(&db.databases));

        assert!(!within.user_exists(&globex, &ann).await.unwrap());
        assert!(!across.exists_in_tenant(&globex, &ann).await.unwrap());
        assert!(across.exists_in_tenant(&acme, &ann).await.unwrap());
    }

    /// A user of a tenant with a database of its own is found there by the
    /// check across tenants, and not in the platform database.
    #[tokio::test]
    async fn a_user_of_a_tenant_with_its_own_database_exists() {
        let db = TestDb::fresh().await;
        let own = TestDb::fresh().await;
        let apart = ScopedTenant::for_background(TenantId::new());
        db.databases.register(*apart, own.as_dedicated());
        let ann = a_user(&db, &apart, "ann@apart.example").await;
        let across = PgCrossTenantUserChecker::new(Arc::clone(&db.databases));

        let in_its_own = across.exists_in_tenant(&apart, &ann).await.unwrap();
        db.databases.deregister(&apart);
        let in_the_platform = across.exists_in_tenant(&apart, &ann).await.unwrap();

        assert!(in_its_own);
        assert!(!in_the_platform);
    }
}
