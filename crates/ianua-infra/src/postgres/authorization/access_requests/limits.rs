//! The one limit each tenant sets on how long its people may ask for
//! access, one row per tenant.

mod record;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::authorization::AccessRequestPolicyStore;
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::authorization::request_policy::AccessRequestPolicy;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;

use self::record::RequestPolicyRecord;
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The Postgres store of each tenant's limit on access requests.
pub struct PgAccessRequestPolicyStore {
    databases: Arc<Databases>,
}

impl PgAccessRequestPolicyStore {
    /// A store keeping the limits in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

impl TenantScoped for PgAccessRequestPolicyStore {}

#[async_trait]
impl AccessRequestPolicyStore for PgAccessRequestPolicyStore {
    async fn find(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<Option<AccessRequestPolicy<ResolvedTenant>>, DomainError> {
        let record = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    RequestPolicyRecord,
                    "queries/access_request_policies/of_tenant.sql",
                    tenant_id.as_uuid()
                )
                .fetch_optional(connection)
                .await
            },
        )
        .await?;
        record.map(RequestPolicyRecord::into_policy).transpose()
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        policy: &AccessRequestPolicy<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let longest = policy.limits().longest().whole_seconds();
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/access_request_policies/save.sql",
                    tenant_id.as_uuid(),
                    longest,
                    policy.updated_at()
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
    use ianua_domain::types::Lifetime;

    use super::*;
    use crate::test_support::TestDb;
    use crate::test_support::rows::at;
    use crate::test_support::rows::authorization::{request_policy, tenant};

    /// A fresh database, the store on it, and a tenant to set a limit for.
    async fn fixture() -> (TestDb, PgAccessRequestPolicyStore, ScopedTenant) {
        let db = TestDb::fresh().await;
        let store = PgAccessRequestPolicyStore::new(Arc::clone(&db.databases));
        (db, store, tenant())
    }

    fn hours(count: i64) -> Lifetime {
        Lifetime::seconds(count * 3600).unwrap()
    }

    /// A tenant that never set a limit has none.
    #[tokio::test]
    async fn a_tenant_without_a_limit_has_none() {
        let (_db, store, acme) = fixture().await;

        assert!(store.find(&acme).await.unwrap().is_none());
    }

    /// A limit reads back as set, and setting another replaces it.
    #[tokio::test]
    async fn a_limit_reads_back_and_is_replaced() {
        let (_db, store, acme) = fixture().await;
        store
            .save(&acme, &request_policy(hours(8), at(0)))
            .await
            .unwrap();
        let first = store.find(&acme).await.unwrap().unwrap();

        store
            .save(&acme, &request_policy(hours(2), at(5)))
            .await
            .unwrap();
        let second = store.find(&acme).await.unwrap().unwrap();

        assert_eq!(first.limits().longest(), hours(8));
        assert_eq!(second.limits().longest(), hours(2));
        assert_eq!(second.updated_at(), at(5));
    }

    /// Acme's saved access-request limit is absent from another tenant's lookup.
    #[tokio::test]
    async fn another_tenants_limit_is_invisible() {
        let (_db, store, acme) = fixture().await;
        store
            .save(&acme, &request_policy(hours(8), at(0)))
            .await
            .unwrap();

        assert!(store.find(&tenant()).await.unwrap().is_none());
    }

    /// A stored access-request duration beyond the domain's maximum is
    /// refused as corrupt storage.
    #[tokio::test]
    async fn a_limit_past_the_longest_is_refused() {
        let (db, store, acme) = fixture().await;
        store
            .save(&acme, &request_policy(hours(8), at(0)))
            .await
            .unwrap();
        db.tamper(
            "ALTER TABLE access_request_policies \
             DROP CONSTRAINT access_request_policies_longest_known; \
             UPDATE access_request_policies SET longest_seconds = 99999999",
        )
        .await;

        let read = store.find(&acme).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
