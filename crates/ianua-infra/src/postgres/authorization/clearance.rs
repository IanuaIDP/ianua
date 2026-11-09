//! Clearance rules: which of a tenant's app permissions clear their
//! holders for confidential or restricted data, one row per tenant.

mod record;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::authorization::ClearanceRuleStore;
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::authorization::clearance::ClearanceRules;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;

use self::record::{ClearanceColumns, ClearanceRecord};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The Postgres store of clearance rules.
pub struct PgClearanceRuleStore {
    databases: Arc<Databases>,
}

impl PgClearanceRuleStore {
    /// A store keeping clearance rules in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

impl TenantScoped for PgClearanceRuleStore {}

#[async_trait]
impl ClearanceRuleStore for PgClearanceRuleStore {
    async fn load(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<Option<ClearanceRules<ResolvedTenant>>, DomainError> {
        let record = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    ClearanceRecord,
                    "queries/clearance_rules/of_tenant.sql",
                    tenant_id.as_uuid()
                )
                .fetch_optional(connection)
                .await
            },
        )
        .await?;
        record.map(ClearanceRecord::into_rules).transpose()
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        rules: &ClearanceRules<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let columns = ClearanceColumns::of(rules);
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/clearance_rules/save.sql",
                    tenant_id.as_uuid(),
                    &columns.permissions,
                    &columns.levels,
                    columns.updated_at
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
    use ianua_domain::domains::data_classification::level::DataClassLevel;

    use super::*;
    use crate::test_support::TestDb;
    use crate::test_support::rows::at;
    use crate::test_support::rows::authorization::{clearance, tenant};

    /// A fresh database, the store on it, and a tenant to keep rules for.
    async fn fixture() -> (TestDb, PgClearanceRuleStore, ScopedTenant) {
        let db = TestDb::fresh().await;
        let store = PgClearanceRuleStore::new(Arc::clone(&db.databases));
        (db, store, tenant())
    }

    /// A tenant that never wrote rules has none, so nothing clears.
    #[tokio::test]
    async fn a_tenant_without_rules_has_none() {
        let (_db, store, acme) = fixture().await;

        assert!(store.load(&acme).await.unwrap().is_none());
    }

    /// Saved rules read back in order, and saving again replaces them.
    #[tokio::test]
    async fn saved_rules_read_back_and_are_replaced() {
        let (_db, store, acme) = fixture().await;
        let first = clearance(
            &[
                ("billing:read", DataClassLevel::Confidential),
                ("health:read", DataClassLevel::Restricted),
            ],
            at(0),
        );
        store.save(&acme, &first).await.unwrap();
        let second = clearance(&[("billing:read", DataClassLevel::Restricted)], at(5));

        let read_first = store.load(&acme).await.unwrap().unwrap();
        store.save(&acme, &second).await.unwrap();
        let read_second = store.load(&acme).await.unwrap().unwrap();

        assert_eq!(read_first.rules(), first.rules());
        assert_eq!(read_second.rules(), second.rules());
        assert_eq!(read_second.updated_at(), at(5));
    }

    /// Clearance rules saved in Acme are absent from another tenant's lookup.
    #[tokio::test]
    async fn another_tenants_rules_are_invisible() {
        let (_db, store, acme) = fixture().await;
        store
            .save(
                &acme,
                &clearance(&[("billing:read", DataClassLevel::Confidential)], at(0)),
            )
            .await
            .unwrap();

        assert!(store.load(&tenant()).await.unwrap().is_none());
    }

    /// Duplicating a permission directly in stored clearance rules makes
    /// their read fail as corrupt storage.
    #[tokio::test]
    async fn rules_naming_a_permission_twice_are_refused() {
        let (db, store, acme) = fixture().await;
        store
            .save(
                &acme,
                &clearance(&[("billing:read", DataClassLevel::Confidential)], at(0)),
            )
            .await
            .unwrap();
        db.tamper(
            "UPDATE clearance_rules SET permissions = permissions || permissions, \
             levels = levels || levels",
        )
        .await;

        let read = store.load(&acme).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
