//! The places a tenant ships its request records to, kept as tenant rows
//! under row-level security. A credential is sealed by the platform's
//! secret sealer before the target is made, and the store keeps it sealed.

mod record;
mod words;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::proxy::LogShippingStore;
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::proxy::log_shipping::LogShippingTarget;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::LogShippingTargetId;

use self::record::{TargetColumns, TargetRecord};
use crate::postgres::foundation::errors::{Uniqueness, unique_on};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The constraint that keeps a name to one target of a tenant.
const NAME_KEY: &str = "log_shipping_targets_name_key";

/// The Postgres store of log shipping targets.
pub struct PgLogShippingStore {
    databases: Arc<Databases>,
}

impl PgLogShippingStore {
    /// A store keeping log shipping targets in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

impl TenantScoped for PgLogShippingStore {}

#[async_trait]
impl LogShippingStore for PgLogShippingStore {
    async fn find(
        &self,
        tenant_id: &ScopedTenant,
        target_id: &LogShippingTargetId,
    ) -> Result<Option<LogShippingTarget<ResolvedTenant>>, DomainError> {
        let record = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    TargetRecord,
                    "queries/log_shipping_targets/by_id.sql",
                    tenant_id.as_uuid(),
                    target_id.as_uuid()
                )
                .fetch_optional(connection)
                .await
            },
        )
        .await?;
        record.map(TargetRecord::into_target).transpose()
    }

    async fn list(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<Vec<LogShippingTarget<ResolvedTenant>>, DomainError> {
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    TargetRecord,
                    "queries/log_shipping_targets/of_tenant.sql",
                    tenant_id.as_uuid()
                )
                .fetch_all(connection)
                .await
            },
        )
        .await?;
        records.into_iter().map(TargetRecord::into_target).collect()
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        target: &LogShippingTarget<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let columns = TargetColumns::of(target)?;
        let written = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                let attempt = sqlx::query_file!(
                    "queries/log_shipping_targets/save.sql",
                    columns.id,
                    tenant_id.as_uuid(),
                    columns.name,
                    columns.destination,
                    columns.credential,
                    columns.records,
                    columns.sample_percent,
                    columns.format,
                    columns.status,
                    columns.created_at,
                    columns.updated_at,
                )
                .execute(connection)
                .await;
                unique_on(attempt, NAME_KEY)
            },
        )
        .await?;
        ensure_unique_name(written)
    }

    async fn delete(
        &self,
        tenant_id: &ScopedTenant,
        target_id: &LogShippingTargetId,
    ) -> Result<(), DomainError> {
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/log_shipping_targets/delete.sql",
                    tenant_id.as_uuid(),
                    target_id.as_uuid()
                )
                .execute(connection)
                .await?;
                Ok(())
            },
        )
        .await
    }
}

/// Reports a duplicate target name after the scoped write has completed.
fn ensure_unique_name(written: Uniqueness) -> Result<(), DomainError> {
    match written {
        Uniqueness::Kept => Ok(()),
        Uniqueness::Taken => Err(DomainError::conflict(message!(
            "infra-a-log-shipping-target-by-that",
            "a log shipping target by that name already exists"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::proxy::log_shipping::{
        LogShippingTargetRow, LogTargetStatus, SamplePercent, ShippedRecords,
    };
    use ianua_domain::types::TenantId;

    use super::*;
    use crate::test_support::TestDb;
    use crate::test_support::rows::at;
    use crate::test_support::rows::proxy::target_row;

    struct Fixture {
        db: TestDb,
        tenant: ScopedTenant,
        store: PgLogShippingStore,
    }

    /// A fresh database, a tenant, and the store on it.
    async fn fixture() -> Fixture {
        let db = TestDb::fresh().await;
        let store = PgLogShippingStore::new(Arc::clone(&db.databases));
        Fixture {
            db,
            tenant: ScopedTenant::for_background(TenantId::new()),
            store,
        }
    }

    fn target(row: LogShippingTargetRow) -> LogShippingTarget<ResolvedTenant> {
        LogShippingTarget::reconstitute(row).unwrap()
    }

    fn names(targets: &[LogShippingTarget<ResolvedTenant>]) -> Vec<&str> {
        targets.iter().map(|t| t.name().as_str()).collect()
    }

    /// A saved target is found with its destination and sealed key, and
    /// saving it again keeps the new choice of records and its pause.
    #[tokio::test]
    async fn a_saved_target_is_found_as_it_was_saved() {
        let db = fixture().await;
        let datadog = target(target_row("datadog", 0));
        db.store.save(&db.tenant, &datadog).await.unwrap();
        let mut changed = target_row("datadog", 0);
        changed.id = *datadog.id();
        changed.settings.records = ShippedRecords::Sampled(SamplePercent::new(25).unwrap());
        changed.status = LogTargetStatus::Paused;
        changed.updated_at = at(4);

        db.store.save(&db.tenant, &target(changed)).await.unwrap();

        let found = db
            .store
            .find(&db.tenant, datadog.id())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.destination(), datadog.destination());
        assert_eq!(
            found.records(),
            ShippedRecords::Sampled(SamplePercent::new(25).unwrap())
        );
        assert_eq!(found.status(), LogTargetStatus::Paused);
    }

    /// A tenant's targets are listed by name, a deleted one is gone, and
    /// another tenant sees none of them.
    #[tokio::test]
    async fn a_tenants_targets_are_listed_by_name() {
        let db = fixture().await;
        let other = ScopedTenant::for_background(TenantId::new());
        let siem = target(target_row("siem", 0));
        let bucket = target(target_row("bucket", 1));
        let gone = target(target_row("gone", 2));
        for saved in [&siem, &bucket, &gone] {
            db.store.save(&db.tenant, saved).await.unwrap();
        }

        db.store.delete(&db.tenant, gone.id()).await.unwrap();

        assert_eq!(
            names(&db.store.list(&db.tenant).await.unwrap()),
            ["bucket", "siem"]
        );
        assert!(db.store.list(&other).await.unwrap().is_empty());
    }

    /// Saving a second log shipping target named `siem` in the same tenant
    /// returns a conflict.
    #[tokio::test]
    async fn a_name_another_target_has_is_refused() {
        let db = fixture().await;
        db.store
            .save(&db.tenant, &target(target_row("siem", 0)))
            .await
            .unwrap();

        let saved = db
            .store
            .save(&db.tenant, &target(target_row("siem", 1)))
            .await;

        assert!(matches!(saved, Err(DomainError::Conflict(_))));
    }

    /// A stored Datadog target without its credential fails to load as
    /// corrupt storage.
    #[tokio::test]
    async fn a_target_missing_its_credential_is_refused() {
        let db = fixture().await;
        let datadog = target(target_row("datadog", 0));
        db.store.save(&db.tenant, &datadog).await.unwrap();
        db.db
            .tamper("UPDATE log_shipping_targets SET credential = NULL")
            .await;

        let read = db.store.find(&db.tenant, datadog.id()).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
