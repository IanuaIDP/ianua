//! A tenant's raised views of how risky an integration's operation is,
//! each table row under row-level security, at most one per operation.
//!
//! A unique constraint keeps one override per operation of a tenant, so
//! two people raising the same operation at once cannot both keep theirs.

mod record;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::workflows::OperationRiskOverrideStore;
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::workflows::integration::risk_override::OperationRiskOverride;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::OperationRiskOverrideId;

use self::record::{RiskColumns, RiskRecord};
use crate::postgres::foundation::errors::{Uniqueness, unique_on};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The constraint that keeps one override per operation of a tenant.
const OPERATION_KEY: &str = "operation_risk_overrides_operation_key";

/// The Postgres store of raised operation risks.
pub struct PgOperationRiskOverrideStore {
    databases: Arc<Databases>,
}

impl TenantScoped for PgOperationRiskOverrideStore {}

impl PgOperationRiskOverrideStore {
    /// A store keeping raised operation risks in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

#[async_trait]
impl OperationRiskOverrideStore for PgOperationRiskOverrideStore {
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &OperationRiskOverrideId,
    ) -> Result<Option<OperationRiskOverride<ResolvedTenant>>, DomainError> {
        let record = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    RiskRecord,
                    "queries/operation_risk_overrides/by_id.sql",
                    tenant_id.as_uuid(),
                    id.as_uuid()
                )
                .fetch_optional(connection)
                .await
            },
        )
        .await?;
        record.map(RiskRecord::into_override).transpose()
    }

    async fn list(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<Vec<OperationRiskOverride<ResolvedTenant>>, DomainError> {
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    RiskRecord,
                    "queries/operation_risk_overrides/of_tenant.sql",
                    tenant_id.as_uuid()
                )
                .fetch_all(connection)
                .await
            },
        )
        .await?;
        records.into_iter().map(RiskRecord::into_override).collect()
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        risk: &OperationRiskOverride<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let columns = RiskColumns::of(risk)?;
        let written = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                let attempt = sqlx::query_file!(
                    "queries/operation_risk_overrides/save.sql",
                    columns.id,
                    tenant_id.as_uuid(),
                    columns.integration,
                    columns.operation,
                    columns.effect,
                    columns.raised_by,
                    columns.created_at,
                    columns.updated_at,
                )
                .execute(connection)
                .await;
                unique_on(attempt, OPERATION_KEY)
            },
        )
        .await?;
        match written {
            Uniqueness::Kept => Ok(()),
            Uniqueness::Taken => Err(DomainError::conflict(message!(
                "infra-the-operation-s-risk-is-raised",
                "the operation's risk is raised already"
            ))),
        }
    }

    async fn delete(
        &self,
        tenant_id: &ScopedTenant,
        id: &OperationRiskOverrideId,
    ) -> Result<(), DomainError> {
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/operation_risk_overrides/delete.sql",
                    tenant_id.as_uuid(),
                    id.as_uuid()
                )
                .execute(connection)
                .await
                .map(|_| ())
            },
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::workflows::integration::risk_override::OperationRiskOverrideRow;
    use ianua_domain::types::{ActionClass, DeclaredAction, TenantId};

    use super::*;
    use crate::test_support::TestDb;
    use crate::test_support::rows::at;
    use crate::test_support::rows::workflows::risk_row;

    struct Fixture {
        db: TestDb,
        store: PgOperationRiskOverrideStore,
        tenant: ScopedTenant,
    }

    /// A fresh database, the store on it, and one tenant to keep overrides
    /// in.
    async fn fixture() -> Fixture {
        let db = TestDb::fresh().await;
        Fixture {
            store: PgOperationRiskOverrideStore::new(Arc::clone(&db.databases)),
            tenant: ScopedTenant::for_background(TenantId::new()),
            db,
        }
    }

    fn risk(row: OperationRiskOverrideRow) -> OperationRiskOverride<ResolvedTenant> {
        OperationRiskOverride::reconstitute(row).unwrap()
    }

    fn operations(risks: &[OperationRiskOverride<ResolvedTenant>]) -> Vec<&str> {
        risks.iter().map(|kept| kept.operation().as_str()).collect()
    }

    /// A saved override is found by its id with its class and who raised
    /// it, and every override is listed oldest first.
    #[tokio::test]
    async fn overrides_are_found_and_listed_oldest_first() {
        let fx = fixture().await;
        let later = risk(risk_row("send-invoice", 2));
        let earlier = risk(risk_row("append-row", 1));
        fx.store.save(&fx.tenant, &later).await.unwrap();
        fx.store.save(&fx.tenant, &earlier).await.unwrap();

        let found = fx
            .store
            .find_by_id(&fx.tenant, later.id())
            .await
            .unwrap()
            .unwrap();
        let listed = fx.store.list(&fx.tenant).await.unwrap();

        assert_eq!(
            found.effect(),
            DeclaredAction::Declared(ActionClass::Financial)
        );
        assert_eq!(found.raised_by(), later.raised_by());
        assert_eq!(operations(&listed), ["append-row", "send-invoice"]);
    }

    /// An override changed keeps its new class, and a removed one is gone.
    #[tokio::test]
    async fn an_override_is_changed_and_removed() {
        let fx = fixture().await;
        let saved = risk(risk_row("append-row", 0));
        fx.store.save(&fx.tenant, &saved).await.unwrap();
        let changed = risk(OperationRiskOverrideRow {
            id: *saved.id(),
            effect: DeclaredAction::Declared(ActionClass::Delete),
            updated_at: at(5),
            ..risk_row("append-row", 0)
        });

        fx.store.save(&fx.tenant, &changed).await.unwrap();
        let found = fx.store.find_by_id(&fx.tenant, saved.id()).await.unwrap();
        fx.store.delete(&fx.tenant, saved.id()).await.unwrap();

        assert_eq!(
            found.unwrap().effect(),
            DeclaredAction::Declared(ActionClass::Delete)
        );
        assert!(
            fx.store
                .find_by_id(&fx.tenant, saved.id())
                .await
                .unwrap()
                .is_none()
        );
    }

    /// Saving a second risk override for the same tenant and operation
    /// returns a conflict.
    #[tokio::test]
    async fn a_second_override_of_an_operation_is_refused() {
        let fx = fixture().await;
        fx.store
            .save(&fx.tenant, &risk(risk_row("append-row", 0)))
            .await
            .unwrap();

        let second = fx
            .store
            .save(&fx.tenant, &risk(risk_row("append-row", 1)))
            .await;

        assert!(matches!(second, Err(DomainError::Conflict(_))));
    }

    /// Another tenant sees none of Acme's overrides and may raise the same
    /// operation, and a tenant with a database of its own keeps its
    /// overrides there.
    #[tokio::test]
    async fn another_tenants_overrides_are_invisible() {
        let fx = fixture().await;
        fx.store
            .save(&fx.tenant, &risk(risk_row("append-row", 0)))
            .await
            .unwrap();
        let own = TestDb::fresh().await;
        let apart = ScopedTenant::for_background(TenantId::new());
        fx.db.databases.register(*apart, own.as_dedicated());

        let before = fx.store.list(&apart).await.unwrap();
        fx.store
            .save(&apart, &risk(risk_row("append-row", 0)))
            .await
            .unwrap();
        let in_own = PgOperationRiskOverrideStore::new(Arc::clone(&own.databases))
            .list(&apart)
            .await
            .unwrap();

        assert!(before.is_empty());
        assert_eq!(operations(&in_own), ["append-row"]);
    }

    /// Reading an override with an invalid stored operation key returns an
    /// infrastructure error.
    #[tokio::test]
    async fn a_row_that_breaks_a_rule_of_the_override_is_refused() {
        let fx = fixture().await;
        let saved = risk(risk_row("append-row", 0));
        fx.store.save(&fx.tenant, &saved).await.unwrap();
        fx.db
            .tamper("UPDATE operation_risk_overrides SET operation = 'Not A Key'")
            .await;

        let read = fx.store.find_by_id(&fx.tenant, saved.id()).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
