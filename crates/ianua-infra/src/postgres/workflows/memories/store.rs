//! A tenant's memories, never their texts. The sweep finds the tenants
//! with memories due in the platform's database and in each database of a
//! tenant's own.

mod record;

use std::sync::Arc;

use async_trait::async_trait;
use futures_util::future::try_join_all;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::workflows::{CrossTenantMemories, MemoryStore};
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::workflows::memory::Memory;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{MemoryId, TenantId};
use time::OffsetDateTime;
use uuid::Uuid;

use self::record::{MemoryColumns, MemoryRecord};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The Postgres store of memories.
pub struct PgMemoryStore {
    databases: Arc<Databases>,
}

impl TenantScoped for PgMemoryStore {}

impl PgMemoryStore {
    /// A store keeping memories in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

/// The memories `records` hold, rebuilt through the domain's checks.
fn rebuilt_all(records: Vec<MemoryRecord>) -> Result<Vec<Memory<ResolvedTenant>>, DomainError> {
    records.into_iter().map(MemoryRecord::into_memory).collect()
}

#[async_trait]
impl MemoryStore for PgMemoryStore {
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &MemoryId,
    ) -> Result<Option<Memory<ResolvedTenant>>, DomainError> {
        let ids = [*id.as_uuid()];
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    MemoryRecord,
                    "queries/memories/by_ids.sql",
                    tenant_id.as_uuid(),
                    &ids
                )
                .fetch_all(connection)
                .await
            },
        )
        .await?;
        Ok(rebuilt_all(records)?.into_iter().next())
    }

    async fn list(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<Vec<Memory<ResolvedTenant>>, DomainError> {
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    MemoryRecord,
                    "queries/memories/of_tenant.sql",
                    tenant_id.as_uuid()
                )
                .fetch_all(connection)
                .await
            },
        )
        .await?;
        rebuilt_all(records)
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        memory: &Memory<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let c = MemoryColumns::of(memory)?;
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/memories/save.sql",
                    c.id,
                    tenant_id.as_uuid(),
                    c.name,
                    c.embedding_source,
                    c.provider_id,
                    c.embedding_model,
                    c.vector_size,
                    c.clearance,
                    c.status,
                    c.deleted_after,
                    c.created_by,
                    c.created_at,
                    c.updated_at,
                )
                .execute(connection)
                .await
            },
        )
        .await?;
        Ok(())
    }

    async fn delete(&self, tenant_id: &ScopedTenant, id: &MemoryId) -> Result<(), DomainError> {
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/memories/delete.sql",
                    tenant_id.as_uuid(),
                    id.as_uuid()
                )
                .execute(connection)
                .await
            },
        )
        .await?;
        Ok(())
    }

    async fn due_for_purge(
        &self,
        tenant_id: &ScopedTenant,
        now: OffsetDateTime,
        limit: u32,
    ) -> Result<Vec<Memory<ResolvedTenant>>, DomainError> {
        let limit = i64::from(limit);
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    MemoryRecord,
                    "queries/memories/due_for_purge.sql",
                    tenant_id.as_uuid(),
                    now,
                    limit
                )
                .fetch_all(connection)
                .await
            },
        )
        .await?;
        rebuilt_all(records)
    }
}

/// The Postgres read, across every tenant, of which hold memories due to
/// be deleted: the platform's database and each database of a tenant's
/// own.
pub struct PgCrossTenantMemories {
    databases: Arc<Databases>,
}

impl PgCrossTenantMemories {
    /// A reader over `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }

    /// The tenants in the platform's database with a memory due at `now`.
    async fn shared_due(&self, now: OffsetDateTime) -> Result<Vec<Uuid>, DomainError> {
        scoped(&self.databases, RowScope::Platform, async |connection| {
            sqlx::query_file_scalar!("queries/memories/due.sql", now)
                .fetch_all(connection)
                .await
        })
        .await
    }

    /// Whether `tenant`, in its own database, holds a memory due at `now`.
    async fn own_due(&self, tenant: TenantId, now: OffsetDateTime) -> Result<bool, DomainError> {
        scoped(
            &self.databases,
            RowScope::Tenant(tenant),
            async |connection| {
                sqlx::query_file_scalar!(
                    "queries/memories/due_of_tenant.sql",
                    tenant.as_uuid(),
                    now
                )
                .fetch_one(connection)
                .await
            },
        )
        .await
    }
}

#[async_trait]
impl CrossTenantMemories for PgCrossTenantMemories {
    async fn tenants_with_memories_due(
        &self,
        now: OffsetDateTime,
    ) -> Result<Vec<TenantId>, DomainError> {
        let own = self.databases.with_own_database();
        let (shared, held) = futures_util::try_join!(
            self.shared_due(now),
            try_join_all(own.iter().map(|tenant| self.own_due(*tenant, now)))
        )?;
        let holding = own
            .into_iter()
            .zip(held)
            .filter_map(|(tenant, holds)| holds.then_some(tenant));
        Ok(shared
            .into_iter()
            .map(TenantId::from_uuid)
            .chain(holding)
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::workflows::memory::{DELETION_WAITING_DAYS, MemoryStatus};
    use time::Duration;

    use super::*;
    use crate::test_support::TestDb;
    use crate::test_support::rows::domain::saved_tenant;
    use crate::test_support::rows::workflows::memory_row;

    fn memory(status: MemoryStatus, made: OffsetDateTime) -> Memory<ResolvedTenant> {
        Memory::reconstitute(memory_row(status, made)).unwrap()
    }

    /// Ann's memory is saved and read back as it was, by its id and in
    /// her tenant's list; another tenant finds nothing under that id.
    #[tokio::test]
    async fn a_memory_reads_back_only_in_its_tenant() {
        let db = TestDb::fresh().await;
        let acme = saved_tenant(&db.databases).await;
        let globex = saved_tenant(&db.databases).await;
        let memories = PgMemoryStore::new(Arc::clone(&db.databases));
        let tickets = memory(MemoryStatus::Active, OffsetDateTime::now_utc());
        memories.save(&acme, &tickets).await.unwrap();

        let found = memories.find_by_id(&acme, tickets.id()).await.unwrap();
        let elsewhere = memories.find_by_id(&globex, tickets.id()).await.unwrap();

        let found = found.unwrap();
        assert_eq!(found.name(), tickets.name());
        assert_eq!(found.source(), tickets.source());
        assert_eq!(found.status(), MemoryStatus::Active);
        assert!(elsewhere.is_none());
        assert_eq!(memories.list(&acme).await.unwrap().len(), 1);
        assert!(memories.list(&globex).await.unwrap().is_empty());
    }

    /// A memory set to be deleted long enough ago is found by the sweep in
    /// its tenant, and deleted; an active one is never found.
    #[tokio::test]
    async fn the_sweep_finds_only_memories_past_their_waiting_period() {
        let db = TestDb::fresh().await;
        let acme = saved_tenant(&db.databases).await;
        let memories = PgMemoryStore::new(Arc::clone(&db.databases));
        let now = OffsetDateTime::now_utc();
        let changed = now - Duration::days(DELETION_WAITING_DAYS + 1);
        let due = memory(
            MemoryStatus::DeletionRequested {
                deleted_after: changed + Duration::days(DELETION_WAITING_DAYS),
            },
            changed,
        );
        let active = memory(MemoryStatus::Active, now);
        memories.save(&acme, &due).await.unwrap();
        memories.save(&acme, &active).await.unwrap();

        let tenants = PgCrossTenantMemories::new(Arc::clone(&db.databases))
            .tenants_with_memories_due(now)
            .await
            .unwrap();
        let found = memories.due_for_purge(&acme, now, 10).await.unwrap();
        memories.delete(&acme, due.id()).await.unwrap();

        assert!(tenants.contains(&*acme));
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].id(), due.id());
        assert_eq!(memories.list(&acme).await.unwrap().len(), 1);
    }
}
