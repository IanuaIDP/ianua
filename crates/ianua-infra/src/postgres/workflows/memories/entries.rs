//! The texts a tenant's memories keep, each with its vector in a pgvector
//! column, searched by cosine across one memory at a time.
//!
//! A vector travels as pgvector's text form, `[0.1,-0.2,…]`, so no type of
//! pgvector's is needed here. A search compares every vector of the one
//! memory exactly: fast enough for a memory of some hundred thousand texts,
//! the point where a deployment keeps its vectors in a vector server.

mod record;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::tenant::TenantMemoryPurger;
use ianua_app::ports::workflows::MemoryEntries;
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::workflows::memory::entry::{
    Embedding, EntryPage, FoundCount, FoundEntry, MemoryEntry, PageStart,
};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{MemoryId, TenantId};

use self::record::{FoundRecord, KeptRecord, paged, vector_text};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The Postgres store of memories' texts and vectors.
pub struct PgMemoryEntries {
    databases: Arc<Databases>,
}

impl TenantScoped for PgMemoryEntries {}

impl PgMemoryEntries {
    /// A store keeping memories' texts in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

#[async_trait]
impl MemoryEntries for PgMemoryEntries {
    async fn keep(
        &self,
        tenant_id: &ScopedTenant,
        memory: &MemoryId,
        entry: &MemoryEntry,
    ) -> Result<(), DomainError> {
        let vector = vector_text(entry.embedding());
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/memory_entries/keep.sql",
                    entry.id().as_uuid(),
                    tenant_id.as_uuid(),
                    memory.as_uuid(),
                    entry.text().as_str(),
                    vector,
                    entry.exposure().as_str(),
                    entry.created_at(),
                )
                .execute(connection)
                .await
            },
        )
        .await?;
        Ok(())
    }

    async fn find_similar(
        &self,
        tenant_id: &ScopedTenant,
        memory: &MemoryId,
        near: &Embedding,
        count: FoundCount,
    ) -> Result<Vec<FoundEntry>, DomainError> {
        let vector = vector_text(near);
        let limit = i64::from(count.get());
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    FoundRecord,
                    "queries/memory_entries/nearest.sql",
                    tenant_id.as_uuid(),
                    memory.as_uuid(),
                    vector,
                    limit
                )
                .fetch_all(connection)
                .await
            },
        )
        .await?;
        records.into_iter().map(FoundRecord::into_found).collect()
    }

    async fn page(
        &self,
        tenant_id: &ScopedTenant,
        memory: &MemoryId,
        start: PageStart,
        limit: u8,
    ) -> Result<EntryPage, DomainError> {
        let from = match start {
            PageStart::First => None,
            PageStart::At(entry) => Some(*entry.as_uuid()),
        };
        let fetched = i64::from(limit).saturating_add(1);
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    KeptRecord,
                    "queries/memory_entries/page.sql",
                    tenant_id.as_uuid(),
                    memory.as_uuid(),
                    from,
                    fetched
                )
                .fetch_all(connection)
                .await
            },
        )
        .await?;
        paged(records, limit)
    }

    async fn count(&self, tenant_id: &ScopedTenant) -> Result<u64, DomainError> {
        let kept = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_scalar!(
                    "queries/memory_entries/count_of_tenant.sql",
                    tenant_id.as_uuid()
                )
                .fetch_one(connection)
                .await
            },
        )
        .await?;
        Ok(u64::try_from(kept).unwrap_or(0))
    }

    async fn forget_all(
        &self,
        tenant_id: &ScopedTenant,
        memory: &MemoryId,
    ) -> Result<(), DomainError> {
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/memory_entries/forget_all.sql",
                    tenant_id.as_uuid(),
                    memory.as_uuid()
                )
                .execute(connection)
                .await
            },
        )
        .await?;
        Ok(())
    }
}

/// The Postgres removal of a deleted tenant's memory texts and vectors.
pub struct PgTenantMemoryPurger {
    databases: Arc<Databases>,
}

impl PgTenantMemoryPurger {
    /// A purger removing texts from `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

#[async_trait]
impl TenantMemoryPurger for PgTenantMemoryPurger {
    async fn purge(&self, tenant_id: &TenantId) -> Result<(), DomainError> {
        scoped(
            &self.databases,
            RowScope::Tenant(*tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/memory_entries/forget_tenant.sql",
                    tenant_id.as_uuid()
                )
                .execute(connection)
                .await
            },
        )
        .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::ports::workflows::MemoryStore as _;
    use ianua_domain::domains::data_classification::level::DataClassLevel;
    use ianua_domain::domains::workflows::memory::entry::{
        MemoryEntryParams, MemoryText, NextPage,
    };
    use ianua_domain::domains::workflows::memory::source::VectorSize;
    use ianua_domain::domains::workflows::memory::{Memory, MemoryStatus};
    use ianua_domain::isolation::scope::ResolvedTenant;
    use time::OffsetDateTime;

    use super::*;
    use crate::postgres::workflows::PgMemoryStore;
    use crate::test_support::TestDb;
    use crate::test_support::rows::domain::saved_tenant;
    use crate::test_support::rows::workflows::memory_row;

    fn three() -> VectorSize {
        VectorSize::new(3).unwrap()
    }

    fn active_memory() -> Memory<ResolvedTenant> {
        Memory::reconstitute(memory_row(MemoryStatus::Active, OffsetDateTime::now_utc())).unwrap()
    }

    fn entry(text: &str, vector: [f32; 3]) -> MemoryEntry {
        MemoryEntry::new(MemoryEntryParams {
            text: MemoryText::new(text).unwrap(),
            embedding: Embedding::new(vector.to_vec(), three()).unwrap(),
            exposure: DataClassLevel::Internal,
        })
    }

    /// Keeps an active memory under the supplied tenant before any entry is inserted.
    async fn saved_memory(
        databases: &Arc<Databases>,
        tenant: &ScopedTenant,
    ) -> Memory<ResolvedTenant> {
        let memory = active_memory();
        PgMemoryStore::new(Arc::clone(databases))
            .save(tenant, &memory)
            .await
            .unwrap();
        memory
    }

    /// Reads the page's text values in the order returned by the store.
    fn page_texts(page: &EntryPage) -> Vec<&str> {
        page.entries
            .iter()
            .map(|entry| entry.text.as_str())
            .collect()
    }

    /// Ann's memory keeps three tickets. A search near "refund" finds the
    /// money-back ticket first and the broken-mug refund after, closest first,
    /// and another tenant searching the same memory id finds nothing.
    #[tokio::test]
    async fn the_nearest_texts_come_back_first_and_only_to_their_tenant() {
        let db = TestDb::fresh().await;
        let acme = saved_tenant(&db.databases).await;
        let globex = saved_tenant(&db.databases).await;
        let entries = PgMemoryEntries::new(Arc::clone(&db.databases));
        let tickets = saved_memory(&db.databases, &acme).await;
        for (text, vector) in [
            ("I want my money back", [1.0, 0.0, 0.0]),
            ("Where is my parcel", [0.0, 1.0, 0.0]),
            ("Refund for a broken mug", [0.9, 0.1, 0.0]),
        ] {
            entries
                .keep(&acme, tickets.id(), &entry(text, vector))
                .await
                .unwrap();
        }
        let near = Embedding::new(vec![1.0, 0.05, 0.0], three()).unwrap();

        let found = entries
            .find_similar(&acme, tickets.id(), &near, FoundCount::new(2).unwrap())
            .await
            .unwrap();
        let elsewhere = entries
            .find_similar(&globex, tickets.id(), &near, FoundCount::new(2).unwrap())
            .await
            .unwrap();

        let texts: Vec<_> = found.iter().map(|entry| entry.text.as_str()).collect();
        assert_eq!(texts, ["I want my money back", "Refund for a broken mug"]);
        assert!(found[0].similarity > found[1].similarity);
        assert!(elsewhere.is_empty());
        assert_eq!(entries.count(&acme).await.unwrap(), 3);
    }

    /// Ann's memory keeps three tickets: a page of two holds the oldest two
    /// and names the third, whose page holds it alone and ends. Another
    /// tenant reading the same memory id reads nothing.
    #[tokio::test]
    async fn texts_are_read_page_by_page_in_the_order_kept() {
        let db = TestDb::fresh().await;
        let acme = saved_tenant(&db.databases).await;
        let globex = saved_tenant(&db.databases).await;
        let entries = PgMemoryEntries::new(Arc::clone(&db.databases));
        let tickets = saved_memory(&db.databases, &acme).await;
        for text in ["first", "second", "third"] {
            entries
                .keep(&acme, tickets.id(), &entry(text, [1.0, 0.0, 0.0]))
                .await
                .unwrap();
        }

        let first = entries
            .page(&acme, tickets.id(), PageStart::First, 2)
            .await
            .unwrap();
        let NextPage::At(next) = first.next else {
            panic!("a second page follows");
        };
        let second = entries
            .page(&acme, tickets.id(), PageStart::At(next), 2)
            .await
            .unwrap();
        let elsewhere = entries
            .page(&globex, tickets.id(), PageStart::First, 2)
            .await
            .unwrap();

        assert_eq!(page_texts(&first), ["first", "second"]);
        assert_eq!(page_texts(&second), ["third"]);
        assert_eq!(second.next, NextPage::Done);
        assert!(elsewhere.entries.is_empty());
    }

    /// Deleting a memory's texts empties it; deleting a whole tenant's
    /// empties every one of its memories, and doing either again does
    /// nothing.
    #[tokio::test]
    async fn texts_are_forgotten_by_memory_and_by_tenant() {
        let db = TestDb::fresh().await;
        let acme = saved_tenant(&db.databases).await;
        let memories = PgMemoryStore::new(Arc::clone(&db.databases));
        let entries = PgMemoryEntries::new(Arc::clone(&db.databases));
        let tickets = active_memory();
        let notes = active_memory();
        memories.save(&acme, &tickets).await.unwrap();
        memories.save(&acme, &notes).await.unwrap();
        entries
            .keep(&acme, tickets.id(), &entry("ticket", [1.0, 0.0, 0.0]))
            .await
            .unwrap();
        entries
            .keep(&acme, notes.id(), &entry("note", [0.0, 1.0, 0.0]))
            .await
            .unwrap();

        entries.forget_all(&acme, tickets.id()).await.unwrap();
        entries.forget_all(&acme, tickets.id()).await.unwrap();
        let after_one = entries.count(&acme).await.unwrap();
        let purger = PgTenantMemoryPurger::new(Arc::clone(&db.databases));
        purger.purge(&acme).await.unwrap();
        purger.purge(&acme).await.unwrap();

        assert_eq!(after_one, 1);
        assert_eq!(entries.count(&acme).await.unwrap(), 0);
    }
}
