//! The agents seen at work in a tenant that nobody registered, each table
//! row under row-level security, kept until someone registers or
//! dismisses each.
//!
//! One sighting is kept per source and fingerprint, by a unique key, so
//! two workers seeing the same caller at once keep one sighting between
//! them.

mod record;
mod words;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::agents::AgentSightingStore;
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::agents::identity::sighting::{
    AgentSighting, SightingFingerprint, SightingSource,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::AgentSightingId;

use self::record::{SightingColumns, SightingRecord};
use crate::postgres::foundation::errors::{Uniqueness, unique_on};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The constraint that keeps one sighting per source and fingerprint of a
/// tenant.
const FINGERPRINT_KEY: &str = "agent_sightings_fingerprint_key";

/// The Postgres store of agent sightings.
pub struct PgAgentSightingStore {
    databases: Arc<Databases>,
}

impl TenantScoped for PgAgentSightingStore {}

impl PgAgentSightingStore {
    /// A store keeping agent sightings in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

fn rebuilt(
    records: Vec<SightingRecord>,
) -> Result<Vec<AgentSighting<ResolvedTenant>>, DomainError> {
    records
        .into_iter()
        .map(SightingRecord::into_sighting)
        .collect()
}

#[async_trait]
impl AgentSightingStore for PgAgentSightingStore {
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        sighting: &AgentSighting<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let columns = SightingColumns::of(sighting);
        let written = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                let attempt = sqlx::query_file!(
                    "queries/agent_sightings/save.sql",
                    columns.id,
                    tenant_id.as_uuid(),
                    columns.source,
                    columns.fingerprint,
                    columns.calls_itself,
                    columns.seen_count,
                    columns.first_seen_at,
                    columns.last_seen_at,
                    columns.state,
                    columns.registered_agent_id,
                    columns.decided_at,
                    columns.updated_at,
                )
                .execute(connection)
                .await;
                unique_on(attempt, FINGERPRINT_KEY)
            },
        )
        .await?;
        ensure_unique_sighting(written)
    }

    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &AgentSightingId,
    ) -> Result<Option<AgentSighting<ResolvedTenant>>, DomainError> {
        let ids = [*id.as_uuid()];
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    SightingRecord,
                    "queries/agent_sightings/by_ids.sql",
                    tenant_id.as_uuid(),
                    &ids
                )
                .fetch_all(connection)
                .await
            },
        )
        .await?;
        Ok(rebuilt(records)?.pop())
    }

    async fn find_by_fingerprint(
        &self,
        tenant_id: &ScopedTenant,
        source: SightingSource,
        fingerprint: &SightingFingerprint,
    ) -> Result<Option<AgentSighting<ResolvedTenant>>, DomainError> {
        let record = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    SightingRecord,
                    "queries/agent_sightings/by_fingerprint.sql",
                    tenant_id.as_uuid(),
                    source.as_str(),
                    fingerprint.as_str()
                )
                .fetch_optional(connection)
                .await
            },
        )
        .await?;
        record.map(SightingRecord::into_sighting).transpose()
    }

    async fn list(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<Vec<AgentSighting<ResolvedTenant>>, DomainError> {
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    SightingRecord,
                    "queries/agent_sightings/of_tenant.sql",
                    tenant_id.as_uuid()
                )
                .fetch_all(connection)
                .await
            },
        )
        .await?;
        rebuilt(records)
    }
}

/// Reports a duplicate caller fingerprint as a conflict.
fn ensure_unique_sighting(written: Uniqueness) -> Result<(), DomainError> {
    match written {
        Uniqueness::Kept => Ok(()),
        Uniqueness::Taken => Err(DomainError::conflict(message!(
            "infra-the-caller-is-already-sighted",
            "the caller is already sighted"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::agents::identity::sighting::{AgentSightingRow, SightingState};
    use ianua_domain::types::{AgentId, TenantId};

    use super::*;
    use crate::test_support::TestDb;
    use crate::test_support::rows::agents::{saved_agent, sighting_row};
    use crate::test_support::rows::at;

    fn sighting(row: AgentSightingRow) -> AgentSighting<ResolvedTenant> {
        AgentSighting::reconstitute(row).unwrap()
    }

    /// The repeated client sighting after it was registered as an agent.
    fn registered_sighting(
        seen: &AgentSighting<ResolvedTenant>,
        agent: AgentId,
    ) -> AgentSighting<ResolvedTenant> {
        sighting(AgentSightingRow {
            id: *seen.id(),
            seen_count: 3,
            last_seen_at: at(20),
            state: SightingState::Registered {
                agent_id: agent,
                at: at(30),
            },
            updated_at: at(30),
            ..sighting_row("client-42")
        })
    }

    /// A fresh database, the store on it, and one tenant to keep sightings
    /// in.
    async fn fixture() -> (TestDb, PgAgentSightingStore, ScopedTenant) {
        let db = TestDb::fresh().await;
        let store = PgAgentSightingStore::new(Arc::clone(&db.databases));
        (db, store, ScopedTenant::for_background(TenantId::new()))
    }

    /// A sighting registered as an agent is found by its id and by its
    /// fingerprint as it was saved; another fingerprint finds nothing.
    #[tokio::test]
    async fn a_saved_sighting_is_found_by_id_and_by_fingerprint() {
        let (db, store, tenant) = fixture().await;
        let agent = saved_agent(&db.databases, &tenant, "reporter").await;
        let seen = sighting(sighting_row("client-42"));
        store.save(&tenant, &seen).await.unwrap();
        let registered = registered_sighting(&seen, agent);
        store.save(&tenant, &registered).await.unwrap();

        let by_id = store.find_by_id(&tenant, seen.id()).await.unwrap().unwrap();
        let by_fingerprint = store
            .find_by_fingerprint(&tenant, seen.source(), seen.fingerprint())
            .await
            .unwrap()
            .unwrap();
        let other = store
            .find_by_fingerprint(
                &tenant,
                seen.source(),
                &SightingFingerprint::new("client-43").unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(by_id.calls_itself(), seen.calls_itself());
        assert_eq!(by_id.seen_count(), 3);
        assert_eq!(by_id.state(), registered.state());
        assert_eq!(by_fingerprint.id(), seen.id());
        assert!(other.is_none());
    }

    /// Saving a second sighting with the same caller fingerprint returns a
    /// conflict.
    #[tokio::test]
    async fn a_second_sighting_of_one_caller_is_refused() {
        let (_db, store, tenant) = fixture().await;
        store
            .save(&tenant, &sighting(sighting_row("client-42")))
            .await
            .unwrap();

        let second = store
            .save(&tenant, &sighting(sighting_row("client-42")))
            .await;

        assert!(matches!(second, Err(DomainError::Conflict(_))));
    }

    /// The tenant's sightings are listed last seen first, and another
    /// tenant sees none of them.
    #[tokio::test]
    async fn sightings_are_listed_last_seen_first() {
        let (_db, store, tenant) = fixture().await;
        let stale = sighting(sighting_row("client-1"));
        let fresh = sighting(AgentSightingRow {
            last_seen_at: at(50),
            updated_at: at(50),
            ..sighting_row("client-2")
        });
        store.save(&tenant, &stale).await.unwrap();
        store.save(&tenant, &fresh).await.unwrap();
        let other = ScopedTenant::for_background(TenantId::new());

        let listed = store.list(&tenant).await.unwrap();
        let elsewhere = store.list(&other).await.unwrap();

        let ids: Vec<AgentSightingId> = listed.iter().map(|sighting| *sighting.id()).collect();
        assert_eq!(ids, [*fresh.id(), *stale.id()]);
        assert!(elsewhere.is_empty());
    }

    /// Saving a sighting registered to an unknown agent returns an
    /// infrastructure error.
    #[tokio::test]
    async fn a_sighting_registered_as_an_unknown_agent_is_refused() {
        let (_db, store, tenant) = fixture().await;
        let stray = sighting(AgentSightingRow {
            state: SightingState::Registered {
                agent_id: AgentId::new(),
                at: at(30),
            },
            updated_at: at(30),
            ..sighting_row("client-42")
        });

        let saved = store.save(&tenant, &stray).await;

        assert!(matches!(saved, Err(DomainError::Infrastructure(_))));
    }

    /// A sighting of a tenant with a database of its own is kept there, and
    /// not in the platform database.
    #[tokio::test]
    async fn a_sighting_of_a_tenant_with_its_own_database_is_kept_there() {
        let (db, store, _) = fixture().await;
        let own = TestDb::fresh().await;
        let apart = ScopedTenant::for_background(TenantId::new());
        db.databases.register(*apart, own.as_dedicated());
        let seen = sighting(sighting_row("client-42"));
        store.save(&apart, &seen).await.unwrap();

        let in_its_own = store.find_by_id(&apart, seen.id()).await.unwrap();
        db.databases.deregister(&apart);
        let in_the_platform = store.find_by_id(&apart, seen.id()).await.unwrap();

        assert!(in_its_own.is_some());
        assert!(in_the_platform.is_none());
    }

    /// A stored sighting with an empty fingerprint is rejected as corrupt.
    #[tokio::test]
    async fn a_row_that_breaks_a_rule_of_the_sighting_is_refused() {
        let (db, store, tenant) = fixture().await;
        let seen = sighting(sighting_row("client-42"));
        store.save(&tenant, &seen).await.unwrap();
        db.tamper("UPDATE agent_sightings SET fingerprint = ''")
            .await;

        let read = store.find_by_id(&tenant, seen.id()).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
