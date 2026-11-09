//! The account connections people began by signing in at a service, each
//! table row under row-level security, and the reads across every tenant
//! that the platform's one callback address and the sweep need.
//!
//! The browser's state is kept as its digest, unique in a database, so two
//! connections never answer one state. The service's answer names no
//! tenant, so the state is read in every database a tenant lives in;
//! should two databases answer one digest, which no state the platform made
//! can do, the read finds nothing to trust and fails. The PKCE verifier and
//! the credential the service issued arrive sealed and are kept as they
//! are. The sweep removes connections that ran out in the platform
//! database and in each tenant's own, a page at a time.

mod record;
mod words;

use std::sync::Arc;

use async_trait::async_trait;
use futures_util::future::try_join_all;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::workflows::{ConnectionAt, ConnectionStates, PendingConnectionStore};
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::workflows::account::connection::PendingConnection;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{PendingConnectionId, TokenHash};
use time::OffsetDateTime;

use self::record::{ConnectionColumns, ConnectionRecord, StateHit};
use crate::postgres::foundation::errors::{Uniqueness, unique_on};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::tenant_databases::everywhere::everywhere;
use crate::postgres::foundation::unit::scoped;

/// The constraint that keeps one connection per state.
const STATE_KEY: &str = "workflow_pending_connections_state_key";

/// Reports a state collision without changing the connection store's conflict contract.
fn ensure_state_available(written: Uniqueness) -> Result<(), DomainError> {
    match written {
        Uniqueness::Kept => Ok(()),
        Uniqueness::Taken => Err(DomainError::conflict(message!(
            "infra-another-connection-holds-the-state",
            "another connection holds the same state"
        ))),
    }
}

/// The Postgres store of pending connections.
pub struct PgPendingConnectionStore {
    databases: Arc<Databases>,
}

impl TenantScoped for PgPendingConnectionStore {}

impl PgPendingConnectionStore {
    /// A store keeping pending connections in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

/// The Postgres reads of pending connections across every tenant: the one
/// a service's answer names by its state, and the sweep of those that ran
/// out.
pub struct PgConnectionStates {
    databases: Arc<Databases>,
}

impl PgConnectionStates {
    /// Reads of the connections kept in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }

    /// Where the connections holding `state` under `scope` were begun.
    async fn holding(&self, scope: RowScope, state: &str) -> Result<Vec<StateHit>, DomainError> {
        scoped(&self.databases, scope, async |connection| {
            sqlx::query_file_as!(
                StateHit,
                "queries/workflow_pending_connections/by_state.sql",
                state
            )
            .fetch_all(connection)
            .await
        })
        .await
    }

    /// Removes up to `limit` connections that ran out before `now` under
    /// `scope`, and how many it removed.
    async fn removed(
        &self,
        scope: RowScope,
        now: OffsetDateTime,
        limit: i64,
    ) -> Result<u64, DomainError> {
        scoped(&self.databases, scope, async |connection| {
            sqlx::query_file!(
                "queries/workflow_pending_connections/remove_expired.sql",
                now,
                limit
            )
            .execute(connection)
            .await
            .map(|done| done.rows_affected())
        })
        .await
    }
}

#[async_trait]
impl PendingConnectionStore for PgPendingConnectionStore {
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &PendingConnectionId,
    ) -> Result<Option<PendingConnection<ResolvedTenant>>, DomainError> {
        let record = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    ConnectionRecord,
                    "queries/workflow_pending_connections/by_id.sql",
                    tenant_id.as_uuid(),
                    id.as_uuid()
                )
                .fetch_optional(connection)
                .await
            },
        )
        .await?;
        record.map(ConnectionRecord::into_connection).transpose()
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        connection: &PendingConnection<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let c = ConnectionColumns::of(connection)?;
        let written = scoped(&self.databases, RowScope::from(tenant_id), async |db| {
            let attempt = sqlx::query_file!(
                "queries/workflow_pending_connections/save.sql",
                c.id,
                tenant_id.as_uuid(),
                c.integration,
                c.name,
                c.sharing,
                c.operations.as_deref(),
                c.place,
                c.started_by,
                c.state_hash,
                c.verifier_sealed,
                c.stage,
                c.credential_sealed,
                c.code_hash,
                c.expires_at,
                c.created_at,
                c.updated_at,
            )
            .execute(db)
            .await;
            unique_on(attempt, STATE_KEY)
        })
        .await?;
        ensure_state_available(written)
    }
}

#[async_trait]
impl ConnectionStates for PgConnectionStates {
    async fn find(&self, state: &TokenHash) -> Result<Option<ConnectionAt>, DomainError> {
        let found = everywhere(
            &self.databases,
            |scope| self.holding(scope, state.as_str()),
            StateHit::tenant,
        )
        .await?;
        let Some(hit) = at_most_one(found)? else {
            return Ok(None);
        };
        Ok(Some(ConnectionAt {
            tenant_id: hit.tenant(),
            connection_id: PendingConnectionId::from_uuid(hit.id),
        }))
    }

    async fn remove_expired(&self, now: OffsetDateTime, limit: u32) -> Result<u64, DomainError> {
        let limit = i64::from(limit);
        let own = self.databases.with_own_database();
        let (shared, apart) = futures_util::try_join!(
            self.removed(RowScope::Platform, now, limit),
            try_join_all(own.into_iter().map(|tenant| self.removed(
                RowScope::Tenant(tenant),
                now,
                limit
            )))
        )?;
        Ok(apart.into_iter().fold(shared, u64::saturating_add))
    }
}

/// The one connection `found` holds, or none.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when two connections answer one
/// state's digest, which no state the platform made can do.
fn at_most_one(found: Vec<StateHit>) -> Result<Option<StateHit>, DomainError> {
    if found.len() > 1 {
        return Err(DomainError::infra_msg(
            "two connections answer one state's digest",
        ));
    }
    Ok(found.into_iter().next())
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::workflows::account::connection::{
        ConnectionStage, PendingConnectionRow,
    };
    use ianua_domain::shared::model::aggregate::Aggregate as _;
    use ianua_domain::types::{SealedSecret, TenantId};

    use super::*;
    use crate::test_support::TestDb;
    use crate::test_support::rows::at;
    use crate::test_support::rows::workflows::pending_connection_row;

    struct Fixture {
        _db: TestDb,
        store: PgPendingConnectionStore,
        states: PgConnectionStates,
        tenant: ScopedTenant,
    }

    /// A fresh database, one tenant, and the store and its reads across
    /// tenants on it.
    async fn fixture() -> Fixture {
        let db = TestDb::fresh().await;
        Fixture {
            store: PgPendingConnectionStore::new(Arc::clone(&db.databases)),
            states: PgConnectionStates::new(Arc::clone(&db.databases)),
            tenant: ScopedTenant::for_background(TenantId::new()),
            _db: db,
        }
    }

    fn connection(row: PendingConnectionRow) -> PendingConnection<ResolvedTenant> {
        PendingConnection::reconstitute(row).unwrap()
    }

    /// Ann began connecting: her connection is found by its id with what
    /// it connects and who began it, and by its state across tenants.
    #[tokio::test]
    async fn a_saved_connection_is_found_by_id_and_by_its_state() {
        let fx = fixture().await;
        let begun = connection(pending_connection_row("state one", 0));

        fx.store.save(&fx.tenant, &begun).await.unwrap();

        let found = fx
            .store
            .find_by_id(&fx.tenant, begun.id())
            .await
            .unwrap()
            .unwrap();
        let at = fx.states.find(begun.state()).await.unwrap().unwrap();
        assert_eq!(found.integration(), begun.integration());
        assert_eq!(found.started_by(), begun.started_by());
        assert_eq!(found.expires_at(), begun.expires_at());
        assert_eq!(at.tenant_id, *fx.tenant);
        assert_eq!(at.connection_id, *begun.id());
    }

    /// The service answered: the connection keeps the sealed credential
    /// and the code's digest, and reads back answered.
    #[tokio::test]
    async fn an_answered_connection_keeps_its_answer() {
        let fx = fixture().await;
        let row = pending_connection_row("state one", 0);
        let id = row.id;
        fx.store.save(&fx.tenant, &connection(row)).await.unwrap();
        let answered = connection(PendingConnectionRow {
            id,
            stage: ConnectionStage::Answered {
                credential: SealedSecret::new("v1.Y3JlZGVudGlhbA").unwrap(),
                code: TokenHash::from_stored("hash of code".to_owned()),
            },
            updated_at: at(5),
            ..pending_connection_row("state one", 0)
        });

        fx.store.save(&fx.tenant, &answered).await.unwrap();

        let found = fx.store.find_by_id(&fx.tenant, &id).await.unwrap().unwrap();
        assert_eq!(found.stage(), answered.stage());
    }

    /// A state digest different from the saved connection's digest finds
    /// no connection.
    #[tokio::test]
    async fn an_unknown_state_finds_nothing() {
        let fx = fixture().await;
        fx.store
            .save(
                &fx.tenant,
                &connection(pending_connection_row("state one", 0)),
            )
            .await
            .unwrap();

        let found = fx
            .states
            .find(&TokenHash::from_stored("hash of a guess".to_owned()))
            .await
            .unwrap();

        assert!(found.is_none());
    }

    /// Saving another tenant's connection with an existing state digest
    /// returns a conflict.
    #[tokio::test]
    async fn a_second_connection_with_one_state_is_refused() {
        let fx = fixture().await;
        let other = ScopedTenant::for_background(TenantId::new());
        fx.store
            .save(
                &fx.tenant,
                &connection(pending_connection_row("state one", 0)),
            )
            .await
            .unwrap();

        let second = fx
            .store
            .save(&other, &connection(pending_connection_row("state one", 0)))
            .await;

        assert!(matches!(second, Err(DomainError::Conflict(_))));
    }

    /// The sweep removes the connections that ran out, in every tenant,
    /// and leaves the ones still running.
    #[tokio::test]
    async fn the_sweep_removes_only_connections_that_ran_out() {
        let fx = fixture().await;
        let other = ScopedTenant::for_background(TenantId::new());
        let old = connection(pending_connection_row("old", 0));
        let elsewhere = connection(pending_connection_row("elsewhere", 0));
        let fresh = connection(pending_connection_row("fresh", 1_000));
        fx.store.save(&fx.tenant, &old).await.unwrap();
        fx.store.save(&other, &elsewhere).await.unwrap();
        fx.store.save(&fx.tenant, &fresh).await.unwrap();

        let removed = fx.states.remove_expired(at(900), 100).await.unwrap();

        assert_eq!(removed, 2);
        assert!(fx.states.find(old.state()).await.unwrap().is_none());
        assert!(fx.states.find(elsewhere.state()).await.unwrap().is_none());
        assert!(fx.states.find(fresh.state()).await.unwrap().is_some());
    }
}
