//! The delegations a tenant's agents ask people for, each table row under
//! row-level security, kept until the person asked answers or the request
//! lapses. An answer is written once: a save over a request answered since
//! it was read is refused as a conflict, so a refused request is never
//! granted and none is granted twice.

mod record;
mod words;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::agents::DelegationRequestStore;
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::agents::authority::delegation_request::DelegationRequest;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{AgentId, DelegationRequestId, PrincipalRef};
use sqlx::PgConnection;

use self::record::{RequestColumns, RequestRecord};
use crate::postgres::authorization::principals::kind_word;
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The Postgres store of delegation requests.
pub struct PgDelegationRequestStore {
    databases: Arc<Databases>,
}

impl TenantScoped for PgDelegationRequestStore {}

impl PgDelegationRequestStore {
    /// A store keeping delegation requests in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

fn rebuilt(
    records: Vec<RequestRecord>,
) -> Result<Vec<DelegationRequest<ResolvedTenant>>, DomainError> {
    records
        .into_iter()
        .map(RequestRecord::into_request)
        .collect()
}

/// Writes the mapped request and reports whether its stored state accepted the change.
async fn write_request(
    connection: &mut PgConnection,
    tenant_id: &ScopedTenant,
    columns: &RequestColumns<'_>,
) -> Result<bool, sqlx::Error> {
    sqlx::query_file!(
        "queries/delegation_requests/save.sql",
        columns.id,
        tenant_id.as_uuid(),
        columns.agent_id,
        columns.asked_of.kind,
        columns.asked_of.id,
        columns.asked_of.person,
        columns.granted,
        columns.limits,
        columns.reason,
        columns.state,
        columns.delegation_id,
        columns.decided_at,
        columns.created_at,
        columns.expires_at,
        columns.updated_at,
    )
    .execute(connection)
    .await
    .map(|done| done.rows_affected() > 0)
}

#[async_trait]
impl DelegationRequestStore for PgDelegationRequestStore {
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        request: &DelegationRequest<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let columns = RequestColumns::of(request)?;
        let written = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| write_request(connection, tenant_id, &columns).await,
        )
        .await?;
        if written {
            return Ok(());
        }
        Err(DomainError::conflict(message!(
            "infra-the-delegation-request-was-answered-since",
            "the delegation request was answered since it was read"
        )))
    }

    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &DelegationRequestId,
    ) -> Result<Option<DelegationRequest<ResolvedTenant>>, DomainError> {
        let ids = [*id.as_uuid()];
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    RequestRecord,
                    "queries/delegation_requests/by_ids.sql",
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

    async fn list_for_agent(
        &self,
        tenant_id: &ScopedTenant,
        agent: &AgentId,
    ) -> Result<Vec<DelegationRequest<ResolvedTenant>>, DomainError> {
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    RequestRecord,
                    "queries/delegation_requests/of_agent.sql",
                    tenant_id.as_uuid(),
                    agent.as_uuid()
                )
                .fetch_all(connection)
                .await
            },
        )
        .await?;
        rebuilt(records)
    }

    async fn list_asked_of(
        &self,
        tenant_id: &ScopedTenant,
        asked_of: &PrincipalRef,
    ) -> Result<Vec<DelegationRequest<ResolvedTenant>>, DomainError> {
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    RequestRecord,
                    "queries/delegation_requests/asked_of.sql",
                    tenant_id.as_uuid(),
                    kind_word(asked_of),
                    asked_of.id()
                )
                .fetch_all(connection)
                .await
            },
        )
        .await?;
        rebuilt(records)
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::ports::agents::DelegationStore;
    use ianua_domain::domains::agents::authority::delegation::{Delegation, DelegationRow};
    use ianua_domain::domains::agents::authority::delegation_request::{
        DelegationRequestRow, RequestState,
    };
    use ianua_domain::types::{DelegationId, TenantId};

    use super::*;
    use crate::postgres::agents::PgDelegationStore;
    use crate::test_support::TestDb;
    use crate::test_support::rows::agents::{human, request_row, root_row, saved_agent};
    use crate::test_support::rows::at;

    fn request(row: DelegationRequestRow) -> DelegationRequest<ResolvedTenant> {
        DelegationRequest::reconstitute(row).unwrap()
    }

    /// Keeps the returned order when comparing request lists.
    fn request_ids(requests: &[DelegationRequest<ResolvedTenant>]) -> Vec<DelegationRequestId> {
        requests.iter().map(|request| *request.id()).collect()
    }

    /// A fresh database, the store on it, one tenant and an agent of it.
    async fn fixture() -> (TestDb, PgDelegationRequestStore, ScopedTenant, AgentId) {
        let db = TestDb::fresh().await;
        let tenant = ScopedTenant::for_background(TenantId::new());
        let agent = saved_agent(&db.databases, &tenant, "ledger").await;
        let store = PgDelegationRequestStore::new(Arc::clone(&db.databases));
        (db, store, tenant, agent)
    }

    /// Saves a delegation Ann granted `agent` through the delegation store.
    async fn granted(db: &TestDb, tenant: &ScopedTenant, agent: AgentId) -> DelegationId {
        let row: DelegationRow = root_row(human("ann@acme.example").principal(), agent);
        let delegation: Delegation<ResolvedTenant> = Delegation::reconstitute(row).unwrap();
        PgDelegationStore::new(Arc::clone(&db.databases))
            .save(tenant, &delegation)
            .await
            .unwrap();
        *delegation.id()
    }

    /// A request is found by its id as it was saved, and answered it keeps
    /// the delegation it became; an id nobody has finds nothing.
    #[tokio::test]
    async fn a_saved_request_is_found_and_keeps_its_answer() {
        let (db, store, tenant, agent) = fixture().await;
        let ann = human("ann@acme.example");
        let asked = request(request_row(agent, ann.clone()));
        store.save(&tenant, &asked).await.unwrap();
        let delegation_id = granted(&db, &tenant, agent).await;
        let approved = request(DelegationRequestRow {
            id: *asked.id(),
            state: RequestState::Approved {
                delegation_id,
                at: at(30),
            },
            updated_at: at(30),
            ..request_row(agent, ann.clone())
        });

        store.save(&tenant, &approved).await.unwrap();

        let found = store
            .find_by_id(&tenant, asked.id())
            .await
            .unwrap()
            .unwrap();
        let unknown = store
            .find_by_id(&tenant, &DelegationRequestId::new())
            .await
            .unwrap();
        assert_eq!(found.asked_of(), &ann);
        assert_eq!(found.granted(), asked.granted());
        assert_eq!(found.constraints(), asked.constraints());
        assert_eq!(found.reason(), asked.reason());
        assert_eq!(found.state(), approved.state());
        assert!(unknown.is_none());
    }

    /// Saving an approval after Ann's denial returns a conflict and leaves
    /// the stored request denied.
    #[tokio::test]
    async fn a_refused_request_is_not_granted_by_an_old_copy() {
        let (db, store, tenant, agent) = fixture().await;
        let ann = human("ann@acme.example");
        let asked = request(request_row(agent, ann.clone()));
        let denied = request(DelegationRequestRow {
            id: *asked.id(),
            state: RequestState::Denied { at: at(20) },
            updated_at: at(20),
            ..request_row(agent, ann.clone())
        });
        store.save(&tenant, &asked).await.unwrap();
        store.save(&tenant, &denied).await.unwrap();
        let delegation_id = granted(&db, &tenant, agent).await;
        let approved = request(DelegationRequestRow {
            id: *asked.id(),
            state: RequestState::Approved {
                delegation_id,
                at: at(30),
            },
            updated_at: at(30),
            ..request_row(agent, ann)
        });

        let late = store.save(&tenant, &approved).await;

        assert!(matches!(late, Err(DomainError::Conflict(_))));
        let found = store
            .find_by_id(&tenant, asked.id())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.state(), denied.state());
    }

    /// Retrying the same approval succeeds, but saving an approval naming
    /// another delegation conflicts and preserves the first answer.
    #[tokio::test]
    async fn a_request_is_granted_once() {
        let (db, store, tenant, agent) = fixture().await;
        let ann = human("ann@acme.example");
        let asked = request(request_row(agent, ann.clone()));
        store.save(&tenant, &asked).await.unwrap();
        let answered = |delegation_id| {
            request(DelegationRequestRow {
                id: *asked.id(),
                state: RequestState::Approved {
                    delegation_id,
                    at: at(30),
                },
                updated_at: at(30),
                ..request_row(agent, ann.clone())
            })
        };
        let first = answered(granted(&db, &tenant, agent).await);
        let second = answered(granted(&db, &tenant, agent).await);
        store.save(&tenant, &first).await.unwrap();

        let retried = store.save(&tenant, &first).await;
        let raced = store.save(&tenant, &second).await;

        assert!(retried.is_ok());
        assert!(matches!(raced, Err(DomainError::Conflict(_))));
        let found = store
            .find_by_id(&tenant, asked.id())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.state(), first.state());
    }

    /// An agent's requests and those made of one person are listed newest
    /// first; another person, and another tenant, see none of them.
    #[tokio::test]
    async fn requests_are_listed_by_agent_and_by_the_person_asked() {
        let (_db, store, tenant, agent) = fixture().await;
        let ann = human("ann@acme.example");
        let older = request(request_row(agent, ann.clone()));
        let newer = request(DelegationRequestRow {
            created_at: at(10),
            expires_at: at(3600),
            updated_at: at(10),
            ..request_row(agent, ann.clone())
        });
        store.save(&tenant, &older).await.unwrap();
        store.save(&tenant, &newer).await.unwrap();
        let other = ScopedTenant::for_background(TenantId::new());

        let by_agent = store.list_for_agent(&tenant, &agent).await.unwrap();
        let of_ann = store
            .list_asked_of(&tenant, &ann.principal())
            .await
            .unwrap();
        let of_bob = store
            .list_asked_of(&tenant, &human("bob@acme.example").principal())
            .await
            .unwrap();
        let elsewhere = store.list_for_agent(&other, &agent).await.unwrap();

        assert_eq!(request_ids(&by_agent), [*newer.id(), *older.id()]);
        assert_eq!(request_ids(&of_ann), [*newer.id(), *older.id()]);
        assert!(of_bob.is_empty());
        assert!(elsewhere.is_empty());
    }

    /// Saving a request from an unknown agent returns an infrastructure error.
    #[tokio::test]
    async fn a_request_from_an_unknown_agent_is_refused() {
        let (_db, store, tenant, _) = fixture().await;
        let stray = request(request_row(AgentId::new(), human("ann@acme.example")));

        let saved = store.save(&tenant, &stray).await;

        assert!(matches!(saved, Err(DomainError::Infrastructure(_))));
    }

    /// A request of a tenant with a database of its own is kept there, and
    /// not in the platform database.
    #[tokio::test]
    async fn a_request_of_a_tenant_with_its_own_database_is_kept_there() {
        let db = TestDb::fresh().await;
        let own = TestDb::fresh().await;
        let apart = ScopedTenant::for_background(TenantId::new());
        db.databases.register(*apart, own.as_dedicated());
        let agent = saved_agent(&db.databases, &apart, "ledger").await;
        let store = PgDelegationRequestStore::new(Arc::clone(&db.databases));
        let asked = request(request_row(agent, human("ann@acme.example")));
        store.save(&apart, &asked).await.unwrap();

        let in_its_own = store.find_by_id(&apart, asked.id()).await.unwrap();
        db.databases.deregister(&apart);
        let in_the_platform = store.find_by_id(&apart, asked.id()).await.unwrap();

        assert!(in_its_own.is_some());
        assert!(in_the_platform.is_none());
    }

    /// A stored delegation request with a two-day lifetime is rejected as
    /// corrupt.
    #[tokio::test]
    async fn a_row_that_breaks_a_rule_of_the_request_is_refused() {
        let (db, store, tenant, agent) = fixture().await;
        let asked = request(request_row(agent, human("ann@acme.example")));
        store.save(&tenant, &asked).await.unwrap();
        db.tamper("UPDATE delegation_requests SET expires_at = created_at + interval '2 days'")
            .await;

        let read = store.find_by_id(&tenant, asked.id()).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
