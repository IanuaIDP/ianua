//! The audit trail: every event a use case dispatches is kept as an audit
//! record, in the running unit of work, so a change and its record are
//! kept or dropped together. A failed write fails the dispatch.
//!
//! A tenant's records go to `audit_records` in the database the tenant
//! lives in, each linked to the one before it in the tenant's chain. The
//! link is read and the records written in one transaction, under the
//! tenant's chain lock, which holds until the transaction ends, so two
//! writers never link to the same record. An organization's records and
//! the platform's go to `platform_audit_records`, unchained, as the domain
//! chains a tenant's records only. With the records, the tenant's chain head
//! moves to the newest of them, sealed under a key the database never
//! holds, so the walk ([`walk`]) can tell a chain cut short from one that
//! ended. A tenant's records are never added to the platform's tables once
//! the tenant moved to a schema of its own, even by a node that has not
//! heard of the move yet.
//!
//! Each record is also queued in the outbox of its database, in the same
//! transaction, for the relay to publish on the message bus once the
//! change commits: a bus that is down delays an event, it never fails the
//! change or loses the event.

mod chain;
mod record;
mod walk;

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use futures_util::future::try_join_all;
use ianua_app::ports::shared::EventDispatcher;
use ianua_domain::domains::audit::builder::{AuditContext, build_audit_record};
use ianua_domain::domains::audit::record::AuditRecord;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::events::chain::EventOrigin;
use ianua_domain::shared::events::event::DomainEvent;
use ianua_domain::types::TenantId;
use sqlx::PgConnection;
use time::OffsetDateTime;
use uuid::Uuid;

use self::record::{Batch, HeadRecord, Link, RecordColumns};
pub use self::walk::PgAuditChainVerifier;
use crate::crypto::AuditChainSeals;
use crate::postgres::foundation::audit_chain;
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The Postgres audit trail: the dispatcher's audit half.
pub struct PgEventDispatcher {
    databases: Arc<Databases>,
    heads: AuditChainSeals,
}

impl PgEventDispatcher {
    /// A trail keeping audit records in `databases`, sealing each tenant's
    /// chain head with `heads`.
    #[must_use]
    pub fn new(databases: Arc<Databases>, heads: AuditChainSeals) -> Self {
        Self { databases, heads }
    }

    /// Keeps `records`: each tenant's chained in its own database, the rest
    /// in the platform's.
    async fn keep(&self, records: &[Dispatched]) -> Result<(), DomainError> {
        let mut chains: HashMap<TenantId, Vec<RecordColumns<'_>>> = HashMap::new();
        let mut unchained = Vec::new();
        for Dispatched {
            record,
            chain_depth,
        } in records
        {
            let columns = RecordColumns::of(record, *chain_depth)?;
            match record.scope.tenant_id() {
                Some(tenant) => chains.entry(*tenant).or_default().push(columns),
                None => unchained.push(columns),
            }
        }
        try_join_all(
            chains
                .into_iter()
                .map(|(tenant, columns)| self.chain(tenant, columns)),
        )
        .await?;
        self.write_unchained(Batch::unchained(unchained)).await
    }

    /// Links `records` into `tenant`'s chain and writes them, in one
    /// transaction under the chain's lock.
    async fn chain(
        &self,
        tenant: TenantId,
        records: Vec<RecordColumns<'_>>,
    ) -> Result<(), DomainError> {
        let tenant_id = *tenant.as_uuid();
        let routed_to_platform = !self.databases.lives_apart(&tenant);
        scoped(
            &self.databases,
            RowScope::Tenant(tenant),
            async move |connection| {
                audit_chain::lock(&mut *connection, tenant_id).await?;
                if routed_to_platform {
                    ensure_not_moved(&mut *connection, tenant_id).await?;
                }
                let link = read_link(&mut *connection, tenant_id).await?;
                let batch = Batch::chained(tenant_id, &link, records);
                write_chained(&mut *connection, tenant_id, &batch).await?;
                self.move_head(&mut *connection, tenant_id, &batch).await?;
                sqlx::query_file!(
                    "queries/event_outbox/add.sql",
                    tenant_id,
                    &batch.ids,
                    &batch.chain_depths
                )
                .execute(&mut *connection)
                .await?;
                announce_events(connection).await
            },
        )
        .await
    }

    /// Moves `tenant_id`'s sealed head to the newest record of `batch`.
    async fn move_head(
        &self,
        connection: &mut PgConnection,
        tenant_id: Uuid,
        batch: &Batch,
    ) -> Result<(), sqlx::Error> {
        let (Some(seq), Some(hash)) = (batch.seqs.last(), batch.entry_hashes.last()) else {
            return Ok(());
        };
        let seal = self.heads.head_seal(&tenant_id, *seq, hash);
        sqlx::query_file!(
            "queries/audit_chain_heads/save.sql",
            tenant_id,
            seq,
            hash,
            seal.as_slice()
        )
        .execute(connection)
        .await?;
        Ok(())
    }

    /// Writes an unchained `batch` of organization and platform records in
    /// one statement, or nothing for an empty one.
    async fn write_unchained(&self, batch: Batch) -> Result<(), DomainError> {
        if batch.ids.is_empty() {
            return Ok(());
        }
        scoped(&self.databases, RowScope::Unscoped, async |connection| {
            write_platform(&mut *connection, &batch).await?;
            sqlx::query_file!("queries/platform_event_outbox/add.sql", &batch.ids)
                .execute(&mut *connection)
                .await?;
            announce_events(connection).await
        })
        .await
    }
}

/// Announces on the event channel that events wait for the bus, heard
/// once the transaction on `connection` commits.
async fn announce_events(connection: &mut PgConnection) -> Result<(), sqlx::Error> {
    sqlx::query_file!("queries/event_outbox/announce.sql")
        .execute(connection)
        .await?;
    Ok(())
}

/// Reads and validates the link before appending under the chain lock.
async fn read_link(connection: &mut PgConnection, tenant_id: Uuid) -> Result<Link, sqlx::Error> {
    let head = sqlx::query_file_as!(HeadRecord, "queries/audit_records/head.sql", tenant_id)
        .fetch_one(connection)
        .await?;
    head.into_link()
        .map_err(|corrupt| sqlx::Error::Decode(Box::new(corrupt)))
}

/// Appends unchained platform records before their events are queued.
async fn write_platform(connection: &mut PgConnection, batch: &Batch) -> Result<(), sqlx::Error> {
    sqlx::query_file!(
        "queries/platform_audit_records/append.sql",
        &batch.ids,
        &batch.organization_ids as &[Option<Uuid>],
        &batch.actors,
        &batch.actor_kinds,
        &batch.actor_ids as &[Option<Uuid>],
        &batch.event_types,
        &batch.target_ids as &[Option<String>],
        &batch.ip_addresses as &[Option<String>],
        &batch.user_agents as &[Option<String>],
        &batch.payloads,
        &batch.acted_through,
        &batch.through_operator_ids as &[Option<Uuid>],
        &batch.through_admin_ids as &[Option<Uuid>],
        &batch.as_user_ids as &[Option<Uuid>],
        &batch.support_impersonation_ids as &[Option<Uuid>],
        &batch.occurred_at as &[OffsetDateTime],
        &batch.through_execution_ids as &[Option<Uuid>],
    )
    .execute(connection)
    .await?;
    Ok(())
}

/// Refuses to add `tenant_id`'s records to the platform's tables once the
/// tenant lives in a schema of its own: a node that has not heard of the
/// move yet would start a second chain where nobody reads it. Read under
/// the chain lock, which the move takes too.
async fn ensure_not_moved(
    connection: &mut PgConnection,
    tenant_id: Uuid,
) -> Result<(), sqlx::Error> {
    let moved = sqlx::query_file_scalar!("queries/tenant_databases/held.sql", tenant_id)
        .fetch_one(connection)
        .await?;
    if moved {
        return Err(sqlx::Error::InvalidArgument(
            "the tenant lives in a schema of its own, and this node has not routed it there yet"
                .to_owned(),
        ));
    }
    Ok(())
}

/// Writes a chained `batch` of `tenant_id`'s records in one statement.
async fn write_chained(
    connection: &mut PgConnection,
    tenant_id: Uuid,
    batch: &Batch,
) -> Result<(), sqlx::Error> {
    sqlx::query_file!(
        "queries/audit_records/append.sql",
        tenant_id,
        &batch.ids,
        &batch.seqs,
        &batch.organization_ids as &[Option<Uuid>],
        &batch.actors,
        &batch.actor_kinds,
        &batch.actor_ids as &[Option<Uuid>],
        &batch.event_types,
        &batch.target_ids as &[Option<String>],
        &batch.ip_addresses as &[Option<String>],
        &batch.user_agents as &[Option<String>],
        &batch.payloads,
        &batch.acted_through,
        &batch.through_operator_ids as &[Option<Uuid>],
        &batch.through_admin_ids as &[Option<Uuid>],
        &batch.as_user_ids as &[Option<Uuid>],
        &batch.support_impersonation_ids as &[Option<Uuid>],
        &batch.occurred_at as &[OffsetDateTime],
        &batch.prev_hashes,
        &batch.entry_hashes,
        &batch.through_execution_ids as &[Option<Uuid>],
    )
    .execute(connection)
    .await?;
    Ok(())
}

#[async_trait]
impl EventDispatcher for PgEventDispatcher {
    async fn dispatch(
        &self,
        events: &[DomainEvent],
        ctx: &AuditContext,
    ) -> Result<(), DomainError> {
        let records: Vec<Dispatched> = events
            .iter()
            .map(|event| Dispatched {
                record: build_audit_record(event, ctx),
                chain_depth: chain_depth_of(event.origin()).max(chain_depth_of(ctx.origin())),
            })
            .collect();
        self.keep(&records).await
    }
}

/// An event's record as it is kept, with the depth of the workflow chain
/// whose work raised it, which the outbox carries to the bus.
struct Dispatched {
    record: AuditRecord,
    chain_depth: i16,
}

/// The depth `origin` names, as the outbox keeps it: 0 for an event raised
/// outside any workflow.
fn chain_depth_of(origin: EventOrigin) -> i16 {
    match origin {
        EventOrigin::Outside => 0,
        EventOrigin::Execution(depth) => i16::from(depth.get()),
    }
}

#[cfg(test)]
mod tests {
    // The trail's own tests call the raw sink they test; use cases reach it
    // only through `RequestAuditor`, as clippy.toml's `disallowed-methods`
    // says.
    #![allow(clippy::disallowed_methods)]

    use ianua_app::listing::{Limit, PageRequest, SortOrder};
    use ianua_app::ports::audit::{AuditLogFilter, EvidenceStore, PlatformAuditLogStore};
    use ianua_app::tenancy::ScopedTenant;
    use ianua_domain::shared::config::DomainLimits;
    use ianua_domain::test_support::events::{sample_organization_event, sample_platform_event};
    use ianua_domain::types::{AgentId, OrganizationId};

    use super::*;
    use crate::postgres::audit::{PgEvidenceStore, PgPlatformAuditLogStore};
    use crate::test_support::TestDb;
    use crate::test_support::rows::at;
    use crate::test_support::rows::audit::{
        agent_event, chain_heads, saved_organization, saved_tenant_of,
    };

    struct Fixture {
        db: TestDb,
        organization: OrganizationId,
        tenant: ScopedTenant,
        trail: PgEventDispatcher,
    }

    /// A fresh database holding Acme and one of its tenants, and the trail
    /// on it.
    async fn fixture() -> Fixture {
        let db = TestDb::fresh().await;
        let organization = saved_organization(&db.databases).await;
        let tenant = saved_tenant_of(&db.databases, organization).await;
        let trail = PgEventDispatcher::new(Arc::clone(&db.databases), chain_heads());
        Fixture {
            db,
            organization,
            tenant,
            trail,
        }
    }

    /// Each of `agent`'s records in `tenant`'s chain: its place, the link
    /// before it, and its own hash.
    async fn chain_of(
        db: &Fixture,
        tenant: &ScopedTenant,
        agent: &AgentId,
    ) -> Vec<(i64, Vec<u8>, Vec<u8>)> {
        PgEvidenceStore::new(Arc::clone(&db.db.databases))
            .agent_records(tenant, agent, 0, 50)
            .await
            .unwrap()
            .into_iter()
            .map(|record| (record.seq, record.prev_hash, record.entry_hash))
            .collect()
    }

    /// Two dispatches of the tenant's events make one chain: the records
    /// are numbered from 1 in the order written, each linked to the one
    /// before it, the first to the genesis link.
    #[tokio::test]
    async fn a_tenants_records_are_chained_in_the_order_written() {
        let db = fixture().await;
        let agent = AgentId::new();
        let context = AuditContext::system();

        db.trail
            .dispatch(
                &[
                    agent_event(*db.tenant, agent, 1),
                    agent_event(*db.tenant, agent, 2),
                ],
                &context,
            )
            .await
            .unwrap();
        db.trail
            .dispatch(&[agent_event(*db.tenant, agent, 3)], &context)
            .await
            .unwrap();

        let chain = chain_of(&db, &db.tenant, &agent).await;
        let seqs: Vec<i64> = chain.iter().map(|(seq, _, _)| *seq).collect();
        assert_eq!(seqs, [1, 2, 3]);
        assert_eq!(chain[0].1, vec![0; 32]);
        assert_eq!(chain[1].1, chain[0].2);
        assert_eq!(chain[2].1, chain[1].2);
    }

    /// Each tenant has a chain of its own, so a record of one tenant never
    /// links to another's.
    #[tokio::test]
    async fn each_tenant_has_a_chain_of_its_own() {
        let db = fixture().await;
        let other = saved_tenant_of(&db.db.databases, db.organization).await;
        let agent = AgentId::new();

        db.trail
            .dispatch(
                &[
                    agent_event(*db.tenant, agent, 1),
                    agent_event(*other, agent, 2),
                ],
                &AuditContext::system(),
            )
            .await
            .unwrap();

        assert_eq!(chain_of(&db, &db.tenant, &agent).await[0].0, 1);
        assert_eq!(chain_of(&db, &other, &agent).await[0].0, 1);
    }

    /// A tenant with a database of its own keeps its chain there.
    #[tokio::test]
    async fn a_tenant_apart_keeps_its_chain_in_its_own_database() {
        let db = fixture().await;
        let own = TestDb::fresh().await;
        db.db.databases.register(*db.tenant, own.as_dedicated());
        let agent = AgentId::new();

        db.trail
            .dispatch(
                &[agent_event(*db.tenant, agent, 1)],
                &AuditContext::system(),
            )
            .await
            .unwrap();

        assert_eq!(chain_of(&db, &db.tenant, &agent).await.len(), 1);
        db.db.databases.deregister(&db.tenant);
        assert!(chain_of(&db, &db.tenant, &agent).await.is_empty());
    }

    /// An organization's events and the platform's are kept beside the
    /// tenants', in the platform's log.
    #[tokio::test]
    async fn organization_and_platform_events_are_kept_unchained() {
        let db = fixture().await;

        db.trail
            .dispatch(
                &[
                    sample_organization_event(db.organization, at(1)),
                    sample_platform_event(),
                ],
                &AuditContext::system(),
            )
            .await
            .unwrap();

        let store =
            PgPlatformAuditLogStore::new(Arc::clone(&db.db.databases), DomainLimits::default());
        let log = store
            .query(
                &AuditLogFilter::default(),
                &SortOrder::default(),
                &PageRequest::first(Limit::new(10).unwrap()),
            )
            .await
            .unwrap();
        assert_eq!(log.items.len(), 2);
        assert!(log.items.iter().all(|entry| entry.tenant_id.is_none()));
    }

    /// Dispatching a record to a removed tenant database returns an
    /// infrastructure error.
    #[tokio::test]
    async fn a_record_that_cannot_be_written_fails_the_dispatch() {
        let db = fixture().await;
        let gone = TestDb::fresh().await;
        let apart = gone.as_dedicated();
        drop(gone);
        db.db.databases.register(*db.tenant, apart);

        let dispatched = db
            .trail
            .dispatch(
                &[agent_event(*db.tenant, AgentId::new(), 1)],
                &AuditContext::system(),
            )
            .await;

        assert!(matches!(dispatched, Err(DomainError::Infrastructure(_))));
    }

    /// Nothing dispatched writes nothing, and succeeds.
    #[tokio::test]
    async fn an_empty_dispatch_writes_nothing() {
        let db = fixture().await;

        db.trail
            .dispatch(&[], &AuditContext::system())
            .await
            .unwrap();
    }
}
