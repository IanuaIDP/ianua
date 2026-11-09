//! A tenant's delegations and the graph they make, each table row under
//! row-level security.
//!
//! A delegation is cut from a parent, minted from the delegations its
//! agent holds, or derived by a token exchange from others it records. A
//! revoke follows all three edges in one recursive statement, so the
//! tear-down is quick on the widest graph and whole or not at all. The
//! named resources a delegation grants are kept beside it, so the agents
//! holding rights on one resource are read from an index.

mod record;
mod words;

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::agents::{DelegationStore, ResourceHolder, RevokedDelegation};
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::agents::authority::capability::ResourceRef;
use ianua_domain::domains::agents::authority::delegation::Delegation;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{AgentId, DelegationId, PrincipalRef};
use sqlx::PgConnection;
use uuid::Uuid;

use self::record::{
    ClosureRecord, DelegationColumns, DelegationRecord, HolderRecord, RevokedRecord, closures_from,
};
use crate::postgres::authorization::principals::kind_word;
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The Postgres delegation store.
pub struct PgDelegationStore {
    databases: Arc<Databases>,
}

impl TenantScoped for PgDelegationStore {}

impl PgDelegationStore {
    /// A store keeping delegations in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

/// Writes the delegation `columns` describe, the named resources it grants
/// and, for a minted one, the delegations it was cut from.
async fn write_delegation(
    connection: &mut PgConnection,
    tenant_id: &Uuid,
    columns: &DelegationColumns<'_>,
) -> Result<(), sqlx::Error> {
    write_identity(&mut *connection, tenant_id, columns).await?;
    write_resources(connection, tenant_id, columns).await?;
    sqlx::query_file!(
        "queries/delegation_sources/give.sql",
        tenant_id,
        columns.id,
        &columns.sources
    )
    .execute(connection)
    .await?;
    Ok(())
}

/// Writes the delegation row before its resource and source edges.
async fn write_identity(
    connection: &mut PgConnection,
    tenant_id: &Uuid,
    columns: &DelegationColumns<'_>,
) -> Result<(), sqlx::Error> {
    sqlx::query_file!(
        "queries/agent_delegations/save.sql",
        columns.id,
        tenant_id,
        columns.delegator_kind,
        columns.delegator_id,
        columns.delegate_id,
        columns.granted,
        columns.limits,
        columns.lineage,
        columns.parent_id,
        columns.minted_delegator_kind,
        columns.minted_delegator_id,
        columns.depth,
        columns.status,
        columns.issued_at,
        columns.expires_at,
        columns.renewed_at,
        columns.updated_at,
        columns.name,
        columns.minted_credential_id,
    )
    .execute(connection)
    .await?;
    Ok(())
}

/// Puts exactly the named resources `columns` lists beside the delegation.
async fn write_resources(
    connection: &mut PgConnection,
    tenant_id: &Uuid,
    columns: &DelegationColumns<'_>,
) -> Result<(), sqlx::Error> {
    sqlx::query_file!(
        "queries/delegation_resources/withdraw.sql",
        tenant_id,
        columns.id
    )
    .execute(&mut *connection)
    .await?;
    sqlx::query_file!(
        "queries/delegation_resources/give.sql",
        tenant_id,
        columns.id,
        &columns.relations,
        &columns.resource_refs
    )
    .execute(connection)
    .await?;
    Ok(())
}

fn rebuilt(records: Vec<DelegationRecord>) -> Result<Vec<Delegation<ResolvedTenant>>, DomainError> {
    records
        .into_iter()
        .map(DelegationRecord::into_delegation)
        .collect()
}

#[async_trait]
impl DelegationStore for PgDelegationStore {
    async fn find_by_ids(
        &self,
        tenant_id: &ScopedTenant,
        ids: &[DelegationId],
    ) -> Result<Vec<Delegation<ResolvedTenant>>, DomainError> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let ids: Vec<Uuid> = ids.iter().map(|id| *id.as_uuid()).collect();
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    DelegationRecord,
                    "queries/agent_delegations/by_ids.sql",
                    tenant_id.as_uuid(),
                    &ids
                )
                .fetch_all(connection)
                .await
            },
        )
        .await?;
        rebuilt(records)
    }

    async fn find_revocation_closures(
        &self,
        tenant_id: &ScopedTenant,
        roots: &[DelegationId],
    ) -> Result<HashMap<DelegationId, Vec<DelegationId>>, DomainError> {
        if roots.is_empty() {
            return Ok(HashMap::new());
        }
        let roots: Vec<Uuid> = roots.iter().map(|root| *root.as_uuid()).collect();
        let reached = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    ClosureRecord,
                    "queries/agent_delegations/closures.sql",
                    tenant_id.as_uuid(),
                    &roots
                )
                .fetch_all(connection)
                .await
            },
        )
        .await?;
        Ok(closures_from(reached))
    }

    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &DelegationId,
    ) -> Result<Option<Delegation<ResolvedTenant>>, DomainError> {
        let ids = [*id.as_uuid()];
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    DelegationRecord,
                    "queries/agent_delegations/by_ids.sql",
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
    ) -> Result<Vec<Delegation<ResolvedTenant>>, DomainError> {
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    DelegationRecord,
                    "queries/agent_delegations/of_agent.sql",
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

    async fn find_by_delegator(
        &self,
        tenant_id: &ScopedTenant,
        delegator: &PrincipalRef,
    ) -> Result<Vec<Delegation<ResolvedTenant>>, DomainError> {
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    DelegationRecord,
                    "queries/agent_delegations/of_delegator.sql",
                    tenant_id.as_uuid(),
                    kind_word(delegator),
                    delegator.id()
                )
                .fetch_all(connection)
                .await
            },
        )
        .await?;
        rebuilt(records)
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        delegation: &Delegation<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let columns = DelegationColumns::of(delegation)?;
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| write_delegation(connection, tenant_id.as_uuid(), &columns).await,
        )
        .await
    }

    async fn record_provenance(
        &self,
        tenant_id: &ScopedTenant,
        delegation_id: &DelegationId,
        sources: &[DelegationId],
    ) -> Result<(), DomainError> {
        let sources: Vec<Uuid> = sources.iter().map(|source| *source.as_uuid()).collect();
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/delegation_provenance/record.sql",
                    tenant_id.as_uuid(),
                    delegation_id.as_uuid(),
                    &sources
                )
                .execute(connection)
                .await?;
                Ok(())
            },
        )
        .await
    }

    async fn resource_holders(
        &self,
        tenant_id: &ScopedTenant,
        resource: &ResourceRef,
    ) -> Result<Vec<ResourceHolder>, DomainError> {
        let now = clock::now();
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    HolderRecord,
                    "queries/delegation_resources/holders.sql",
                    tenant_id.as_uuid(),
                    resource.as_str(),
                    now
                )
                .fetch_all(connection)
                .await
            },
        )
        .await?;
        records.into_iter().map(HolderRecord::into_holder).collect()
    }

    async fn revoke_subtree(
        &self,
        tenant_id: &ScopedTenant,
        root: &DelegationId,
    ) -> Result<Vec<RevokedDelegation>, DomainError> {
        let now = clock::now();
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    RevokedRecord,
                    "queries/agent_delegations/revoke_closure.sql",
                    tenant_id.as_uuid(),
                    root.as_uuid(),
                    now
                )
                .fetch_all(connection)
                .await
            },
        )
        .await?;
        Ok(records
            .into_iter()
            .map(RevokedRecord::into_revoked)
            .collect())
    }

    async fn find_revocation_closure(
        &self,
        tenant_id: &ScopedTenant,
        root: &DelegationId,
    ) -> Result<Vec<DelegationId>, DomainError> {
        let ids = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_scalar!(
                    "queries/agent_delegations/closure.sql",
                    tenant_id.as_uuid(),
                    root.as_uuid()
                )
                .fetch_all(connection)
                .await
            },
        )
        .await?;
        Ok(ids.into_iter().map(DelegationId::from_uuid).collect())
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::agents::authority::capability::{
        CapabilitySet, Relation, ResourceCapability,
    };
    use ianua_domain::domains::agents::authority::delegation::{
        DelegationRenewal, DelegationRow, Lineage, Revoker,
    };
    use ianua_domain::shared::model::aggregate::Aggregate as _;
    use ianua_domain::types::{Label, TenantId, UserId};

    use super::*;
    use crate::test_support::TestDb;
    use crate::test_support::rows::agents::{
        child_row, minted_row, root_row, saved_agent, saved_credential,
    };
    use crate::test_support::rows::identity::from_now;

    fn delegation(row: DelegationRow) -> Delegation<ResolvedTenant> {
        Delegation::reconstitute(row).unwrap()
    }

    fn reading(object: &str) -> ResourceCapability {
        ResourceCapability::new(
            Relation::new("reader").unwrap(),
            ResourceRef::new(object).unwrap(),
        )
    }

    fn ann() -> PrincipalRef {
        PrincipalRef::User(UserId::from_uuid(Uuid::from_u128(7)))
    }

    /// A fresh database, the store on it, one tenant and two agents of it.
    async fn fixture() -> (TestDb, PgDelegationStore, ScopedTenant, [AgentId; 2]) {
        let db = TestDb::fresh().await;
        let tenant = ScopedTenant::for_background(TenantId::new());
        let ledger = saved_agent(&db.databases, &tenant, "ledger").await;
        let helper = saved_agent(&db.databases, &tenant, "helper").await;
        let store = PgDelegationStore::new(Arc::clone(&db.databases));
        (db, store, tenant, [ledger, helper])
    }

    async fn save_all(
        store: &PgDelegationStore,
        tenant: &ScopedTenant,
        delegations: &[&Delegation<ResolvedTenant>],
    ) {
        for delegation in delegations {
            store.save(tenant, delegation).await.unwrap();
        }
    }

    fn ids(delegations: &[Delegation<ResolvedTenant>]) -> Vec<DelegationId> {
        delegations
            .iter()
            .map(|delegation| *delegation.id())
            .collect()
    }

    fn sorted(mut ids: Vec<DelegationId>) -> Vec<DelegationId> {
        ids.sort_by_key(|id| *id.as_uuid());
        ids
    }

    /// A calendar grant that expired before the resource-holder lookup.
    fn expired_calendar(helper: AgentId) -> Delegation<ResolvedTenant> {
        delegation(DelegationRow {
            granted: CapabilitySet::empty().with_resources(vec![reading("calendar:q1")]),
            issued_at: from_now(-1200),
            expires_at: from_now(-600),
            updated_at: from_now(-1200),
            ..root_row(ann(), helper)
        })
    }

    /// A delegation graph spanning parent, minted and provenance edges plus an isolated root.
    struct Graph {
        root: Delegation<ResolvedTenant>,
        child: Delegation<ResolvedTenant>,
        minted: Delegation<ResolvedTenant>,
        derived: Delegation<ResolvedTenant>,
        apart: Delegation<ResolvedTenant>,
    }

    /// Stores the graph and its first provenance edge before a revocation walk.
    async fn save_graph(
        db: &TestDb,
        store: &PgDelegationStore,
        tenant: &ScopedTenant,
        [ledger, helper]: [AgentId; 2],
    ) -> Graph {
        let key = saved_credential(&db.databases, tenant, helper, "helper-key").await;
        let root = delegation(root_row(ann(), ledger));
        let child = delegation(child_row(&root, helper));
        let minted = delegation(minted_row(helper, *key.id(), &[&child]));
        let derived = delegation(root_row(ann(), helper));
        let apart = delegation(root_row(ann(), ledger));
        save_all(store, tenant, &[&root, &child, &minted, &derived, &apart]).await;
        store
            .record_provenance(tenant, derived.id(), &[*minted.id()])
            .await
            .unwrap();
        Graph {
            root,
            child,
            minted,
            derived,
            apart,
        }
    }

    /// Reads a delegation known to have been stored by the fixture.
    async fn found(
        store: &PgDelegationStore,
        tenant: &ScopedTenant,
        id: &DelegationId,
    ) -> Delegation<ResolvedTenant> {
        store.find_by_id(tenant, id).await.unwrap().unwrap()
    }

    /// Confirms another tenant sees no graph and empty root selections read nothing.
    async fn assert_empty_and_foreign_graphs(
        store: &PgDelegationStore,
        tenant: &ScopedTenant,
        roots: &[DelegationId],
    ) {
        let other = ScopedTenant::for_background(TenantId::new());
        let foreign = store.find_revocation_closures(&other, roots).await.unwrap();
        let foreign_rows = store.find_by_ids(&other, roots).await.unwrap();
        assert!(foreign.values().all(Vec::is_empty));
        assert!(foreign_rows.is_empty());
        assert!(
            store
                .find_revocation_closures(tenant, &[])
                .await
                .unwrap()
                .is_empty()
        );
        assert!(store.find_by_ids(tenant, &[]).await.unwrap().is_empty());
    }

    /// The derived delegation is revoked while the disconnected root stays live.
    async fn assert_revocation_standings(
        store: &PgDelegationStore,
        tenant: &ScopedTenant,
        graph: &Graph,
    ) {
        let still = found(store, tenant, graph.apart.id()).await;
        let gone = found(store, tenant, graph.derived.id()).await;
        assert!(!still.is_revoked());
        assert!(gone.is_revoked());
    }

    /// A named, renewed root granting read access to a calendar is found by
    /// its id as it was saved; an id nobody has finds nothing.
    #[tokio::test]
    async fn a_saved_delegation_is_found_by_its_id() {
        let (_db, store, tenant, [ledger, _]) = fixture().await;
        let row = root_row(ann(), ledger);
        let renewed_at = row.issued_at;
        let root = delegation(DelegationRow {
            granted: CapabilitySet::empty().with_resources(vec![reading("calendar:q1")]),
            renewed: DelegationRenewal::RenewedAt(renewed_at),
            name: Some(Label::new("name", "Q1 reconciliation").unwrap()),
            ..row
        });
        save_all(&store, &tenant, &[&root]).await;

        let found = store.find_by_id(&tenant, root.id()).await.unwrap().unwrap();
        let unknown = store
            .find_by_id(&tenant, &DelegationId::new())
            .await
            .unwrap();

        assert_eq!(found.delegator(), root.delegator());
        assert_eq!(found.delegate(), root.delegate());
        assert_eq!(found.granted(), root.granted());
        assert_eq!(found.constraints(), root.constraints());
        assert_eq!(found.lineage(), &Lineage::Root);
        assert_eq!(found.renewed(), root.renewed());
        assert_eq!(found.name(), root.name());
        assert_eq!(found.expires_at(), root.expires_at());
        assert!(unknown.is_none());
    }

    /// A delegation passed on and one minted from two others keep where
    /// they sit in their chain: the parent, and the sources in their order
    /// with the key the agent signed in with to mint it.
    #[tokio::test]
    async fn a_lineage_reads_back_as_it_was_saved() {
        let (db, store, tenant, [ledger, helper]) = fixture().await;
        let key = saved_credential(&db.databases, &tenant, ledger, "ledger-key").await;
        let first = delegation(root_row(ann(), ledger));
        let second = delegation(root_row(ann(), ledger));
        let child = delegation(child_row(&first, helper));
        let minted = delegation(minted_row(ledger, *key.id(), &[&second, &first]));
        save_all(&store, &tenant, &[&first, &second, &child, &minted]).await;

        let found_child = store
            .find_by_id(&tenant, child.id())
            .await
            .unwrap()
            .unwrap();
        let found_minted = store
            .find_by_id(&tenant, minted.id())
            .await
            .unwrap()
            .unwrap();

        assert_eq!(found_child.lineage(), &Lineage::Under(*first.id()));
        assert_eq!(found_child.depth(), 1);
        assert_eq!(found_minted.lineage(), minted.lineage());
    }

    /// An agent's delegations and a person's grants are listed oldest first,
    /// and another tenant sees none of them.
    #[tokio::test]
    async fn delegations_are_listed_by_agent_and_by_delegator() {
        let (_db, store, tenant, [ledger, helper]) = fixture().await;
        let first = delegation(root_row(ann(), ledger));
        let child = delegation(child_row(&first, helper));
        save_all(&store, &tenant, &[&first, &child]).await;
        let other = ScopedTenant::for_background(TenantId::new());

        let held = store.list_for_agent(&tenant, &helper).await.unwrap();
        let granted = store.find_by_delegator(&tenant, &ann()).await.unwrap();
        let passed_on = store
            .find_by_delegator(&tenant, &PrincipalRef::Agent(ledger))
            .await
            .unwrap();
        let elsewhere = store.find_by_delegator(&other, &ann()).await.unwrap();

        assert_eq!(ids(&held), [*child.id()]);
        assert_eq!(ids(&granted), [*first.id()]);
        assert_eq!(ids(&passed_on), [*child.id()]);
        assert!(elsewhere.is_empty());
    }

    /// The agents holding rights on a resource are those of live
    /// delegations; a revoked or expired one, or one on another resource,
    /// counts for nothing.
    #[tokio::test]
    async fn the_holders_of_a_resource_are_those_of_live_delegations() {
        let (_db, store, tenant, [ledger, helper]) = fixture().await;
        let calendar = CapabilitySet::empty().with_resources(vec![reading("calendar:q1")]);
        let live = delegation(DelegationRow {
            granted: calendar.clone(),
            ..root_row(ann(), ledger)
        });
        let mut revoked = delegation(DelegationRow {
            granted: calendar,
            ..root_row(ann(), helper)
        });
        revoked.revoke(Revoker::Platform).unwrap();
        let expired = expired_calendar(helper);
        let elsewhere = delegation(DelegationRow {
            granted: CapabilitySet::empty().with_resources(vec![reading("calendar:q2")]),
            ..root_row(ann(), helper)
        });
        save_all(&store, &tenant, &[&live, &revoked, &expired, &elsewhere]).await;

        let holders = store
            .resource_holders(&tenant, &ResourceRef::new("calendar:q1").unwrap())
            .await
            .unwrap();

        assert_eq!(
            holders,
            [ResourceHolder {
                agent: ledger,
                relation: Relation::new("reader").unwrap(),
            }]
        );
    }

    /// Revoking a root tears down the child passed on from it, the token
    /// minted from that child, and what a token exchange derived from the
    /// token, in one call; a second revoke changes nothing and names
    /// nothing.
    #[tokio::test]
    async fn a_revoke_reaches_everything_cut_minted_or_derived_from_it() {
        let (db, store, tenant, [ledger, helper]) = fixture().await;
        let graph = save_graph(&db, &store, &tenant, [ledger, helper]).await;
        store
            .record_provenance(&tenant, graph.derived.id(), &[*graph.minted.id()])
            .await
            .unwrap();

        let closure = store
            .find_revocation_closure(&tenant, graph.root.id())
            .await
            .unwrap();
        let revoked: Vec<DelegationId> = store
            .revoke_subtree(&tenant, graph.root.id())
            .await
            .unwrap()
            .iter()
            .map(|revoked| revoked.id)
            .collect();
        let again = store
            .revoke_subtree(&tenant, graph.root.id())
            .await
            .unwrap();

        let reached = vec![*graph.child.id(), *graph.minted.id(), *graph.derived.id()];
        assert_eq!(sorted(closure), sorted(reached.clone()));
        assert_eq!(
            sorted(revoked),
            sorted([reached, vec![*graph.root.id()]].concat())
        );
        assert!(again.is_empty());
        assert_revocation_standings(&store, &tenant, &graph).await;
    }

    /// Overlapping roots follow parent, minted and provenance edges through
    /// a cycle independently. Each excludes itself, duplicates collapse,
    /// and another tenant can read neither the graph nor its records.
    #[tokio::test]
    async fn batched_closures_keep_each_roots_complete_tenant_scoped_graph() {
        let (db, store, tenant, [ledger, helper]) = fixture().await;
        let graph = save_graph(&db, &store, &tenant, [ledger, helper]).await;
        store
            .record_provenance(&tenant, graph.root.id(), &[*graph.derived.id()])
            .await
            .unwrap();
        let missing = DelegationId::new();
        let roots = [
            *graph.root.id(),
            *graph.child.id(),
            *graph.root.id(),
            missing,
        ];

        let closures = store
            .find_revocation_closures(&tenant, &roots)
            .await
            .unwrap();
        let found = store.find_by_ids(&tenant, &roots).await.unwrap();
        assert_empty_and_foreign_graphs(&store, &tenant, &roots).await;

        assert_cycle_closures(&closures, &graph);
        assert!(closures.get(&missing).is_none_or(Vec::is_empty));
        assert_eq!(
            sorted(ids(&found)),
            sorted(vec![*graph.root.id(), *graph.child.id()])
        );
    }

    /// The root's and the child's closures each hold the rest of the cycle,
    /// never the delegation itself.
    fn assert_cycle_closures(closures: &HashMap<DelegationId, Vec<DelegationId>>, graph: &Graph) {
        let rest = |own: &Delegation<ResolvedTenant>| {
            let mut all = vec![
                *graph.root.id(),
                *graph.child.id(),
                *graph.minted.id(),
                *graph.derived.id(),
            ];
            all.retain(|id| id != own.id());
            sorted(all)
        };
        assert_eq!(sorted(closures[graph.root.id()].clone()), rest(&graph.root));
        assert_eq!(
            sorted(closures[graph.child.id()].clone()),
            rest(&graph.child)
        );
    }

    /// Two delegations recorded as derived from each other end the walk of
    /// a revoke rather than loop.
    #[tokio::test]
    async fn a_loop_in_the_graph_ends_the_walk() {
        let (_db, store, tenant, [ledger, helper]) = fixture().await;
        let one = delegation(root_row(ann(), ledger));
        let two = delegation(root_row(ann(), helper));
        save_all(&store, &tenant, &[&one, &two]).await;
        store
            .record_provenance(&tenant, two.id(), &[*one.id()])
            .await
            .unwrap();
        store
            .record_provenance(&tenant, one.id(), &[*two.id()])
            .await
            .unwrap();

        let closure = store
            .find_revocation_closure(&tenant, one.id())
            .await
            .unwrap();

        assert_eq!(closure, [*two.id()]);
    }

    /// Saving a pre-revocation copy leaves the delegation revoked and does
    /// not move its update time before that copy's update time.
    #[tokio::test]
    async fn a_revoked_delegation_stays_revoked_when_an_old_copy_is_saved() {
        let (_db, store, tenant, [ledger, _]) = fixture().await;
        let root = delegation(root_row(ann(), ledger));
        save_all(&store, &tenant, &[&root]).await;
        store.revoke_subtree(&tenant, root.id()).await.unwrap();

        save_all(&store, &tenant, &[&root]).await;

        let found = store.find_by_id(&tenant, root.id()).await.unwrap().unwrap();
        assert!(found.is_revoked());
        assert!(found.updated_at() >= root.updated_at());
    }

    /// A delegation of a tenant with a database of its own is kept there,
    /// and not in the platform database.
    #[tokio::test]
    async fn a_delegation_of_a_tenant_with_its_own_database_is_kept_there() {
        let db = TestDb::fresh().await;
        let own = TestDb::fresh().await;
        let apart = ScopedTenant::for_background(TenantId::new());
        db.databases.register(*apart, own.as_dedicated());
        let ledger = saved_agent(&db.databases, &apart, "ledger").await;
        let store = PgDelegationStore::new(Arc::clone(&db.databases));
        let root = delegation(root_row(ann(), ledger));
        store.save(&apart, &root).await.unwrap();

        let in_its_own = store.find_by_id(&apart, root.id()).await.unwrap();
        db.databases.deregister(&apart);
        let in_the_platform = store.find_by_id(&apart, root.id()).await.unwrap();

        assert!(in_its_own.is_some());
        assert!(in_the_platform.is_none());
    }

    /// Saving a delegation to an unknown agent returns an infrastructure error.
    #[tokio::test]
    async fn a_delegation_to_an_unknown_agent_is_refused() {
        let (_db, store, tenant, _) = fixture().await;
        let stray = delegation(root_row(ann(), AgentId::new()));

        let saved = store.save(&tenant, &stray).await;

        assert!(matches!(saved, Err(DomainError::Infrastructure(_))));
    }

    /// A stored root delegation with a depth beyond its limit is rejected as
    /// corrupt.
    #[tokio::test]
    async fn a_row_that_breaks_a_rule_of_the_delegation_is_refused() {
        let (db, store, tenant, [ledger, _]) = fixture().await;
        let root = delegation(root_row(ann(), ledger));
        save_all(&store, &tenant, &[&root]).await;
        db.tamper("UPDATE agent_delegations SET depth = 9").await;

        let read = store.find_by_id(&tenant, root.id()).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
