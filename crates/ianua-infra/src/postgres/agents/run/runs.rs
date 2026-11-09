//! A tenant's agent runs and the steps they took, each row under
//! row-level security.
//!
//! A run is one row, and each of its steps a row of its own, written once:
//! a save adds the steps past the last one stored and never writes a step
//! again, so a long run does not rewrite its history with every step. A
//! save over a version the caller read is one statement that writes only
//! while the stored run is still at that version, so a person's pause and
//! the worker's step never undo each other.

mod record;
mod words;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::listing::{Page, PageRequest, SortOrder};
use ianua_app::ports::TenantScoped;
use ianua_app::ports::agents::{RunSortField, RunStore, RunSummary, RunVersion};
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::agents::execution::run::{AgentRun, RunStatus};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{AgentId, AgentRunId, TenantId};
use serde_json::Value;
use sqlx::PgConnection;
use time::OffsetDateTime;
use uuid::Uuid;

use self::record::{RunColumns, RunRecord, steps_after};
use crate::postgres::foundation::paging::{Nullable, PageQuery, SortColumns, in_page_order};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::stored::StoredWord as _;
use crate::postgres::foundation::unit::scoped;

/// The Postgres agent run store.
pub struct PgRunStore {
    databases: Arc<Databases>,
}

impl TenantScoped for PgRunStore {}

/// A run's steps not yet stored: their numbers, and each sealed.
struct NewSteps {
    numbers: Vec<i32>,
    sealed: Vec<Value>,
}

impl PgRunStore {
    /// A store keeping agent runs in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }

    /// Reads a bounded page of run rows without fetching historical steps.
    async fn summaries(
        &self,
        tenant: &ScopedTenant,
        listed: PageQuery<'static>,
        request: &PageRequest,
    ) -> Result<Page<RunSummary>, DomainError> {
        let order = SortOrder::<RunSortField>::default();
        let keyset = request.keyset(&order)?;
        let records = scoped(
            &self.databases,
            RowScope::from(tenant),
            async |connection| {
                let ids = listed.fetch(&keyset, &mut *connection).await?;
                let records = sqlx::query_file_as!(
                    RunRecord,
                    "queries/agent_runs/summaries.sql",
                    tenant.as_uuid(),
                    &ids
                )
                .fetch_all(connection)
                .await?;
                Ok(in_page_order(&ids, records, |record| record.id))
            },
        )
        .await?;
        let summaries = records
            .into_iter()
            .map(RunRecord::into_summary)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(keyset.seal(summaries))
    }

    /// The steps of `run` past the last one `tenant` stores for it.
    async fn new_steps(
        &self,
        tenant: &ScopedTenant,
        run: &AgentRun<ResolvedTenant>,
    ) -> Result<NewSteps, DomainError> {
        let latest = scoped(
            &self.databases,
            RowScope::from(tenant),
            async |connection| {
                sqlx::query_file_scalar!(
                    "queries/agent_run_steps/latest.sql",
                    tenant.as_uuid(),
                    run.id().as_uuid()
                )
                .fetch_one(connection)
                .await
            },
        )
        .await?;
        let (numbers, sealed) = steps_after(run, latest)?;
        Ok(NewSteps { numbers, sealed })
    }

    /// Rebuilds runs whose headers and steps were read in one SQL snapshot.
    async fn read(
        &self,
        tenant: &ScopedTenant,
        rows: impl AsyncFnOnce(&mut PgConnection) -> Result<Vec<RunRecord>, sqlx::Error>,
    ) -> Result<Vec<AgentRun<ResolvedTenant>>, DomainError> {
        let records = scoped(&self.databases, RowScope::from(tenant), rows).await?;
        records.into_iter().map(RunRecord::into_run).collect()
    }
}

impl SortColumns for RunSortField {
    fn column(self) -> &'static str {
        match self {
            Self::CreatedAt => "created_at",
        }
    }

    fn nullable(self) -> Nullable {
        Nullable::Never
    }
}

/// The tenant's run ids, narrowed to a lifecycle state when requested.
fn listed_runs(tenant: &ScopedTenant, status: Option<RunStatus>) -> PageQuery<'static> {
    let listed = PageQuery::ids("id", "agent_runs").filter("tenant_id = ?", *tenant.as_uuid());
    match status {
        Some(status) => listed.filter("status = ?", status.word()),
        None => listed,
    }
}

/// Writes `run` as it is now, added or over what is stored.
/// The checked statement keeps the complete run header in one write with explicit binds.
#[allow(clippy::too_many_lines)]
async fn write_run(
    connection: &mut PgConnection,
    tenant: &TenantId,
    run: &RunColumns<'_>,
) -> Result<(), sqlx::Error> {
    sqlx::query_file!(
        "queries/agent_runs/save.sql",
        run.id,
        tenant.as_uuid(),
        run.agent_id,
        run.provider_id,
        run.goal,
        &run.purpose,
        &run.granted_tools,
        &run.approval_classes,
        run.approval,
        run.delegation_id,
        run.max_steps,
        run.spend_limit_micros,
        run.input_tokens,
        run.output_tokens,
        run.spent_micros,
        run.started_by.kind,
        run.started_by.id,
        run.started_by.person,
        run.exposure,
        run.chain_depth,
        run.status,
        run.pending_call,
        run.created_at,
        run.updated_at,
        run.spend_check,
        run.spend_check_micros,
        run.check_version_id,
        run.check_tries,
    )
    .execute(connection)
    .await
    .map(|_| ())
}

/// Writes `run` over the stored run only while it was last changed at
/// `read`, and gives back when it is stored as changed now.
async fn rewrite_run(
    connection: &mut PgConnection,
    tenant: &TenantId,
    run: &RunColumns<'_>,
    read: OffsetDateTime,
) -> Result<Option<OffsetDateTime>, sqlx::Error> {
    sqlx::query_file_scalar!(
        "queries/agent_runs/save_unchanged_since.sql",
        tenant.as_uuid(),
        run.id,
        read,
        &run.purpose,
        &run.granted_tools,
        &run.approval_classes,
        run.approval,
        run.delegation_id,
        run.max_steps,
        run.spend_limit_micros,
        run.input_tokens,
        run.output_tokens,
        run.spent_micros,
        run.exposure,
        run.chain_depth,
        run.status,
        run.pending_call,
        run.updated_at,
        run.spend_check,
        run.spend_check_micros,
    )
    .fetch_optional(connection)
    .await
}

/// Adds the steps `steps` of the run `run_id`, in one statement.
async fn write_steps(
    connection: &mut PgConnection,
    tenant: &TenantId,
    run_id: &Uuid,
    steps: &NewSteps,
) -> Result<(), sqlx::Error> {
    if steps.numbers.is_empty() {
        return Ok(());
    }
    sqlx::query_file!(
        "queries/agent_run_steps/save.sql",
        tenant.as_uuid(),
        run_id,
        &steps.numbers,
        &steps.sealed
    )
    .execute(connection)
    .await
    .map(|_| ())
}

#[async_trait]
impl RunStore for PgRunStore {
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        run: &AgentRun<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let steps = self.new_steps(tenant_id, run).await?;
        let columns = RunColumns::of(run)?;
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                write_run(&mut *connection, tenant_id, &columns).await?;
                write_steps(connection, tenant_id, columns.id, &steps).await
            },
        )
        .await
    }

    async fn save_unchanged_since(
        &self,
        tenant_id: &ScopedTenant,
        run: &AgentRun<ResolvedTenant>,
        read: RunVersion,
    ) -> Result<RunVersion, DomainError> {
        let steps = self.new_steps(tenant_id, run).await?;
        let columns = RunColumns::of(run)?;
        let stored = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                let changed = read.changed_at();
                let Some(at) = rewrite_run(&mut *connection, tenant_id, &columns, changed).await?
                else {
                    return Ok(None);
                };
                write_steps(connection, tenant_id, columns.id, &steps).await?;
                Ok(Some(at))
            },
        )
        .await?;
        stored.map(RunVersion::stored).ok_or_else(|| {
            DomainError::conflict(message!(
                "infra-the-run-changed-since-it-was",
                "the run changed since it was read, or is gone"
            ))
        })
    }

    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &AgentRunId,
    ) -> Result<Option<AgentRun<ResolvedTenant>>, DomainError> {
        let ids = [*id.as_uuid()];
        let found = self
            .read(tenant_id, async |connection| {
                sqlx::query_file_as!(
                    RunRecord,
                    "queries/agent_runs/by_ids.sql",
                    tenant_id.as_uuid(),
                    &ids[..]
                )
                .fetch_all(connection)
                .await
            })
            .await?;
        Ok(found.into_iter().next())
    }

    async fn list_for_agent(
        &self,
        tenant_id: &ScopedTenant,
        agent: &AgentId,
        status: Option<RunStatus>,
        request: &PageRequest,
    ) -> Result<Page<RunSummary>, DomainError> {
        let listed = listed_runs(tenant_id, status).filter("agent_id = ?", *agent.as_uuid());
        self.summaries(tenant_id, listed, request).await
    }

    async fn list_in_tenant(
        &self,
        tenant_id: &ScopedTenant,
        status: Option<RunStatus>,
        request: &PageRequest,
    ) -> Result<Page<RunSummary>, DomainError> {
        self.summaries(tenant_id, listed_runs(tenant_id, status), request)
            .await
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::listing::Limit;
    use ianua_domain::domains::agents::authority::delegation::ActingUnder;
    use ianua_domain::domains::agents::execution::run::{
        AgentRunRow, CheckTries, RunCheck, RunState,
    };
    use ianua_domain::shared::events::chain::{ChainDepth, EventOrigin};
    use ianua_domain::shared::model::aggregate::Aggregate as _;
    use ianua_domain::shared::model::restriction::Restriction;
    use ianua_domain::types::{Initiator, SandboxVersionId};

    use super::*;
    use crate::test_support::TestDb;
    use crate::test_support::rows::agents::run::{another_agent, held_call, run_row, tool_step};
    use crate::test_support::rows::agents::saved_delegation;
    use crate::test_support::rows::at;

    struct Fixture {
        db: TestDb,
        store: PgRunStore,
        tenant: ScopedTenant,
        agent: AgentId,
    }

    /// A fresh database, the store on it, and one agent of one tenant to
    /// keep runs of.
    async fn fixture() -> Fixture {
        let db = TestDb::fresh().await;
        let tenant = ScopedTenant::for_background(TenantId::new());
        let agent = another_agent(&db.databases, &tenant).await;
        Fixture {
            store: PgRunStore::new(Arc::clone(&db.databases)),
            tenant,
            agent,
            db,
        }
    }

    fn run(row: AgentRunRow) -> AgentRun<ResolvedTenant> {
        AgentRun::reconstitute(row).unwrap()
    }

    /// A run of `agent` that took one step and is paused on the call it
    /// holds at the next, `seconds` after the fixed moment.
    fn paused(agent: AgentId, seconds: i64) -> AgentRunRow {
        AgentRunRow {
            steps: vec![tool_step(1, seconds)],
            state: RunState::AwaitingApproval(held_call(2)),
            created_at: at(seconds),
            updated_at: at(seconds.saturating_add(1)),
            ..run_row(agent)
        }
    }

    impl Fixture {
        /// Reads one filtered page for the fixture's agent.
        async fn page(&self, status: Option<RunStatus>, request: &PageRequest) -> Page<RunSummary> {
            self.store
                .list_for_agent(&self.tenant, &self.agent, status, request)
                .await
                .unwrap()
        }

        /// Stores tied paused runs plus runs excluded by agent or lifecycle filters.
        async fn save_page_cases(&self) -> [AgentRunId; 3] {
            let first = self.saved(paused(self.agent, 0)).await;
            let second = self.saved(paused(self.agent, 0)).await;
            let third = self.saved(paused(self.agent, 0)).await;
            self.saved(run_row(self.agent)).await;
            let other_agent = another_agent(&self.db.databases, &self.tenant).await;
            self.saved(paused(other_agent, 0)).await;
            [*first.id(), *second.id(), *third.id()]
        }

        async fn saved(&self, row: AgentRunRow) -> AgentRun<ResolvedTenant> {
            let run = run(row);
            self.store.save(&self.tenant, &run).await.unwrap();
            run
        }

        async fn found(&self, id: &AgentRunId) -> Option<AgentRun<ResolvedTenant>> {
            self.store.find_by_id(&self.tenant, id).await.unwrap()
        }

        async fn of_agent(&self, status: Option<RunStatus>) -> Vec<AgentRunId> {
            let request = PageRequest::default();
            let listed = self
                .store
                .list_for_agent(&self.tenant, &self.agent, status, &request);
            ids(&listed.await.unwrap().items)
        }

        async fn in_tenant(
            &self,
            tenant: &ScopedTenant,
            status: Option<RunStatus>,
        ) -> Vec<AgentRunId> {
            ids(&self
                .store
                .list_in_tenant(tenant, status, &PageRequest::default())
                .await
                .unwrap()
                .items)
        }
    }

    fn ids(runs: &[RunSummary]) -> Vec<AgentRunId> {
        runs.iter().map(|run| run.id).collect()
    }

    /// The identifiers across two consecutive pages, preserving their returned order.
    fn joined_ids(first: &[RunSummary], second: &[RunSummary]) -> Vec<AgentRunId> {
        first.iter().chain(second).map(|run| run.id).collect()
    }

    /// The fixture run after its worker records a first step at the supplied time.
    fn stepped_run(id: AgentRunId, agent: AgentId, seconds: i64) -> AgentRun<ResolvedTenant> {
        run(AgentRunRow {
            id,
            steps: vec![tool_step(1, seconds)],
            updated_at: at(seconds),
            ..run_row(agent)
        })
    }

    /// A run started inside a workflow, paused on a call after one step, is
    /// found again with its step, its held call, who started it and what
    /// it spent.
    #[tokio::test]
    async fn a_saved_run_is_found_with_its_steps_and_held_call() {
        let fx = fixture().await;
        let delegation = saved_delegation(&fx.db.databases, &fx.tenant, fx.agent).await;
        let saved = fx
            .saved(AgentRunRow {
                origin: EventOrigin::Execution(ChainDepth::from_stored(2).unwrap()),
                delegation_id: ActingUnder::Delegation(delegation),
                ..paused(fx.agent, 0)
            })
            .await;

        let found = fx.found(saved.id()).await.unwrap();

        assert_eq!(found.steps(), saved.steps());
        assert_eq!(found.state(), saved.state());
        assert_eq!(found.started_by(), saved.started_by());
        assert_eq!(found.origin(), saved.origin());
        assert_eq!(found.purpose(), saved.purpose());
        assert_eq!(found.granted_tools(), saved.granted_tools());
        assert_eq!(found.delegation_id(), saved.delegation_id());
        assert_eq!(found.spend_limit(), saved.spend_limit());
        assert_eq!(found.spend_check(), saved.spend_check());
        assert_eq!(found.usage(), saved.usage());
        assert_eq!(found.spent(), saved.spent());
        assert_eq!(found.updated_at(), saved.updated_at());
    }

    /// A run whose answers a sandbox version's code checks, with two tries,
    /// reads back held to that check; a plain run reads back held to none.
    #[tokio::test]
    async fn a_run_held_to_a_check_reads_back_held_to_it() {
        let fx = fixture().await;
        let check = RunCheck::Sandbox {
            version: SandboxVersionId::new(),
            tries: CheckTries::new(2).unwrap(),
        };
        let held = fx
            .saved(AgentRunRow {
                check,
                ..run_row(fx.agent)
            })
            .await;
        let plain = fx.saved(run_row(fx.agent)).await;

        assert_eq!(fx.found(held.id()).await.unwrap().check(), check);
        assert_eq!(
            fx.found(plain.id()).await.unwrap().check(),
            RunCheck::Unchecked
        );
    }

    /// A run an agent started for itself, under no spend limit, reads back
    /// with the agent as its starter and no limit.
    #[tokio::test]
    async fn a_run_an_agent_started_reads_back_as_the_agents() {
        let fx = fixture().await;
        let saved = fx
            .saved(AgentRunRow {
                started_by: Initiator::Agent(fx.agent),
                spend_limit: Restriction::Unrestricted,
                ..run_row(fx.agent)
            })
            .await;

        let found = fx.found(saved.id()).await.unwrap();

        assert_eq!(found.started_by(), &Initiator::Agent(fx.agent));
        assert_eq!(found.spend_limit(), Restriction::Unrestricted);
    }

    /// An id the tenant has no run for finds nothing, rather than failing.
    #[tokio::test]
    async fn an_unknown_run_is_not_found() {
        let fx = fixture().await;

        assert!(fx.found(&AgentRunId::new()).await.is_none());
    }

    /// The worker records a second step: saving the run again adds it
    /// after the first, which stays as it was stored.
    #[tokio::test]
    async fn saving_again_adds_the_new_steps() {
        let fx = fixture().await;
        let first = fx
            .saved(AgentRunRow {
                steps: vec![tool_step(1, 2)],
                ..run_row(fx.agent)
            })
            .await;
        fx.saved(AgentRunRow {
            id: *first.id(),
            steps: vec![tool_step(1, 2), tool_step(2, 4)],
            updated_at: at(20),
            ..run_row(fx.agent)
        })
        .await;

        let found = fx.found(first.id()).await.unwrap();

        assert_eq!(found.steps(), [tool_step(1, 2), tool_step(2, 4)]);
        assert_eq!(found.updated_at(), at(20));
    }

    /// The worker saves over the version it read and is given the new one,
    /// which a later save over it is held to in turn.
    #[tokio::test]
    async fn a_save_over_the_version_read_gives_back_the_new_one() {
        let fx = fixture().await;
        let saved = fx.saved(run_row(fx.agent)).await;
        let read = RunVersion::of(&fx.found(saved.id()).await.unwrap());
        let stepped = run(AgentRunRow {
            id: *saved.id(),
            steps: vec![tool_step(1, 3)],
            updated_at: at(30),
            ..run_row(fx.agent)
        });

        let store = &fx.store;
        let now = store.save_unchanged_since(&fx.tenant, &stepped, read);
        let now = now.await.unwrap();
        let again = store.save_unchanged_since(&fx.tenant, &stepped, now);

        assert_eq!(now.changed_at(), at(30));
        assert_eq!(again.await.unwrap(), now);
        assert_eq!(fx.found(saved.id()).await.unwrap().steps().len(), 1);
    }

    /// A read retains the original run version when a worker saves a step
    /// after its query. The next read sees the new step and update time.
    #[tokio::test]
    async fn a_read_keeps_one_version_when_the_worker_adds_a_step() {
        let fx = fixture().await;
        let saved = fx.saved(run_row(fx.agent)).await;
        let ids = [*saved.id().as_uuid()];
        let stepped = stepped_run(*saved.id(), fx.agent, 20);

        let read = fx
            .store
            .read(&fx.tenant, async |connection| {
                let records = sqlx::query_file_as!(
                    RunRecord,
                    "queries/agent_runs/by_ids.sql",
                    fx.tenant.as_uuid(),
                    &ids[..]
                )
                .fetch_all(connection)
                .await?;
                fx.store.save(&fx.tenant, &stepped).await.unwrap();
                Ok(records)
            })
            .await
            .unwrap();

        assert_eq!(read.len(), 1);
        assert_eq!(read[0].updated_at(), saved.updated_at());
        assert!(read[0].steps().is_empty());
        let latest = fx.found(saved.id()).await.unwrap();
        assert_eq!(latest.updated_at(), at(20));
        assert_eq!(latest.steps(), [tool_step(1, 20)]);
    }

    /// Saving a step with a mismatched run version returns a conflict and
    /// leaves the stored run without steps.
    #[tokio::test]
    async fn a_save_over_a_version_that_moved_on_is_refused() {
        let fx = fixture().await;
        let saved = fx.saved(run_row(fx.agent)).await;
        let stale = RunVersion::stored(at(5));
        let stepped = run(AgentRunRow {
            id: *saved.id(),
            steps: vec![tool_step(1, 3)],
            updated_at: at(30),
            ..run_row(fx.agent)
        });

        let refused = fx
            .store
            .save_unchanged_since(&fx.tenant, &stepped, stale)
            .await;

        assert!(matches!(refused, Err(DomainError::Conflict(_))));
        assert!(fx.found(saved.id()).await.unwrap().steps().is_empty());
    }

    /// Updating an unstored run by version returns a conflict and leaves it
    /// absent.
    #[tokio::test]
    async fn a_save_over_a_version_of_a_run_that_is_gone_is_refused() {
        let fx = fixture().await;
        let never = run(run_row(fx.agent));
        let read = RunVersion::of(&never);

        let refused = fx
            .store
            .save_unchanged_since(&fx.tenant, &never, read)
            .await;

        assert!(matches!(refused, Err(DomainError::Conflict(_))));
        assert!(fx.found(never.id()).await.is_none());
    }

    /// A broken historical step is never hydrated for a summary listing;
    /// the full detail read still refuses that same corrupted trace.
    #[tokio::test]
    async fn run_summaries_do_not_hydrate_historical_steps() {
        let fx = fixture().await;
        let saved = fx.saved(paused(fx.agent, 0)).await;
        fx.db
            .tamper("UPDATE agent_run_steps SET step = jsonb_set(step, '{v}', '2')")
            .await;

        let listed = fx
            .store
            .list_for_agent(&fx.tenant, &fx.agent, None, &PageRequest::default())
            .await
            .unwrap();
        let detail = fx.store.find_by_id(&fx.tenant, saved.id()).await;

        assert_eq!(listed.items.len(), 1);
        assert_eq!(listed.items[0].id, *saved.id());
        assert_eq!(listed.items[0].state, *saved.state());
        assert!(matches!(detail, Err(DomainError::Infrastructure(_))));
    }

    /// Tied creation times are ordered by id across pages, with state and
    /// tenant filters applied before the limit and an empty final continuation.
    #[tokio::test]
    async fn run_summary_pages_keep_ties_filters_and_tenant_boundaries() {
        let fx = fixture().await;
        let cases = fx.save_page_cases().await;
        let request = PageRequest::first(Limit::new(2).unwrap());
        let status = Some(RunStatus::AwaitingApproval);

        let one = fx.page(status, &request).await;
        let following = request.following(&one).unwrap();
        let two = fx.page(status, &following).await;
        let other = ScopedTenant::for_background(TenantId::new());
        let foreign = fx
            .store
            .list_in_tenant(&other, status, &following)
            .await
            .unwrap();
        let mut expected = cases.to_vec();
        expected.sort_unstable_by(|a, b| b.as_uuid().cmp(a.as_uuid()));
        let actual = joined_ids(&one.items, &two.items);

        assert_eq!(actual, expected);
        assert_eq!(one.items.len(), 2);
        assert_eq!(two.items.len(), 1);
        assert!(two.next.is_none());
        assert!(foreign.items.is_empty());
        assert!(foreign.next.is_none());
        let tenant = fx
            .store
            .list_in_tenant(&fx.tenant, status, &PageRequest::default())
            .await
            .unwrap();
        assert_eq!(tenant.items.len(), 4);
    }

    /// Listing run summaries rejects a stored blank goal as corrupt.
    #[tokio::test]
    async fn run_summaries_refuse_corrupt_projected_values() {
        let fx = fixture().await;
        fx.saved(run_row(fx.agent)).await;
        fx.db.tamper("UPDATE agent_runs SET goal = ' '").await;

        let listed = fx
            .store
            .list_in_tenant(&fx.tenant, None, &PageRequest::default())
            .await;

        assert!(matches!(listed, Err(DomainError::Infrastructure(_))));
    }

    /// An agent's runs are listed newest first, narrowed to one status
    /// when one is asked for, and leave out another agent's.
    #[tokio::test]
    async fn an_agents_runs_are_listed_newest_first_by_status() {
        let fx = fixture().await;
        let older = fx.saved(paused(fx.agent, 0)).await;
        let newer = fx.saved(paused(fx.agent, 5)).await;
        let running = fx
            .saved(AgentRunRow {
                created_at: at(9),
                updated_at: at(9),
                ..run_row(fx.agent)
            })
            .await;
        let other = another_agent(&fx.db.databases, &fx.tenant).await;
        fx.saved(run_row(other)).await;

        let every = fx.of_agent(None).await;
        let awaiting = fx.of_agent(Some(RunStatus::AwaitingApproval)).await;

        assert_eq!(every, [*running.id(), *newer.id(), *older.id()]);
        assert_eq!(awaiting, [*newer.id(), *older.id()]);
    }

    /// Every run of the tenant is listed, whatever its agent, newest first,
    /// and narrowed to one status when one is asked for.
    #[tokio::test]
    async fn the_tenants_runs_are_listed_newest_first_by_status() {
        let fx = fixture().await;
        let other = another_agent(&fx.db.databases, &fx.tenant).await;
        let theirs = fx.saved(paused(other, 4)).await;
        let ours = fx.saved(run_row(fx.agent)).await;

        let every = fx.in_tenant(&fx.tenant, None).await;
        let running = fx.in_tenant(&fx.tenant, Some(RunStatus::Running)).await;

        assert_eq!(every, [*theirs.id(), *ours.id()]);
        assert_eq!(running, [*ours.id()]);
    }

    /// Another tenant sees none of Acme's runs, by id or in a list.
    #[tokio::test]
    async fn another_tenants_runs_are_invisible() {
        let fx = fixture().await;
        let saved = fx.saved(run_row(fx.agent)).await;
        let other = ScopedTenant::for_background(TenantId::new());

        let by_id = fx.store.find_by_id(&other, saved.id()).await.unwrap();

        assert!(by_id.is_none());
        assert!(fx.in_tenant(&other, None).await.is_empty());
    }

    /// Saving a run for an unknown agent returns an infrastructure error.
    #[tokio::test]
    async fn a_run_of_an_unknown_agent_is_refused() {
        let fx = fixture().await;
        let stray = run(run_row(AgentId::new()));

        let saved = fx.store.save(&fx.tenant, &stray).await;

        assert!(matches!(saved, Err(DomainError::Infrastructure(_))));
    }

    /// A dedicated tenant's run reads back with its steps directly from its
    /// database; the platform tenant's run list remains empty.
    #[tokio::test]
    async fn a_tenant_with_its_own_database_keeps_its_runs_there() {
        let fx = fixture().await;
        let own = TestDb::fresh().await;
        let apart = ScopedTenant::for_background(TenantId::new());
        fx.db.databases.register(*apart, own.as_dedicated());
        let agent = another_agent(&fx.db.databases, &apart).await;
        let saved = run(paused(agent, 0));

        fx.store.save(&apart, &saved).await.unwrap();

        let in_own = PgRunStore::new(Arc::clone(&own.databases));
        let found = in_own.find_by_id(&apart, saved.id()).await.unwrap();
        assert_eq!(found.unwrap().steps(), saved.steps());
        assert!(fx.in_tenant(&fx.tenant, None).await.is_empty());
    }

    /// Reading a stored run with a blank goal returns a corruption error.
    #[tokio::test]
    async fn a_row_that_breaks_a_rule_of_the_run_is_refused() {
        let fx = fixture().await;
        let saved = fx.saved(run_row(fx.agent)).await;
        fx.db.tamper("UPDATE agent_runs SET goal = ' '").await;

        let read = fx.store.find_by_id(&fx.tenant, saved.id()).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }

    /// Reading a run whose step uses an unsupported envelope version returns
    /// a corruption error.
    #[tokio::test]
    async fn a_step_in_an_unknown_shape_is_refused() {
        let fx = fixture().await;
        let saved = fx.saved(paused(fx.agent, 0)).await;
        fx.db
            .tamper("UPDATE agent_run_steps SET step = jsonb_set(step, '{v}', '2')")
            .await;

        let read = fx.store.find_by_id(&fx.tenant, saved.id()).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
