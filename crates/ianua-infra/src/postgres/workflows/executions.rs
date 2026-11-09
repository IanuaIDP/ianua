//! A tenant's workflow runs, each table row under row-level security.
//!
//! A run carries the graph of the version it runs, so a later version never
//! changes one already started, and its steps' standing as one JSON value.
//! Beside it are kept the agent runs its steps wait on now, so the run is
//! found by one when it ends; every save writes them as its steps hold
//! them. A list reads the ids of its page first, newest first, then reads
//! those runs through the one query by ids. The runs of agent flows are
//! told apart by their workflow's row, which says where it came from. A
//! pass of a loop names the run it belongs to, and lists leave it out.
//!
//! A run ends once. A save read before the run ended, such as a worker's
//! next step landing after a person stopped it, would bring it back to
//! life or end it a second way; the save is refused and the end stands.
//!
//! A change to a stored run is written only over the version it was read
//! at, its last change time, in the one statement that writes it, and every
//! such write moves that time on by at least a microsecond. So of the
//! worker, a settling agent run and a person deciding at once, the first to
//! save wins and the others are refused, rather than the last one undoing
//! the rest.

mod record;
mod words;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::listing::{Page, PageRequest, SortOrder};
use ianua_app::ports::TenantScoped;
use ianua_app::ports::workflows::{
    ExecutionVersion, NewestFirstField, RunKind, WorkflowExecutionStore,
};
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::workflows::execution::WorkflowExecution;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{AgentRunId, WorkflowExecutionId, WorkflowId};
use sqlx::PgConnection;
use time::OffsetDateTime;
use uuid::Uuid;

use self::record::{ExecutionColumns, ExecutionRecord};
use self::words::ModeKind;
use crate::postgres::foundation::paging::{PageQuery, in_page_order};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::stored::StoredWord as _;
use crate::postgres::foundation::unit::scoped;

/// The most ended runs one statement removes.
const PURGED_AT_ONCE: i64 = 1_000;

/// The runs a list of designed workflows' runs reads, beside the workflow
/// each runs.
const DESIGNED_RUNS: &str =
    "workflow_executions e JOIN workflows w ON w.tenant_id = e.tenant_id AND w.id = e.workflow_id";

/// The Postgres store of workflow runs.
pub struct PgWorkflowExecutionStore {
    databases: Arc<Databases>,
}

impl TenantScoped for PgWorkflowExecutionStore {}

impl PgWorkflowExecutionStore {
    /// A store keeping workflow runs in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }

    /// The page `listed` reads, newest first.
    async fn newest_first(
        &self,
        tenant: &ScopedTenant,
        listed: PageQuery<'static>,
        page: &PageRequest,
    ) -> Result<Page<WorkflowExecution<ResolvedTenant>>, DomainError> {
        let order = SortOrder::<NewestFirstField>::default();
        let keyset = page.keyset(&order)?;
        let records = scoped(
            &self.databases,
            RowScope::from(tenant),
            async |connection| {
                let ids = listed.fetch(&keyset, &mut *connection).await?;
                let records = records_of(connection, tenant.as_uuid(), &ids).await?;
                Ok(in_page_order(&ids, records, |record| record.id))
            },
        )
        .await?;
        Ok(keyset.seal(rebuilt_all(records)?))
    }
}

/// The records of the runs of `tenant` that `ids` names, in no order.
async fn records_of(
    connection: &mut PgConnection,
    tenant: &Uuid,
    ids: &[Uuid],
) -> Result<Vec<ExecutionRecord>, sqlx::Error> {
    sqlx::query_file_as!(
        ExecutionRecord,
        "queries/workflow_executions/by_ids.sql",
        tenant,
        ids
    )
    .fetch_all(connection)
    .await
}

fn rebuilt_all(
    records: Vec<ExecutionRecord>,
) -> Result<Vec<WorkflowExecution<ResolvedTenant>>, DomainError> {
    records
        .into_iter()
        .map(ExecutionRecord::into_execution)
        .collect()
}

/// Whether a save wrote the run, or found it ended another way than the
/// save says and wrote nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Saved {
    /// The run and the agent runs it waits on are written.
    Written,
    /// Nothing is written: the kept run ended, and ended otherwise.
    AlreadyEnded,
}

/// Writes `columns`, and the agent runs they wait on, for `tenant`, unless
/// the kept run already ended otherwise.
async fn written(
    connection: &mut PgConnection,
    tenant: &Uuid,
    c: &ExecutionColumns<'_>,
) -> Result<Saved, sqlx::Error> {
    if write_execution(&mut *connection, tenant, c).await? == 0 {
        return Ok(Saved::AlreadyEnded);
    }
    hold_agent_runs(connection, tenant, c).await?;
    Ok(Saved::Written)
}

/// Writes the run `c` describes, answering how many rows it wrote.
/// The checked query's explicit bind list alone exceeds the function-length limit.
#[allow(clippy::too_many_lines)]
async fn write_execution(
    connection: &mut PgConnection,
    tenant: &Uuid,
    c: &ExecutionColumns<'_>,
) -> Result<u64, sqlx::Error> {
    let done = sqlx::query_file!(
        "queries/workflow_executions/save.sql",
        c.id,
        tenant,
        c.workflow_id,
        c.version,
        c.graph,
        c.acting_for,
        c.authors,
        c.cause,
        c.cause_detail.event,
        c.cause_detail.event_depth,
        c.cause_detail.restarted,
        c.cause_detail.from,
        c.pass_of,
        c.pass_step,
        c.pass_index,
        c.chain_depth,
        c.input,
        c.exposure,
        c.steps,
        c.status,
        c.cancelled_by,
        c.deadline,
        c.created_at,
        c.updated_at,
        c.failure_alert,
        c.mode,
        &c.stand_ins,
        c.cause_detail.change,
    )
    .execute(connection)
    .await?;
    Ok(done.rows_affected())
}

/// Writes the run `c` describes over the stored one only while it was last
/// changed at `read`, and the agent runs it waits on with it. Answers when
/// it is stored as changed now, or `None` when it changed since, ended
/// otherwise or is gone, and nothing is written.
async fn rewritten(
    connection: &mut PgConnection,
    tenant: &Uuid,
    c: &ExecutionColumns<'_>,
    read: OffsetDateTime,
) -> Result<Option<OffsetDateTime>, sqlx::Error> {
    let stored = sqlx::query_file_scalar!(
        "queries/workflow_executions/save_unchanged_since.sql",
        tenant,
        c.id,
        read,
        c.steps,
        c.status,
        c.cancelled_by,
        c.deadline,
        c.updated_at,
    )
    .fetch_optional(&mut *connection)
    .await?;
    let Some(at) = stored else {
        return Ok(None);
    };
    hold_agent_runs(connection, tenant, c).await?;
    Ok(Some(at))
}

/// Puts exactly the agent runs `c` waits on beside the run.
async fn hold_agent_runs(
    connection: &mut PgConnection,
    tenant: &Uuid,
    c: &ExecutionColumns<'_>,
) -> Result<(), sqlx::Error> {
    sqlx::query_file!(
        "queries/workflow_execution_runs/release.sql",
        tenant,
        c.id,
        &c.agent_runs
    )
    .execute(&mut *connection)
    .await?;
    sqlx::query_file!(
        "queries/workflow_execution_runs/hold.sql",
        tenant,
        c.id,
        &c.agent_runs
    )
    .execute(connection)
    .await?;
    Ok(())
}

#[async_trait]
impl WorkflowExecutionStore for PgWorkflowExecutionStore {
    async fn latest_for_workflows(
        &self,
        tenant_id: &ScopedTenant,
        workflow_ids: &[WorkflowId],
    ) -> Result<Vec<WorkflowExecution<ResolvedTenant>>, DomainError> {
        if workflow_ids.is_empty() {
            return Ok(Vec::new());
        }
        let ids: Vec<_> = workflow_ids.iter().map(|id| *id.as_uuid()).collect();
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    ExecutionRecord,
                    "queries/workflow_executions/latest_of_workflows.sql",
                    tenant_id.as_uuid(),
                    &ids
                )
                .fetch_all(connection)
                .await
            },
        )
        .await?;
        rebuilt_all(records)
    }

    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &WorkflowExecutionId,
    ) -> Result<Option<WorkflowExecution<ResolvedTenant>>, DomainError> {
        let ids = [*id.as_uuid()];
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| records_of(connection, tenant_id.as_uuid(), &ids).await,
        )
        .await?;
        Ok(rebuilt_all(records)?.into_iter().next())
    }

    async fn find_by_agent_run(
        &self,
        tenant_id: &ScopedTenant,
        run_id: &AgentRunId,
    ) -> Result<Option<WorkflowExecution<ResolvedTenant>>, DomainError> {
        let record = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    ExecutionRecord,
                    "queries/workflow_executions/by_agent_run.sql",
                    tenant_id.as_uuid(),
                    run_id.as_uuid()
                )
                .fetch_optional(connection)
                .await
            },
        )
        .await?;
        record.map(ExecutionRecord::into_execution).transpose()
    }

    async fn list_for_workflow(
        &self,
        tenant_id: &ScopedTenant,
        workflow_id: &WorkflowId,
        kind: RunKind,
        page: &PageRequest,
    ) -> Result<Page<WorkflowExecution<ResolvedTenant>>, DomainError> {
        let listed = PageQuery::ids("id", "workflow_executions")
            .filter("tenant_id = ?", *tenant_id.as_uuid())
            .filter("workflow_id = ?", *workflow_id.as_uuid())
            .filter("mode = ?", ModeKind::listed(kind).word())
            .keep("pass_of IS NULL");
        self.newest_first(tenant_id, listed, page).await
    }

    async fn list_passes(
        &self,
        tenant_id: &ScopedTenant,
        execution_id: &WorkflowExecutionId,
        page: &PageRequest,
    ) -> Result<Page<WorkflowExecution<ResolvedTenant>>, DomainError> {
        let listed = PageQuery::ids("id", "workflow_executions")
            .filter("tenant_id = ?", *tenant_id.as_uuid())
            .filter("pass_of = ?", *execution_id.as_uuid());
        self.newest_first(tenant_id, listed, page).await
    }

    async fn list_designed(
        &self,
        tenant_id: &ScopedTenant,
        kind: RunKind,
        page: &PageRequest,
    ) -> Result<Page<WorkflowExecution<ResolvedTenant>>, DomainError> {
        let listed = PageQuery::ids("e.id", DESIGNED_RUNS)
            .filter("e.tenant_id = ?", *tenant_id.as_uuid())
            .filter("e.mode = ?", ModeKind::listed(kind).word())
            .keep("w.origin = 'designed'")
            .keep("e.pass_of IS NULL");
        self.newest_first(tenant_id, listed, page).await
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        execution: &WorkflowExecution<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let columns = ExecutionColumns::of(execution)?;
        let saved = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| written(connection, tenant_id.as_uuid(), &columns).await,
        )
        .await?;
        match saved {
            Saved::Written => Ok(()),
            Saved::AlreadyEnded => Err(DomainError::conflict(message!(
                "infra-the-execution-already-ended-and-ends",
                "the execution already ended, and ends only once"
            ))),
        }
    }

    async fn save_unchanged_since(
        &self,
        tenant_id: &ScopedTenant,
        execution: &WorkflowExecution<ResolvedTenant>,
        read: ExecutionVersion,
    ) -> Result<ExecutionVersion, DomainError> {
        let columns = ExecutionColumns::of(execution)?;
        let stored = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                rewritten(connection, tenant_id.as_uuid(), &columns, read.changed_at()).await
            },
        )
        .await?;
        stored.map(ExecutionVersion::stored).ok_or_else(|| {
            DomainError::conflict(message!(
                "infra-the-execution-changed-since-it-was",
                "the execution changed since it was read, or is gone"
            ))
        })
    }

    async fn delete(
        &self,
        tenant_id: &ScopedTenant,
        id: &WorkflowExecutionId,
    ) -> Result<(), DomainError> {
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/workflow_executions/delete.sql",
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

    async fn purge_ended_before(
        &self,
        tenant_id: &ScopedTenant,
        cutoff: OffsetDateTime,
    ) -> Result<u64, DomainError> {
        let mut removed = 0_u64;
        loop {
            let batch = scoped(
                &self.databases,
                RowScope::from(tenant_id),
                async |connection| {
                    sqlx::query_file!(
                        "queries/workflow_executions/purge_ended.sql",
                        tenant_id.as_uuid(),
                        cutoff,
                        PURGED_AT_ONCE
                    )
                    .execute(connection)
                    .await
                },
            )
            .await?
            .rows_affected();
            removed = removed.saturating_add(batch);
            if batch < PURGED_AT_ONCE.unsigned_abs() {
                return Ok(removed);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::listing::Limit;
    use ianua_app::ports::workflows::WorkflowStore;
    use ianua_domain::domains::data_classification::level::DataClassLevel;
    use ianua_domain::domains::workflows::data::FlowData;
    use ianua_domain::domains::workflows::design::node::{NodeKey, Port};
    use ianua_domain::domains::workflows::design::workflow::Workflow;
    use ianua_domain::domains::workflows::execution::record::ExecutionEnd;
    use ianua_domain::domains::workflows::execution::step::{Holding, StepState, Underway};
    use ianua_domain::domains::workflows::execution::{
        Cause, ExecutionStatus, PassOf, RestartFrom, StoredMode, WorkflowExecutionRow,
    };
    use ianua_domain::shared::events::chain::{ChainDepth, EventOrigin};
    use ianua_domain::types::event_type::IdentityEvent;
    use ianua_domain::types::{EventType, PrincipalRef, TenantId, UserId};

    use super::*;
    use crate::postgres::workflows::PgWorkflowStore;
    use crate::test_support::TestDb;
    use crate::test_support::rows::agents::run::saved_run;
    use crate::test_support::rows::at;
    use crate::test_support::rows::workflows::{flow_row, published_row, running_row};

    struct Fixture {
        db: TestDb,
        store: PgWorkflowExecutionStore,
        workflows: PgWorkflowStore,
        tenant: ScopedTenant,
        report: Workflow<ResolvedTenant>,
    }

    /// A fresh database, one tenant, its published report workflow, and the
    /// store on it.
    async fn fixture() -> Fixture {
        let db = TestDb::fresh().await;
        let tenant = ScopedTenant::for_background(TenantId::new());
        let workflows = PgWorkflowStore::new(Arc::clone(&db.databases));
        let report = Workflow::reconstitute(published_row("report", 0)).unwrap();
        workflows.insert(&tenant, &report).await.unwrap();
        Fixture {
            store: PgWorkflowExecutionStore::new(Arc::clone(&db.databases)),
            workflows,
            tenant,
            report,
            db,
        }
    }

    fn execution(row: WorkflowExecutionRow) -> WorkflowExecution<ResolvedTenant> {
        WorkflowExecution::reconstitute(row).unwrap()
    }

    /// `row`, its one step finished.
    fn succeeded(row: WorkflowExecutionRow) -> WorkflowExecutionRow {
        WorkflowExecutionRow {
            steps: vec![StepState::Succeeded {
                output: FlowData::null(),
                exposure: DataClassLevel::Internal,
                seen: Vec::new(),
                port: Port::Next,
                holds: Holding::ForGood,
            }],
            status: ExecutionStatus::Ended(ExecutionEnd::Succeeded),
            ..row
        }
    }

    fn first(limit: u32) -> PageRequest {
        PageRequest::first(Limit::new(limit).unwrap())
    }

    impl Fixture {
        /// Saves a real report run at the requested creation time with its own agent run.
        async fn running(&self, created: i64) -> WorkflowExecution<ResolvedTenant> {
            self.saved(running_row(&self.report, self.agent_run().await, created))
                .await
        }

        /// Saves a loop pass while preserving its parent and step identity.
        async fn pass(&self, of: PassOf, created: i64) -> WorkflowExecution<ResolvedTenant> {
            self.saved(WorkflowExecutionRow {
                pass: Some(of),
                ..running_row(&self.report, self.agent_run().await, created)
            })
            .await
        }

        /// Lists the report's runs with the selected real or test mode.
        async fn listed(
            &self,
            kind: RunKind,
            page: &PageRequest,
        ) -> Page<WorkflowExecution<ResolvedTenant>> {
            self.store
                .list_for_workflow(&self.tenant, self.report.id(), kind, page)
                .await
                .unwrap()
        }

        /// Lists designed runs in the selected mode, excluding agent flows and loop passes.
        async fn designed(&self, kind: RunKind) -> Page<WorkflowExecution<ResolvedTenant>> {
            self.store
                .list_designed(&self.tenant, kind, &first(10))
                .await
                .unwrap()
        }

        /// Reads the latest runs for the selected tenant and workflows.
        async fn latest(
            &self,
            tenant: &ScopedTenant,
            workflows: &[WorkflowId],
        ) -> Vec<WorkflowExecution<ResolvedTenant>> {
            self.store
                .latest_for_workflows(tenant, workflows)
                .await
                .unwrap()
        }

        /// Attempts a version-checked write, leaving refusal assertions to the caller.
        async fn replace(
            &self,
            execution: &WorkflowExecution<ResolvedTenant>,
            read: ExecutionVersion,
        ) -> Result<ExecutionVersion, DomainError> {
            self.store
                .save_unchanged_since(&self.tenant, execution, read)
                .await
        }

        /// Lists the passes belonging to one parent execution.
        async fn passes(
            &self,
            parent: &WorkflowExecutionId,
        ) -> Page<WorkflowExecution<ResolvedTenant>> {
            self.store
                .list_passes(&self.tenant, parent, &first(10))
                .await
                .unwrap()
        }

        async fn agent_run(&self) -> AgentRunId {
            *saved_run(&self.db.databases, &self.tenant).await.id()
        }

        async fn saved(&self, row: WorkflowExecutionRow) -> WorkflowExecution<ResolvedTenant> {
            let kept = execution(row);
            self.store.save(&self.tenant, &kept).await.unwrap();
            kept
        }

        async fn found(&self, id: &WorkflowExecutionId) -> WorkflowExecution<ResolvedTenant> {
            self.store
                .find_by_id(&self.tenant, id)
                .await
                .unwrap()
                .unwrap()
        }

        async fn waiting_on(&self, run: &AgentRunId) -> Option<WorkflowExecutionId> {
            self.store
                .find_by_agent_run(&self.tenant, run)
                .await
                .unwrap()
                .map(|found| *found.id())
        }
    }

    fn ids(page: &Page<WorkflowExecution<ResolvedTenant>>) -> Vec<WorkflowExecutionId> {
        page.items.iter().map(|kept| *kept.id()).collect()
    }

    /// A saved run is found by its id with everything it was started with
    /// and where its steps stand, and another tenant does not find it.
    #[tokio::test]
    async fn a_saved_run_is_found_only_by_its_tenant() {
        let fx = fixture().await;
        let run = fx
            .saved(running_row(&fx.report, fx.agent_run().await, 10))
            .await;
        let other = ScopedTenant::for_background(TenantId::new());

        let found = fx.found(run.id()).await;
        let theirs = fx.store.find_by_id(&other, run.id()).await.unwrap();
        let unknown = fx
            .store
            .find_by_id(&fx.tenant, &WorkflowExecutionId::new())
            .await
            .unwrap();

        assert_eq!(found.graph(), run.graph());
        assert_eq!(found.acting_for(), run.acting_for());
        assert_eq!(found.input(), run.input());
        assert_eq!(found.cause(), Cause::Manual);
        assert!(found.steps().eq(run.steps()));
        assert_eq!(found.deadline(), run.deadline());
        assert!(theirs.is_none());
        assert!(unknown.is_none());
    }

    /// A pass of a loop is kept naming the run and loop step it belongs to,
    /// read back so, and listed among that run's passes. The lists of
    /// runs, and the latest run of the workflow, leave it out. Stopped with
    /// its loop, it reads back as ended so.
    #[tokio::test]
    async fn a_pass_names_its_loop_and_lists_leave_it_out() {
        let fx = fixture().await;
        let run = fx.running(10).await;
        let of = PassOf {
            execution: *run.id(),
            step: NodeKey::new("each").unwrap(),
            index: 2,
        };
        let pass = fx.pass(of.clone(), 20).await;

        let found = fx.found(pass.id()).await;
        let listed = fx.listed(RunKind::Real, &first(10)).await;
        let designed = fx.designed(RunKind::Real).await;
        let latest = fx.latest(&fx.tenant, &[*fx.report.id()]).await;
        let _later = ianua_domain::shared::clock::freeze(at(30));
        let mut stopped = found.clone();
        stopped.stop_pass().unwrap();
        fx.store.save(&fx.tenant, &stopped).await.unwrap();

        let passes = fx.passes(run.id()).await;
        assert_eq!(found.pass(), Some(&of));
        assert_eq!(ids(&passes), [*pass.id()]);
        assert_eq!(ids(&listed), [*run.id()]);
        assert_eq!(ids(&designed), [*run.id()]);
        assert_eq!(
            latest.iter().map(|kept| *kept.id()).collect::<Vec<_>>(),
            [*run.id()]
        );
        assert_eq!(
            fx.found(pass.id()).await.status(),
            ExecutionStatus::Ended(ExecutionEnd::LoopEnded)
        );
    }

    /// Ann tests her workflow once and it runs for real once. The test is
    /// kept with the step it stood in for and listed only among tests; the
    /// real run only among runs, and only it counts as the latest.
    #[tokio::test]
    async fn a_test_is_kept_and_listed_apart_from_real_runs() {
        let fx = fixture().await;
        let real = fx.running(10).await;
        let stood_in = fx
            .report
            .graph()
            .every_node()
            .next()
            .expect("the report has a step")
            .key()
            .clone();
        let test = fx
            .saved(WorkflowExecutionRow {
                mode: StoredMode::Test {
                    stand_ins: vec![stood_in.clone()],
                },
                ..running_row(&fx.report, fx.agent_run().await, 20)
            })
            .await;

        let found = fx.found(test.id()).await;
        let runs = fx.listed(RunKind::Real, &first(10)).await;
        let tests = fx.designed(RunKind::Tests).await;
        let latest = fx.latest(&fx.tenant, &[*fx.report.id()]).await;

        assert!(found.mode().stands_in(&stood_in));
        assert_eq!(ids(&runs), [*real.id()]);
        assert_eq!(ids(&tests), [*test.id()]);
        assert_eq!(
            latest.iter().map(|kept| *kept.id()).collect::<Vec<_>>(),
            [*real.id()]
        );
    }

    /// A run is found by the agent run its step waits on, and no longer
    /// once the step has finished.
    #[tokio::test]
    async fn a_run_is_found_by_the_agent_run_it_waits_on() {
        let fx = fixture().await;
        let agent_run = fx.agent_run().await;
        let row = running_row(&fx.report, agent_run, 10);
        let id = row.id;
        fx.saved(row).await;
        let while_running = fx.waiting_on(&agent_run).await;

        fx.saved(succeeded(WorkflowExecutionRow {
            id,
            updated_at: at(20),
            ..running_row(&fx.report, agent_run, 10)
        }))
        .await;

        assert_eq!(while_running, Some(id));
        assert_eq!(fx.waiting_on(&agent_run).await, None);
        assert_eq!(
            fx.found(&id).await.status(),
            ExecutionStatus::Ended(ExecutionEnd::Succeeded)
        );
    }

    /// After a completed run is saved, saving a running copy against the
    /// same read version conflicts. The run stays successful and no longer
    /// waits on the agent run.
    #[tokio::test]
    async fn a_change_read_before_another_is_refused() {
        let fx = fixture().await;
        let agent_run = fx.agent_run().await;
        let row = running_row(&fx.report, agent_run, 10);
        let id = row.id;
        fx.saved(row).await;
        let read = ExecutionVersion::of(&fx.found(&id).await);
        let finished = execution(succeeded(WorkflowExecutionRow {
            id,
            updated_at: at(20),
            ..running_row(&fx.report, agent_run, 10)
        }));
        let stale = execution(WorkflowExecutionRow {
            id,
            updated_at: at(20),
            ..running_row(&fx.report, agent_run, 10)
        });

        let first = fx.replace(&finished, read).await;
        let second = fx.replace(&stale, read).await;

        assert!(first.is_ok(), "{first:?}");
        assert!(
            matches!(second, Err(DomainError::Conflict(_))),
            "{second:?}"
        );
        assert_eq!(
            fx.found(&id).await.status(),
            ExecutionStatus::Ended(ExecutionEnd::Succeeded)
        );
        assert_eq!(fx.waiting_on(&agent_run).await, None);
    }

    /// Each change over a version moves it on, even one that carries the
    /// same time as the last: the version given back lets the next change
    /// through, and the one read before does not.
    #[tokio::test]
    async fn every_change_moves_the_version_on() {
        let fx = fixture().await;
        let agent_run = fx.agent_run().await;
        let row = running_row(&fx.report, agent_run, 10);
        let id = row.id;
        let kept = fx.saved(row).await;
        let read = ExecutionVersion::of(&fx.found(&id).await);

        let moved = fx
            .store
            .save_unchanged_since(&fx.tenant, &kept, read)
            .await
            .unwrap();
        let again = fx
            .store
            .save_unchanged_since(&fx.tenant, &kept, moved)
            .await;
        let stale = fx.store.save_unchanged_since(&fx.tenant, &kept, read).await;

        assert!(moved.changed_at() > read.changed_at());
        assert!(again.is_ok(), "{again:?}");
        assert!(matches!(stale, Err(DomainError::Conflict(_))), "{stale:?}");
    }

    /// A run nobody stored cannot be changed over a version: the change is
    /// refused and nothing is written.
    #[tokio::test]
    async fn a_change_to_a_run_never_stored_is_refused() {
        let fx = fixture().await;
        let run = execution(running_row(&fx.report, fx.agent_run().await, 10));

        let saved = fx
            .store
            .save_unchanged_since(&fx.tenant, &run, ExecutionVersion::of(&run))
            .await;

        assert!(matches!(saved, Err(DomainError::Conflict(_))), "{saved:?}");
        assert!(
            fx.store
                .find_by_id(&fx.tenant, run.id())
                .await
                .unwrap()
                .is_none()
        );
    }

    /// A run someone stopped keeps who stopped it, and is still found by
    /// the agent run it abandoned, whose late result is still recorded.
    #[tokio::test]
    async fn a_cancelled_run_keeps_who_stopped_it() {
        let fx = fixture().await;
        let agent_run = fx.agent_run().await;
        let by = PrincipalRef::User(UserId::new());
        let row = running_row(&fx.report, agent_run, 10);
        let cancelled = fx
            .saved(WorkflowExecutionRow {
                steps: vec![StepState::Abandoned {
                    exposure: DataClassLevel::Internal,
                    seen: Vec::new(),
                    underway: Underway::AgentRun(agent_run),
                }],
                status: ExecutionStatus::Ended(ExecutionEnd::Cancelled(by)),
                ..row
            })
            .await;

        let found = fx.found(cancelled.id()).await;

        assert_eq!(
            found.status(),
            ExecutionStatus::Ended(ExecutionEnd::Cancelled(by))
        );
        assert_eq!(fx.waiting_on(&agent_run).await, Some(*cancelled.id()));
    }

    /// Saving a running copy after the run was cancelled returns a conflict
    /// and preserves the stored cancellation and who cancelled it.
    #[tokio::test]
    async fn a_save_read_before_the_run_ended_is_refused() {
        let fx = fixture().await;
        let agent_run = fx.agent_run().await;
        let by = PrincipalRef::User(UserId::new());
        let read_before = execution(running_row(&fx.report, agent_run, 10));
        fx.store.save(&fx.tenant, &read_before).await.unwrap();
        fx.saved(WorkflowExecutionRow {
            id: *read_before.id(),
            steps: vec![StepState::Abandoned {
                exposure: DataClassLevel::Internal,
                seen: Vec::new(),
                underway: Underway::AgentRun(agent_run),
            }],
            status: ExecutionStatus::Ended(ExecutionEnd::Cancelled(by)),
            updated_at: at(20),
            ..running_row(&fx.report, agent_run, 10)
        })
        .await;

        let late = fx.store.save(&fx.tenant, &read_before).await;

        assert!(matches!(late, Err(DomainError::Conflict(_))));
        assert_eq!(
            fx.found(read_before.id()).await.status(),
            ExecutionStatus::Ended(ExecutionEnd::Cancelled(by))
        );
    }

    /// A run started again names the run it picks up from and where, and a
    /// run started by another run's event keeps how deep in the chain it
    /// is.
    #[tokio::test]
    async fn what_started_a_run_reads_back() {
        let fx = fixture().await;
        let failed = fx
            .saved(running_row(&fx.report, fx.agent_run().await, 10))
            .await;
        let restart = Cause::Restart {
            of: *failed.id(),
            from: RestartFrom::FailedStep,
        };
        let event = Cause::Event {
            event: EventType::Identity(IdentityEvent::UserRegistered),
            origin: EventOrigin::Execution(ChainDepth::from_stored(2).unwrap()),
        };
        let again = fx
            .saved(WorkflowExecutionRow {
                cause: restart,
                ..running_row(&fx.report, fx.agent_run().await, 11)
            })
            .await;
        let chained = fx
            .saved(WorkflowExecutionRow {
                cause: event,
                chain_depth: ChainDepth::from_stored(3).unwrap(),
                ..running_row(&fx.report, fx.agent_run().await, 12)
            })
            .await;

        assert_eq!(fx.found(again.id()).await.cause(), restart);
        assert_eq!(fx.found(chained.id()).await.cause(), event);
        assert_eq!(fx.found(chained.id()).await.chain_depth().get(), 3);
    }

    /// A workflow's runs are read page by page, newest first, and another
    /// workflow's are not among them.
    #[tokio::test]
    async fn a_workflows_runs_are_listed_newest_first() {
        let fx = fixture().await;
        let older = fx
            .saved(running_row(&fx.report, fx.agent_run().await, 10))
            .await;
        let newer = fx
            .saved(running_row(&fx.report, fx.agent_run().await, 20))
            .await;
        let budget = Workflow::reconstitute(published_row("budget", 0)).unwrap();
        fx.workflows.insert(&fx.tenant, &budget).await.unwrap();
        fx.saved(running_row(&budget, fx.agent_run().await, 30))
            .await;

        let page_one = fx
            .store
            .list_for_workflow(&fx.tenant, fx.report.id(), RunKind::Real, &first(1))
            .await
            .unwrap();
        let after = PageRequest::new(page_one.next.clone(), Limit::new(1).unwrap());
        let page_two = fx
            .store
            .list_for_workflow(&fx.tenant, fx.report.id(), RunKind::Real, &after)
            .await
            .unwrap();

        assert_eq!(ids(&page_one), [*newer.id()]);
        assert_eq!(ids(&page_two), [*older.id()]);
        assert!(!page_two.has_next());
    }

    /// A batch selects the newest run per requested workflow, breaking equal
    /// creation times by id, while omitting absent and foreign tenant runs.
    #[tokio::test]
    async fn latest_runs_are_batched_and_tenant_scoped() {
        let fx = fixture().await;
        let older = fx.running(10).await;
        let first = fx.running(20).await;
        let tied = fx.running(20).await;
        let expected = if first.id().as_uuid() > tied.id().as_uuid() {
            *first.id()
        } else {
            *tied.id()
        };
        let other = Workflow::reconstitute(published_row("other", 0)).unwrap();
        fx.workflows.insert(&fx.tenant, &other).await.unwrap();
        let other_run = fx
            .saved(running_row(&other, fx.agent_run().await, 30))
            .await;
        let requested = [
            *fx.report.id(),
            *other.id(),
            *fx.report.id(),
            WorkflowId::new(),
        ];

        let found = fx.latest(&fx.tenant, &requested).await;

        assert_eq!(found.len(), 2);
        let ids: Vec<_> = found.iter().map(|run| *run.id()).collect();
        assert!(ids.contains(&expected));
        assert!(ids.contains(other_run.id()));
        assert!(!ids.contains(older.id()));
        assert!(fx.latest(&fx.tenant, &[]).await.is_empty());
        let foreign = ScopedTenant::for_background(TenantId::new());
        assert!(fx.latest(&foreign, &requested).await.is_empty());
    }

    /// The runs of designed workflows are listed and an agent flow's run is
    /// left out, as its flow is.
    #[tokio::test]
    async fn the_runs_of_agent_flows_are_left_out() {
        let fx = fixture().await;
        let designed = fx
            .saved(running_row(&fx.report, fx.agent_run().await, 10))
            .await;
        let flow = Workflow::reconstitute(flow_row("digest", 0)).unwrap();
        fx.workflows.insert(&fx.tenant, &flow).await.unwrap();
        fx.saved(running_row(&flow, fx.agent_run().await, 20)).await;

        let listed = fx
            .store
            .list_designed(&fx.tenant, RunKind::Real, &first(10))
            .await
            .unwrap();

        assert_eq!(ids(&listed), [*designed.id()]);
    }

    /// Deleting an agent flow takes its run with it, and a run deleted on
    /// its own is gone.
    #[tokio::test]
    async fn a_run_goes_with_its_agent_flow() {
        let fx = fixture().await;
        let flow = Workflow::reconstitute(flow_row("digest", 0)).unwrap();
        fx.workflows.insert(&fx.tenant, &flow).await.unwrap();
        let flow_run = fx.saved(running_row(&flow, fx.agent_run().await, 10)).await;
        let run = fx
            .saved(running_row(&fx.report, fx.agent_run().await, 20))
            .await;

        fx.workflows
            .delete_flow(&fx.tenant, flow.id())
            .await
            .unwrap();
        fx.store.delete(&fx.tenant, run.id()).await.unwrap();

        for gone in [flow_run.id(), run.id()] {
            assert!(
                fx.store
                    .find_by_id(&fx.tenant, gone)
                    .await
                    .unwrap()
                    .is_none()
            );
        }
    }

    /// Saving a run of an unknown workflow version returns an
    /// infrastructure error.
    #[tokio::test]
    async fn a_run_of_an_unknown_version_is_refused() {
        let fx = fixture().await;
        let unknown = Workflow::reconstitute(published_row("unknown", 0)).unwrap();

        let saved = fx
            .store
            .save(
                &fx.tenant,
                &execution(running_row(&unknown, fx.agent_run().await, 10)),
            )
            .await;

        assert!(matches!(saved, Err(DomainError::Infrastructure(_))));
    }

    /// A tenant with a database of its own keeps its runs there, found by
    /// id and by the agent run they wait on.
    #[tokio::test]
    async fn a_tenant_with_its_own_database_keeps_its_runs_there() {
        let fx = fixture().await;
        let own = TestDb::fresh().await;
        let apart = ScopedTenant::for_background(TenantId::new());
        fx.db.databases.register(*apart, own.as_dedicated());
        fx.workflows.insert(&apart, &fx.report).await.unwrap();
        let agent_run = *saved_run(&fx.db.databases, &apart).await.id();
        let run = execution(running_row(&fx.report, agent_run, 10));

        fx.store.save(&apart, &run).await.unwrap();

        let in_own = PgWorkflowExecutionStore::new(Arc::clone(&own.databases));
        let found = in_own.find_by_agent_run(&apart, &agent_run).await.unwrap();
        assert_eq!(found.map(|kept| *kept.id()), Some(*run.id()));
        assert!(
            fx.store
                .find_by_id(&fx.tenant, run.id())
                .await
                .unwrap()
                .is_none()
        );
    }

    /// Reading a run whose stored state omits its step returns an
    /// infrastructure error.
    #[tokio::test]
    async fn a_row_that_breaks_a_rule_of_the_run_is_refused() {
        let fx = fixture().await;
        let run = fx
            .saved(running_row(&fx.report, fx.agent_run().await, 10))
            .await;
        fx.db
            .tamper("UPDATE workflow_executions SET steps = '{\"v\": 1, \"value\": []}'")
            .await;

        let read = fx.store.find_by_id(&fx.tenant, run.id()).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }

    /// `row`, ended successfully at the instant the fixture's clock calls
    /// `updated`.
    fn ended_at(row: WorkflowExecutionRow, updated: i64) -> WorkflowExecutionRow {
        WorkflowExecutionRow {
            updated_at: at(updated),
            ..succeeded(row)
        }
    }

    impl Fixture {
        /// Saves a report run that ended at `updated`.
        async fn ended(&self, updated: i64) -> WorkflowExecution<ResolvedTenant> {
            let row = running_row(&self.report, self.agent_run().await, 1);
            self.saved(ended_at(row, updated)).await
        }

        /// Whether the run `id` is still kept.
        async fn kept(&self, id: &WorkflowExecutionId) -> bool {
            self.store
                .find_by_id(&self.tenant, id)
                .await
                .unwrap()
                .is_some()
        }
    }

    /// A run that ended an hour before the cutoff goes and one that ended
    /// an hour after stays, as does one still running however old; another
    /// tenant's run is out of reach.
    #[tokio::test]
    async fn runs_ended_before_the_cutoff_go_and_the_rest_stay() {
        let fx = fixture().await;
        let past = fx.ended(100).await;
        let inside = fx.ended(300).await;
        let waiting = fx.running(1).await;

        let removed = fx
            .store
            .purge_ended_before(&fx.tenant, at(200))
            .await
            .unwrap();

        assert_eq!(removed, 1);
        assert!(!fx.kept(past.id()).await);
        assert!(fx.kept(inside.id()).await);
        assert!(fx.kept(waiting.id()).await);
    }

    /// An old run went on from by a later restart that is still kept
    /// stays until that restart has gone, so its removal never takes the
    /// restart with it.
    #[tokio::test]
    async fn a_run_restarted_from_stays_until_its_restart_is_gone() {
        let fx = fixture().await;
        let first = fx.ended(100).await;
        let restart = Cause::Restart {
            of: *first.id(),
            from: RestartFrom::FailedStep,
        };
        let row = running_row(&fx.report, fx.agent_run().await, 1);
        let again = fx
            .saved(WorkflowExecutionRow {
                cause: restart,
                ..ended_at(row, 300)
            })
            .await;

        let during = fx
            .store
            .purge_ended_before(&fx.tenant, at(200))
            .await
            .unwrap();
        assert_eq!(during, 0);
        assert!(fx.kept(first.id()).await);

        let restart_gone = fx
            .store
            .purge_ended_before(&fx.tenant, at(400))
            .await
            .unwrap();
        assert_eq!(restart_gone, 1);
        assert!(!fx.kept(again.id()).await);
        assert!(
            fx.kept(first.id()).await,
            "it goes only once nothing follows it"
        );

        let first_gone = fx
            .store
            .purge_ended_before(&fx.tenant, at(400))
            .await
            .unwrap();

        assert_eq!(first_gone, 1);
        assert!(!fx.kept(first.id()).await);
    }

    /// A run's finished passes go with it; a run with a pass still working
    /// stays until the pass ends.
    #[tokio::test]
    async fn a_run_waits_for_its_working_passes_and_goes_with_its_ended_ones() {
        let fx = fixture().await;
        let run = fx.ended(100).await;
        let working = fx
            .pass(
                PassOf {
                    execution: *run.id(),
                    step: NodeKey::new("each").unwrap(),
                    index: 0,
                },
                1,
            )
            .await;

        let during = fx
            .store
            .purge_ended_before(&fx.tenant, at(200))
            .await
            .unwrap();
        assert_eq!(during, 0, "a pass still works");
        assert!(fx.kept(run.id()).await);
        let row = running_row(&fx.report, fx.agent_run().await, 1);
        let ended_pass = fx
            .saved(WorkflowExecutionRow {
                id: *working.id(),
                pass: working.pass().cloned(),
                ..ended_at(row, 150)
            })
            .await;

        let after = fx
            .store
            .purge_ended_before(&fx.tenant, at(200))
            .await
            .unwrap();

        assert_eq!(after, 1, "the pass goes with its run, not on its own");
        assert!(!fx.kept(run.id()).await);
        assert!(!fx.kept(ended_pass.id()).await);
    }
}
