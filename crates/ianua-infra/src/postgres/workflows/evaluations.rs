//! Workflows' sample cases and their evaluations, each table row under
//! row-level security. A change to an evaluation is written only over the
//! row as it was read, and ended evaluations are purged a batch at a time.

mod record;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::workflows::{EvaluationSetStore, EvaluationStore};
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::workflows::evaluation::run::Evaluation;
use ianua_domain::domains::workflows::evaluation::set::EvaluationSet;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{EvaluationId, WorkflowId};
use time::OffsetDateTime;

use self::record::{EvaluationColumns, EvaluationRecord, ProgressColumns, SetColumns, SetRecord};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The most ended evaluations of one tenant one purge removes at a time.
const PURGED_AT_ONCE: i64 = 1_000;

/// The Postgres store of workflows' sample cases.
pub struct PgEvaluationSetStore {
    databases: Arc<Databases>,
}

impl TenantScoped for PgEvaluationSetStore {}

impl PgEvaluationSetStore {
    /// A store keeping sample cases in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

#[async_trait]
impl EvaluationSetStore for PgEvaluationSetStore {
    async fn find(
        &self,
        tenant_id: &ScopedTenant,
        workflow_id: &WorkflowId,
    ) -> Result<Option<EvaluationSet<ResolvedTenant>>, DomainError> {
        let record = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    SetRecord,
                    "queries/evaluation_sets/find.sql",
                    tenant_id.as_uuid(),
                    workflow_id.as_uuid()
                )
                .fetch_optional(connection)
                .await
            },
        )
        .await?;
        record.map(SetRecord::into_set).transpose()
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        set: &EvaluationSet<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let c = SetColumns::of(set)?;
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/evaluation_sets/save.sql",
                    tenant_id.as_uuid(),
                    c.workflow_id,
                    c.cases,
                    c.publish_gate,
                    c.edited_by,
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
}

/// The Postgres store of evaluations.
pub struct PgEvaluationStore {
    databases: Arc<Databases>,
}

impl TenantScoped for PgEvaluationStore {}

impl PgEvaluationStore {
    /// A store keeping evaluations in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

#[async_trait]
impl EvaluationStore for PgEvaluationStore {
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &EvaluationId,
    ) -> Result<Option<Evaluation<ResolvedTenant>>, DomainError> {
        let record = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    EvaluationRecord,
                    "queries/evaluations/by_id.sql",
                    tenant_id.as_uuid(),
                    id.as_uuid()
                )
                .fetch_optional(connection)
                .await
            },
        )
        .await?;
        record.map(EvaluationRecord::into_evaluation).transpose()
    }

    async fn latest_of(
        &self,
        tenant_id: &ScopedTenant,
        workflow_id: &WorkflowId,
        limit: u32,
    ) -> Result<Vec<Evaluation<ResolvedTenant>>, DomainError> {
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    EvaluationRecord,
                    "queries/evaluations/latest_of.sql",
                    tenant_id.as_uuid(),
                    workflow_id.as_uuid(),
                    i64::from(limit)
                )
                .fetch_all(connection)
                .await
            },
        )
        .await?;
        records
            .into_iter()
            .map(EvaluationRecord::into_evaluation)
            .collect()
    }

    async fn insert(
        &self,
        tenant_id: &ScopedTenant,
        evaluation: &Evaluation<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let c = EvaluationColumns::of(evaluation)?;
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/evaluations/insert.sql",
                    c.id,
                    tenant_id.as_uuid(),
                    c.workflow_id,
                    c.version,
                    c.revision,
                    c.cases,
                    c.outcomes,
                    c.state,
                    c.started_by,
                    c.deadline,
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

    async fn save_unchanged_since(
        &self,
        tenant_id: &ScopedTenant,
        evaluation: &Evaluation<ResolvedTenant>,
        read_at: OffsetDateTime,
    ) -> Result<(), DomainError> {
        let c = ProgressColumns::of(evaluation)?;
        let done = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/evaluations/save_unchanged.sql",
                    tenant_id.as_uuid(),
                    evaluation.id().as_uuid(),
                    c.outcomes,
                    c.state,
                    c.updated_at,
                    read_at,
                )
                .execute(connection)
                .await
            },
        )
        .await?;
        if done.rows_affected() == 0 {
            return Err(DomainError::conflict(message!(
                "workflows-the-evaluation-changed-since-it-was-read",
                "the evaluation changed since it was read"
            )));
        }
        Ok(())
    }

    async fn overdue(
        &self,
        tenant_id: &ScopedTenant,
        now: OffsetDateTime,
        limit: u32,
    ) -> Result<Vec<Evaluation<ResolvedTenant>>, DomainError> {
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    EvaluationRecord,
                    "queries/evaluations/overdue.sql",
                    tenant_id.as_uuid(),
                    now,
                    i64::from(limit)
                )
                .fetch_all(connection)
                .await
            },
        )
        .await?;
        records
            .into_iter()
            .map(EvaluationRecord::into_evaluation)
            .collect()
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
                        "queries/evaluations/purge_ended.sql",
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
            if batch < u64::try_from(PURGED_AT_ONCE).unwrap_or(u64::MAX) {
                return Ok(removed);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::ports::workflows::WorkflowStore as _;
    use ianua_domain::domains::authorization::permission::{SystemPermission, WorkflowAction};
    use ianua_domain::domains::data_classification::level::DataClassLevel;
    use ianua_domain::domains::workflows::control::WorkflowControl;
    use ianua_domain::domains::workflows::data::{DataPath, FlowData};
    use ianua_domain::domains::workflows::design::workflow::Workflow;
    use ianua_domain::domains::workflows::evaluation::case::{
        CaseName, CaseParams, EvaluationCase,
    };
    use ianua_domain::domains::workflows::evaluation::check::{Expectation, ExpectedText};
    use ianua_domain::domains::workflows::evaluation::outcome::Verdict;
    use ianua_domain::domains::workflows::evaluation::run::EvaluationState;
    use ianua_domain::domains::workflows::evaluation::set::{PublishGate, SetParams};
    use ianua_domain::shared::model::aggregate::Aggregate as _;
    use ianua_domain::test_support::authority::assumed_authority;
    use ianua_domain::types::TenantId;
    use time::Duration;

    use super::*;
    use crate::postgres::workflows::PgWorkflowStore;
    use crate::test_support::TestDb;
    use crate::test_support::rows::workflows::{ann, draft_row};

    const MANAGES: [SystemPermission; 1] = [SystemPermission::Workflows(WorkflowAction::Manage)];

    struct Fixture {
        _db: TestDb,
        sets: PgEvaluationSetStore,
        evaluations: PgEvaluationStore,
        tenant: ScopedTenant,
        draft: Workflow<ResolvedTenant>,
    }

    /// A tenant holding one of Ann's drafts.
    async fn fixture() -> Fixture {
        let db = TestDb::fresh().await;
        let tenant = ScopedTenant::for_background(TenantId::new());
        let draft = Workflow::reconstitute(draft_row("parcels", 0)).unwrap();
        PgWorkflowStore::new(Arc::clone(&db.databases))
            .insert(&tenant, &draft)
            .await
            .unwrap();
        Fixture {
            sets: PgEvaluationSetStore::new(Arc::clone(&db.databases)),
            evaluations: PgEvaluationStore::new(Arc::clone(&db.databases)),
            tenant,
            draft,
            _db: db,
        }
    }

    fn control(tenant: &ScopedTenant) -> WorkflowControl<'static> {
        WorkflowControl::new(assumed_authority(&ann(), **tenant, &MANAGES, &[]))
    }

    fn case(name: &str) -> EvaluationCase {
        EvaluationCase::new(CaseParams {
            name: CaseName::new(name).unwrap(),
            input: FlowData::text("my parcel is late").unwrap(),
            exposure: DataClassLevel::Internal,
            checks: vec![Expectation::Contains {
                at: DataPath::parse("trigger").unwrap(),
                text: ExpectedText::new("parcel").unwrap(),
            }],
        })
        .unwrap()
    }

    impl Fixture {
        fn set(&self, gate: PublishGate) -> EvaluationSet<ResolvedTenant> {
            let params = SetParams {
                cases: vec![case("late"), case("lost")],
                gate,
            };
            EvaluationSet::create(&self.draft, &control(&self.tenant), params).unwrap()
        }

        fn started(&self) -> Evaluation<ResolvedTenant> {
            let set = self.set(PublishGate::Off);
            Evaluation::start(&set, &self.draft, &control(&self.tenant)).unwrap()
        }
    }

    /// Ann's set reads back as saved; saving again replaces it. Another
    /// tenant finds none.
    #[tokio::test]
    async fn a_set_reads_back_and_is_replaced() {
        let fx = fixture().await;
        let first = fx.set(PublishGate::Off);
        let second = fx.set(PublishGate::MustPass);
        let other = ScopedTenant::for_background(TenantId::new());

        fx.sets.save(&fx.tenant, &first).await.unwrap();
        fx.sets.save(&fx.tenant, &second).await.unwrap();
        let read = fx
            .sets
            .find(&fx.tenant, fx.draft.id())
            .await
            .unwrap()
            .unwrap();

        assert_eq!(read.cases(), second.cases());
        assert_eq!(read.gate(), PublishGate::MustPass);
        assert!(fx.sets.find(&other, fx.draft.id()).await.unwrap().is_none());
    }

    /// An evaluation reads back as started; a change written over the
    /// copy read lands once, and a second write over the same copy is a
    /// conflict.
    #[tokio::test]
    async fn an_evaluation_changes_only_over_the_copy_read() {
        let fx = fixture().await;
        fx.evaluations
            .insert(&fx.tenant, &fx.started())
            .await
            .unwrap();
        let listed = fx
            .evaluations
            .latest_of(&fx.tenant, fx.draft.id(), 1)
            .await
            .unwrap();
        let mut read = listed.into_iter().next().unwrap();
        let read_at = read.updated_at();

        read.give_up().unwrap();
        fx.evaluations
            .save_unchanged_since(&fx.tenant, &read, read_at)
            .await
            .unwrap();
        let again = fx
            .evaluations
            .save_unchanged_since(&fx.tenant, &read, read_at)
            .await;
        let ended = fx
            .evaluations
            .find_by_id(&fx.tenant, read.id())
            .await
            .unwrap()
            .unwrap();

        assert!(matches!(again, Err(DomainError::Conflict(_))));
        assert_eq!(ended.state(), EvaluationState::Ended(Verdict::Failed));
        assert_eq!(ended.outcomes(), read.outcomes());
    }

    /// An evaluation past its deadline is found overdue; one that ended
    /// long ago is purged, one still running is kept.
    #[tokio::test]
    async fn overdue_evaluations_are_found_and_ended_ones_purged() {
        let fx = fixture().await;
        let running = fx.started();
        let mut ended = fx.started();
        ended.give_up().unwrap();
        fx.evaluations.insert(&fx.tenant, &running).await.unwrap();
        fx.evaluations.insert(&fx.tenant, &ended).await.unwrap();
        let later = ianua_domain::shared::clock::now().saturating_add(Duration::hours(2));

        let overdue = fx.evaluations.overdue(&fx.tenant, later, 10).await.unwrap();
        let removed = fx
            .evaluations
            .purge_ended_before(&fx.tenant, later)
            .await
            .unwrap();

        assert_eq!(overdue.len(), 1);
        assert_eq!(overdue[0].id(), running.id());
        assert_eq!(removed, 1);
        assert!(
            fx.evaluations
                .find_by_id(&fx.tenant, running.id())
                .await
                .unwrap()
                .is_some()
        );
    }
}
