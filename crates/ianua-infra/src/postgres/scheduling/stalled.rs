//! The work left half-done, found for the reconcile sweep: runs no worker
//! drives, setups and teardowns that never began or stalled, and clones
//! left copying. Each read spans every tenant, as platform work, and is
//! held to ten seconds.
//!
//! A run lives in its tenant's database and its lease in the platform's,
//! so the runs are read from every database, the oldest of them kept, and
//! those a worker still holds a lease on left out, in one read of the
//! leases.

use std::future::Future;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use futures_util::future::try_join_all;
use ianua_app::ports::scheduling::{StalledClone, StalledRun, StalledWork};
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{AgentRunId, TenantCloneId, TenantId};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// How long a read may take before the sweep gives up on it.
const ANSWER_WITHIN: Duration = Duration::from_secs(10);

/// A run still running, where it was found.
struct Running {
    tenant: Uuid,
    run: Uuid,
    started: OffsetDateTime,
}

/// Finds the work left half-done.
pub struct PgStalledWork {
    databases: Arc<Databases>,
}

impl PgStalledWork {
    /// The finder over `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }

    /// Every place runs are kept: the platform database, then each
    /// database of its own.
    fn places(&self) -> Vec<RowScope> {
        let mut places = vec![RowScope::Platform];
        places.extend(
            self.databases
                .with_own_database()
                .into_iter()
                .map(RowScope::Tenant),
        );
        places
    }

    /// The runs still running in `place` that started before `before`, at
    /// most `limit`.
    async fn running_in(
        &self,
        place: RowScope,
        before: OffsetDateTime,
        limit: i64,
    ) -> Result<Vec<Running>, DomainError> {
        let rows = scoped(&self.databases, place, async |connection| {
            sqlx::query_file!("queries/agent_runs/running_since.sql", before, limit)
                .fetch_all(connection)
                .await
        })
        .await?;
        Ok(rows
            .into_iter()
            .map(|row| Running {
                tenant: row.tenant_id,
                run: row.id,
                started: row.created_at,
            })
            .collect())
    }

    /// Which of `runs` a worker still holds a lease on now.
    async fn leased(&self, runs: &[Uuid]) -> Result<Vec<Uuid>, DomainError> {
        let now = clock::now();
        scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file_scalar!("queries/platform_leases/held_among.sql", runs, now)
                .fetch_all(connection)
                .await
        })
        .await
    }

    /// The tenants `read` answers, read as platform work.
    async fn tenants_of(
        &self,
        read: impl AsyncFnOnce(&mut sqlx::PgConnection) -> Result<Vec<Uuid>, sqlx::Error>,
    ) -> Result<Vec<TenantId>, DomainError> {
        let ids = scoped(&self.databases, RowScope::Platform, read).await?;
        Ok(ids.into_iter().map(TenantId::from_uuid).collect())
    }
}

#[async_trait]
impl StalledWork for PgStalledWork {
    async fn runs_without_lease(
        &self,
        before: OffsetDateTime,
        limit: NonZeroU32,
    ) -> Result<Vec<StalledRun>, DomainError> {
        let most = i64::from(limit.get());
        bounded(async {
            let found = try_join_all(
                self.places()
                    .into_iter()
                    .map(|place| self.running_in(place, before, most)),
            )
            .await?;
            let mut running: Vec<Running> = found.into_iter().flatten().collect();
            running.sort_by_key(|run| (run.started, run.run));
            running.truncate(usize::try_from(limit.get()).unwrap_or(usize::MAX));
            let ids: Vec<Uuid> = running.iter().map(|run| run.run).collect();
            let leased = self.leased(&ids).await?;
            Ok(running
                .into_iter()
                .filter(|run| !leased.contains(&run.run))
                .map(|run| StalledRun {
                    tenant_id: TenantId::from_uuid(run.tenant),
                    run_id: AgentRunId::from_uuid(run.run),
                })
                .collect())
        })
        .await
    }

    async fn setups_left(
        &self,
        before: OffsetDateTime,
        limit: NonZeroU32,
    ) -> Result<Vec<TenantId>, DomainError> {
        let most = i64::from(limit.get());
        bounded(self.tenants_of(async |connection| {
            sqlx::query_file_scalar!("queries/tenants/setups_left.sql", before, most)
                .fetch_all(connection)
                .await
        }))
        .await
    }

    async fn teardowns_left(
        &self,
        before: OffsetDateTime,
        limit: NonZeroU32,
    ) -> Result<Vec<TenantId>, DomainError> {
        let most = i64::from(limit.get());
        bounded(self.tenants_of(async |connection| {
            sqlx::query_file_scalar!("queries/tenants/teardowns_left.sql", before, most)
                .fetch_all(connection)
                .await
        }))
        .await
    }

    async fn clones_copying(
        &self,
        before: OffsetDateTime,
        limit: NonZeroU32,
    ) -> Result<Vec<StalledClone>, DomainError> {
        let most = i64::from(limit.get());
        let rows = bounded(scoped(
            &self.databases,
            RowScope::Platform,
            async |connection| {
                sqlx::query_file!("queries/tenant_clones/copying_since.sql", before, most)
                    .fetch_all(connection)
                    .await
            },
        ))
        .await?;
        Ok(rows
            .into_iter()
            .map(|row| StalledClone {
                clone_id: TenantCloneId::from_uuid(row.id),
                target: TenantId::from_uuid(row.tenant_id),
            })
            .collect())
    }
}

/// `work`, failed when it takes longer than [`ANSWER_WITHIN`].
async fn bounded<T>(work: impl Future<Output = Result<T, DomainError>>) -> Result<T, DomainError> {
    tokio::time::timeout(ANSWER_WITHIN, work)
        .await
        .map_err(|_| DomainError::infra_msg("the stalled work was not read within ten seconds"))?
}

#[cfg(test)]
mod tests {
    use ianua_app::ports::agents::RunLease as _;
    use ianua_app::ports::tenant::{
        TenantCloneStore as _, TenantSetupStore as _, TenantStore as _, TenantTeardownStore as _,
    };
    use ianua_domain::domains::tenant::clone::{
        ClonePart, CloneState, TenantClone, TenantCloneRow,
    };
    use ianua_domain::domains::tenant::lifecycle::{Tenant, TenantRow};
    use ianua_domain::domains::tenant::setup::{SetupStep, TenantSetup, TenantSetupRow};
    use ianua_domain::domains::tenant::status::TenantStatus;
    use ianua_domain::domains::tenant::teardown::{
        TeardownStep, TenantTeardown, TenantTeardownRow,
    };
    use ianua_domain::shared::config::DomainLimits;
    use ianua_domain::shared::model::steps::RunFailure;
    use ianua_domain::types::{OrganizationId, UntrustedText};

    use super::*;
    use crate::postgres::agents::PgRunLease;
    use crate::postgres::tenant::{
        PgTenantCloneStore, PgTenantSetupStore, PgTenantStore, PgTenantTeardownStore,
    };
    use crate::test_support::TestDb;
    use crate::test_support::rows::agents::run::saved_run;
    use crate::test_support::rows::at;
    use crate::test_support::rows::audit::{saved_organization, saved_tenant_of};
    use crate::test_support::rows::tenant::{deleted_tenant_row, tenant_row};

    const MOST: NonZeroU32 = NonZeroU32::MIN.saturating_add(9);

    /// A tenant of `organization` standing as `status`, saved.
    async fn saved_tenant(
        db: &TestDb,
        organization: OrganizationId,
        status: TenantStatus,
    ) -> TenantId {
        let row = match status {
            TenantStatus::Deleted => deleted_tenant_row(organization, &fresh_slug()),
            _ => TenantRow {
                status,
                ..tenant_row(organization, &fresh_slug())
            },
        };
        let tenant = Tenant::reconstitute(row).unwrap();
        PgTenantStore::new(Arc::clone(&db.databases), DomainLimits::default())
            .save(&tenant)
            .await
            .unwrap();
        *tenant.id()
    }

    fn fresh_slug() -> String {
        format!("t{}", Uuid::now_v7().simple())
    }

    /// Rebuilds an unfinished setup with its saved failure state and fixed progress times.
    fn unfinished_setup(tenant: TenantId, failure: RunFailure<SetupStep>) -> TenantSetup {
        TenantSetup::reconstitute(TenantSetupRow {
            tenant_id: tenant,
            planned: vec![
                SetupStep::SigningKey,
                SetupStep::AssertionKey,
                SetupStep::StartingRoles,
                SetupStep::Activate,
            ],
            done: Vec::new(),
            failed: failure,
            started_at: at(1),
            updated_at: at(2),
        })
        .unwrap()
    }

    /// Rebuilds a settings clone with copied parts matching its progress state.
    fn settings_clone(
        organization: OrganizationId,
        source: TenantId,
        target: TenantId,
        state: CloneState,
    ) -> TenantClone {
        let copied = match state {
            CloneState::Copying => Vec::new(),
            _ => vec![ClonePart::Settings],
        };
        TenantClone::reconstitute(TenantCloneRow {
            id: TenantCloneId::new(),
            organization_id: organization,
            source,
            target,
            parts: vec![ClonePart::Settings],
            copied,
            state,
            started_at: at(1),
        })
        .unwrap()
    }

    /// The stalled-work scan returns the unleased run with its tenant id
    /// and excludes the run whose lease is still held.
    #[tokio::test]
    async fn a_run_nobody_drives_is_found_and_a_held_one_is_not() {
        let db = TestDb::fresh().await;
        let organization = saved_organization(&db.databases).await;
        let tenant = saved_tenant_of(&db.databases, organization).await;
        let left = saved_run(&db.databases, &tenant).await;
        let held = saved_run(&db.databases, &tenant).await;
        PgRunLease::new(Arc::clone(&db.databases), Duration::from_secs(60))
            .try_claim(held.id())
            .await
            .unwrap();

        let found = PgStalledWork::new(Arc::clone(&db.databases))
            .runs_without_lease(at(100), MOST)
            .await
            .unwrap();

        let runs: Vec<AgentRunId> = found.iter().map(|run| run.run_id).collect();
        assert_eq!(runs, [*left.id()]);
        assert_eq!(found[0].tenant_id, *tenant);
    }

    /// A setup that never began, or stands running unchanged, is found; one
    /// that failed, waiting for an operator, and an active tenant are not.
    #[tokio::test]
    async fn setups_left_half_done_are_found_and_failed_ones_are_not() {
        let db = TestDb::fresh().await;
        let organization = saved_organization(&db.databases).await;
        let never_begun = saved_tenant(&db, organization, TenantStatus::Provisioning).await;
        let stalled = saved_tenant(&db, organization, TenantStatus::Provisioning).await;
        let failed = saved_tenant(&db, organization, TenantStatus::Provisioning).await;
        saved_tenant(&db, organization, TenantStatus::Active).await;
        let setups = PgTenantSetupStore::new(Arc::clone(&db.databases));
        for (tenant, failure) in [
            (stalled, RunFailure::NotFailed),
            (
                failed,
                RunFailure::FailedAt {
                    step: SetupStep::SigningKey,
                    why: UntrustedText::record("no key"),
                },
            ),
        ] {
            let setup = unfinished_setup(tenant, failure);
            setups.save(&setup).await.unwrap();
        }

        let mut found = PgStalledWork::new(Arc::clone(&db.databases))
            .setups_left(at(100), MOST)
            .await
            .unwrap();

        found.sort_by_key(|tenant| *tenant.as_uuid());
        let mut expected = vec![never_begun, stalled];
        expected.sort_by_key(|tenant| *tenant.as_uuid());
        assert_eq!(found, expected);
    }

    /// A deleted tenant whose teardown never began is found; one whose
    /// teardown is done is not.
    #[tokio::test]
    async fn teardowns_never_begun_are_found_and_done_ones_are_not() {
        let db = TestDb::fresh().await;
        let organization = saved_organization(&db.databases).await;
        let never_begun = saved_tenant(&db, organization, TenantStatus::Deleted).await;
        let done = saved_tenant(&db, organization, TenantStatus::Deleted).await;
        let teardown = TenantTeardown::reconstitute(TenantTeardownRow {
            tenant_id: done,
            planned: vec![TeardownStep::Data],
            done: vec![TeardownStep::Data],
            failed: RunFailure::NotFailed,
            started_at: at(3),
            updated_at: at(4),
        })
        .unwrap();
        PgTenantTeardownStore::new(Arc::clone(&db.databases))
            .save(&teardown)
            .await
            .unwrap();

        let found = PgStalledWork::new(Arc::clone(&db.databases))
            .teardowns_left(at(100), MOST)
            .await
            .unwrap();

        assert_eq!(found, [never_begun]);
    }

    /// A clone left copying is found; one that completed is not.
    #[tokio::test]
    async fn clones_left_copying_are_found_and_ended_ones_are_not() {
        let db = TestDb::fresh().await;
        let organization = saved_organization(&db.databases).await;
        let source = saved_tenant(&db, organization, TenantStatus::Active).await;
        let target = saved_tenant(&db, organization, TenantStatus::Active).await;
        let clones = PgTenantCloneStore::new(Arc::clone(&db.databases));
        let mut left = None;
        for state in [CloneState::Copying, CloneState::Completed { at: at(5) }] {
            let clone = settings_clone(organization, source, target, state);
            clones.save(&clone).await.unwrap();
            left = left.or(Some(*clone.id()));
        }

        let found = PgStalledWork::new(Arc::clone(&db.databases))
            .clones_copying(at(100), MOST)
            .await
            .unwrap();

        assert_eq!(
            found,
            [StalledClone {
                clone_id: left.unwrap(),
                target
            }]
        );
    }
}
