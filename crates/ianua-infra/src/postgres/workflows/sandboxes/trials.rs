//! The trials of a tenant's sandbox versions, each table row under
//! row-level security. A trial's end is written only while it still runs,
//! and ended trials are purged a batch at a time.

mod record;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::workflows::SandboxTrialStore;
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::workflows::sandbox::trial::SandboxTrial;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::model::aggregate::Aggregate as _;
use ianua_domain::types::SandboxTrialId;
use time::OffsetDateTime;

use self::record::{EndWritten, TrialColumns, TrialRecord};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The most ended trials of one tenant one purge removes at a time.
const PURGED_AT_ONCE: i64 = 1_000;

/// The Postgres store of sandbox trials.
pub struct PgSandboxTrialStore {
    databases: Arc<Databases>,
}

impl TenantScoped for PgSandboxTrialStore {}

impl PgSandboxTrialStore {
    /// A store keeping sandbox trials in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

#[async_trait]
impl SandboxTrialStore for PgSandboxTrialStore {
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &SandboxTrialId,
    ) -> Result<Option<SandboxTrial<ResolvedTenant>>, DomainError> {
        let record = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    TrialRecord,
                    "queries/sandbox_trials/by_id.sql",
                    tenant_id.as_uuid(),
                    id.as_uuid()
                )
                .fetch_optional(connection)
                .await
            },
        )
        .await?;
        record.map(TrialRecord::into_trial).transpose()
    }

    async fn insert(
        &self,
        tenant_id: &ScopedTenant,
        trial: &SandboxTrial<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let c = TrialColumns::of(trial)?;
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/sandbox_trials/insert.sql",
                    c.id,
                    tenant_id.as_uuid(),
                    c.sandbox_id,
                    c.version_id,
                    c.input,
                    c.end.state,
                    c.end.output,
                    c.end.failure,
                    c.end.failure_detail,
                    c.started_by,
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

    async fn save_end(
        &self,
        tenant_id: &ScopedTenant,
        trial: &SandboxTrial<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let end = EndWritten::of(trial.state())?;
        let updated_at = trial.updated_at();
        let done = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/sandbox_trials/save_end.sql",
                    tenant_id.as_uuid(),
                    trial.id().as_uuid(),
                    end.state,
                    end.output,
                    end.failure,
                    end.failure_detail,
                    updated_at,
                )
                .execute(connection)
                .await
            },
        )
        .await?;
        if done.rows_affected() == 0 {
            return Err(DomainError::conflict(message!(
                "workflows-the-trial-ended-already",
                "the trial ended already"
            )));
        }
        Ok(())
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
                        "queries/sandbox_trials/purge_ended.sql",
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
    use ianua_app::ports::workflows::{SandboxStore as _, SandboxVersionStore as _};
    use ianua_domain::domains::authorization::permission::{SystemPermission, WorkflowAction};
    use ianua_domain::domains::workflows::control::WorkflowControl;
    use ianua_domain::domains::workflows::data::FlowData;
    use ianua_domain::domains::workflows::execution::step::{CodeFailure, CodeOutcome};
    use ianua_domain::domains::workflows::sandbox::build::{Bundle, BundleDigest};
    use ianua_domain::domains::workflows::sandbox::network::NetworkAccess;
    use ianua_domain::domains::workflows::sandbox::package::Packages;
    use ianua_domain::domains::workflows::sandbox::recipe::{
        CodeParams, CodeProgram, Program, RunBudget, SandboxCode,
    };
    use ianua_domain::domains::workflows::sandbox::runtime::{Language, Runtime, RuntimeImage};
    use ianua_domain::domains::workflows::sandbox::source::CodeSource;
    use ianua_domain::domains::workflows::sandbox::trial::TrialState;
    use ianua_domain::domains::workflows::sandbox::{
        CreateSandboxParams, Sandbox, SandboxKind, VersionDraft,
    };
    use ianua_domain::test_support::authority::assumed_authority;
    use ianua_domain::types::{Label, TenantId, UntrustedText};
    use time::Duration;

    use super::*;
    use crate::postgres::workflows::{PgSandboxStore, PgSandboxVersionStore};
    use crate::test_support::TestDb;
    use crate::test_support::rows::workflows::ann;

    const MANAGES: [SystemPermission; 1] = [SystemPermission::Workflows(WorkflowAction::Manage)];

    struct Fixture {
        _db: TestDb,
        trials: PgSandboxTrialStore,
        tenant: ScopedTenant,
        sandbox: Sandbox<ResolvedTenant>,
        version: ianua_domain::domains::workflows::sandbox::version::SandboxVersion<ResolvedTenant>,
    }

    /// A tenant holding one Python sandbox and its built version 1.
    async fn fixture() -> Fixture {
        let db = TestDb::fresh().await;
        let tenant = ScopedTenant::for_background(TenantId::new());
        let control = || WorkflowControl::new(assumed_authority(&ann(), *tenant, &MANAGES, &[]));
        let mut sandbox = Sandbox::create(
            CreateSandboxParams {
                name: Label::new("name", "Slugs").unwrap(),
                kind: SandboxKind::Code(Language::Python),
            },
            &control(),
        )
        .unwrap();
        let mut version = sandbox.save_version(&control(), draft()).unwrap();
        let bundle = Bundle::new(BundleDigest::new("b".repeat(64)).unwrap(), 10, Vec::new());
        version.finish_build(bundle.unwrap()).unwrap();
        let sandboxes = PgSandboxStore::new(Arc::clone(&db.databases));
        let versions = PgSandboxVersionStore::new(Arc::clone(&db.databases));
        sandboxes.save(&tenant, &sandbox).await.unwrap();
        versions.insert(&tenant, &version).await.unwrap();
        Fixture {
            trials: PgSandboxTrialStore::new(Arc::clone(&db.databases)),
            tenant,
            sandbox,
            version,
            _db: db,
        }
    }

    /// An isolated Python version with no packages and the standard trial budget.
    fn draft() -> VersionDraft {
        let code = CodeProgram::new(CodeParams {
            runtime: Runtime::Python313,
            image: RuntimeImage::new(format!("python:3.13-slim@sha256:{}", "ae".repeat(32)))
                .unwrap(),
            code: SandboxCode::new("def main(item):\n\treturn item\n").unwrap(),
            packages: Packages::new(Vec::new()).unwrap(),
        })
        .unwrap();
        VersionDraft {
            program: Program::Code(code),
            budget: RunBudget::new(30, 256).unwrap(),
            network: NetworkAccess::closed(),
            source: CodeSource::Written,
        }
    }

    impl Fixture {
        /// Reads a trial through its owner's scoped store, retaining absence for purge assertions.
        async fn find_trial(&self, id: &SandboxTrialId) -> Option<SandboxTrial<ResolvedTenant>> {
            self.trials.find_by_id(&self.tenant, id).await.unwrap()
        }

        fn started(&self) -> SandboxTrial<ResolvedTenant> {
            let control =
                WorkflowControl::new(assumed_authority(&ann(), *self.tenant, &MANAGES, &[]));
            self.sandbox
                .try_version(
                    &control,
                    &self.version,
                    FlowData::text("Fix login").unwrap(),
                )
                .unwrap()
        }
    }

    /// Ann's trial reads back as started, running with its input; once it
    /// ran, its end reads back. Another tenant finds none of it.
    #[tokio::test]
    async fn a_trial_reads_back_as_started_and_as_it_ended() {
        let fx = fixture().await;
        let mut trial = fx.started();
        fx.trials.insert(&fx.tenant, &trial).await.unwrap();
        let other = ScopedTenant::for_background(TenantId::new());

        let started = fx.find_trial(trial.id()).await.unwrap();
        trial
            .settle(CodeOutcome::Failed(CodeFailure::Raised(
                UntrustedText::record("ValueError: no title"),
            )))
            .unwrap();
        fx.trials.save_end(&fx.tenant, &trial).await.unwrap();
        let ended = fx.find_trial(trial.id()).await.unwrap();

        assert_eq!(started.state(), &TrialState::Running);
        assert_eq!(started.input(), trial.input());
        assert_eq!(ended.state(), trial.state());
        assert!(
            fx.trials
                .find_by_id(&other, trial.id())
                .await
                .unwrap()
                .is_none()
        );
    }

    /// Saving a trial's end a second time returns a conflict.
    #[tokio::test]
    async fn a_trial_ends_once() {
        let fx = fixture().await;
        let mut trial = fx.started();
        fx.trials.insert(&fx.tenant, &trial).await.unwrap();
        trial
            .settle(CodeOutcome::Succeeded(FlowData::bool(true)))
            .unwrap();
        fx.trials.save_end(&fx.tenant, &trial).await.unwrap();

        let again = fx.trials.save_end(&fx.tenant, &trial).await;

        assert!(matches!(again, Err(DomainError::Conflict(_))));
    }

    /// The purge removes the trials that ended before the cutoff and keeps
    /// a trial still running, however old.
    #[tokio::test]
    async fn only_ended_trials_past_the_cutoff_are_purged() {
        let fx = fixture().await;
        let mut ended = fx.started();
        let running = fx.started();
        fx.trials.insert(&fx.tenant, &ended).await.unwrap();
        fx.trials.insert(&fx.tenant, &running).await.unwrap();
        ended
            .settle(CodeOutcome::Failed(CodeFailure::TimedOut))
            .unwrap();
        fx.trials.save_end(&fx.tenant, &ended).await.unwrap();

        let removed = fx
            .trials
            .purge_ended_before(
                &fx.tenant,
                ianua_domain::shared::clock::now().saturating_add(Duration::hours(1)),
            )
            .await
            .unwrap();

        assert_eq!(removed, 1);
        assert!(fx.find_trial(ended.id()).await.is_none());
        assert!(fx.find_trial(running.id()).await.is_some());
    }
}
