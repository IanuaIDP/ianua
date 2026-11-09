//! Carry out erasure requests whose grace period has ended.
//!
//! A person who asks to be forgotten gets a grace period to change their
//! mind. Once it has passed, this removes their account and everything that
//! hangs off it, on a schedule, without anyone having to remember to.
//!
//! What the audit log records about an erasure names the account by its id
//! only. The records are permanent, so a name or an address written into them
//! here would outlive the very data the person asked to have removed.

use std::sync::Arc;

use ianua_domain::domains::identity::privacy::erasure::ErasureRequest;
use ianua_domain::domains::identity::privacy::erasure_status::ErasureStatus;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::events::event::DomainEvent;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::ActorRef;
use time::OffsetDateTime;

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::identity::{ErasureBatch, ErasurePosition, ErasureRequestStore, UserStore};
use crate::ports::runtime::UnitOfWork;
use crate::ports::tenant::TenantStore;
use crate::services::kept_together::kept_together;
use crate::services::tenant_batches::TenantBatches;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::identity::users::sessions::sign_out::StandingRemoval;

/// What one run carried out.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ErasureReport {
    /// Requests carried out in full.
    pub completed: u64,
    /// Requests that failed this time; each is tried again next run.
    pub failed: u64,
}

/// How one request ended this run.
enum Outcome {
    Completed,
    Failed,
}

/// Ports needed to carry out erasures.
#[derive(ianua_macros::Fakes)]
pub struct ProcessErasuresPorts {
    /// Lists the tenants to look in.
    pub tenant_store: Arc<dyn TenantStore>,
    /// Finds and records erasure requests.
    pub erasure_store: Arc<dyn ErasureRequestStore>,
    /// Deletes the account.
    pub user_store: Arc<dyn UserStore>,
    /// Ends the account's sessions and delegations before it goes.
    pub removal: StandingRemoval,
    /// Keeps each request's changes and the records of them together.
    pub unit_of_work: Arc<dyn UnitOfWork>,
}

/// Carries out every erasure request that is due.
pub struct ProcessErasuresUseCase {
    ports: ProcessErasuresPorts,
}

/// One tenant an erasure run is working in, with the auditor its records go
/// through.
struct InTenant<'a> {
    tenant: ScopedTenant,
    auditor: &'a RequestAuditor,
    now: OffsetDateTime,
}

impl ProcessErasuresUseCase {
    /// Creates the use case.
    #[must_use]
    pub fn new(ports: ProcessErasuresPorts) -> Self {
        Self { ports }
    }

    /// What carrying out every due request of one tenant came to.
    async fn process_tenant(&self, within: &InTenant<'_>) -> Result<ErasureReport, AppError> {
        let mut report = ErasureReport::default();
        let mut batch = ErasureBatch::first(within.now);
        loop {
            let due = self
                .ports
                .erasure_store
                .find_due(&within.tenant, batch)
                .await
                .or_internal()?;
            let count = due.len();
            batch.after = due.last().map(|request| ErasurePosition {
                scheduled_at: request.scheduled_at(),
                id: *request.id(),
            });
            report = report.plus(self.process_batch(within, due).await?);
            if count < ErasureBatch::LIMIT {
                return Ok(report);
            }
        }
    }

    /// Attempts each request once, committing its changes and audit together.
    async fn process_batch(
        &self,
        within: &InTenant<'_>,
        due: Vec<ErasureRequest<ResolvedTenant>>,
    ) -> Result<ErasureReport, AppError> {
        let mut report = ErasureReport::default();
        for request in due {
            let carried_out = self.carry_out(within, request);
            match kept_together(self.ports.unit_of_work.as_ref(), carried_out).await? {
                Outcome::Completed => report.completed += 1,
                Outcome::Failed => report.failed += 1,
            }
        }
        Ok(report)
    }

    /// Takes one request through to completed or failed, recording each step.
    async fn carry_out(
        &self,
        within: &InTenant<'_>,
        mut request: ErasureRequest<ResolvedTenant>,
    ) -> Result<Outcome, AppError> {
        let tenant = &within.tenant;
        self.begin(within, &mut request).await?;
        let user_id = *request.user_id();

        let removed = self
            .ports
            .removal
            .remove(
                self.ports.user_store.as_ref(),
                tenant,
                user_id,
                &ActorRef::System,
            )
            .await;
        let Ok(revoked) = removed else {
            tracing::error!(tenant_id = %**tenant, %user_id, "erasure failed; retried next run");
            self.fail(within, &mut request).await?;
            return Ok(Outcome::Failed);
        };

        request
            .complete()
            .map_err(|e| AppError::from_domain(e.into()))?;
        self.save(tenant, &request).await?;
        let mut events = request.take_events(tenant);
        events.extend(revoked);
        record(within.auditor, events).await?;
        Ok(Outcome::Completed)
    }

    /// Marks the request as being carried out, a first attempt or a retry of
    /// one that failed, and records that it started.
    async fn begin(
        &self,
        within: &InTenant<'_>,
        request: &mut ErasureRequest<ResolvedTenant>,
    ) -> Result<(), AppError> {
        let begun = match request.status() {
            ErasureStatus::Failed => request.retry().map_err(DomainError::from),
            _ => request.start_processing(within.now),
        };
        begun.map_err(AppError::from_domain)?;
        self.save(&within.tenant, request).await?;
        record(within.auditor, request.take_events(&within.tenant)).await
    }

    /// Marks the request failed, to be tried again next run, and records it.
    async fn fail(
        &self,
        within: &InTenant<'_>,
        request: &mut ErasureRequest<ResolvedTenant>,
    ) -> Result<(), AppError> {
        request
            .fail()
            .map_err(|e| AppError::from_domain(e.into()))?;
        self.save(&within.tenant, request).await?;
        record(within.auditor, request.take_events(&within.tenant)).await
    }

    async fn save(
        &self,
        tenant: &ScopedTenant,
        request: &ErasureRequest<ResolvedTenant>,
    ) -> Result<(), AppError> {
        self.ports
            .erasure_store
            .save(tenant, request)
            .await
            .or_internal()
    }
}

impl Command for ProcessErasuresUseCase {
    type Caller = ();
    type Input = OffsetDateTime;
    type Output = Result<ErasureReport, AppError>;

    /// Carries out every due request in every tenant, as of `now`.
    ///
    /// A request that fails is marked failed and tried again on the next run;
    /// it does not stop the others. Each tenant's records go through
    /// `auditor` scoped to that tenant, attributed to the system.
    ///
    /// # Errors
    ///
    /// - `AppError::Conflict` if a due request refuses the status change it
    ///   is taken through.
    /// - `AppError::Internal` when the tenants or a tenant's due requests
    ///   cannot be read, or what was done cannot be recorded.
    async fn execute(
        &self,
        (): &(),
        auditor: &RequestAuditor,
        now: OffsetDateTime,
    ) -> Result<ErasureReport, AppError> {
        let mut report = ErasureReport::default();
        let mut tenants = TenantBatches::over(self.ports.tenant_store.as_ref());
        while let Some(batch) = tenants.next().await? {
            for tenant in &batch {
                let tenant_auditor = auditor.with_tenant(*tenant.id());
                let within = InTenant {
                    tenant: ScopedTenant::for_background(*tenant.id()),
                    auditor: &tenant_auditor,
                    now,
                };
                report = report.plus(self.process_tenant(&within).await?);
            }
        }
        Ok(report)
    }
}

/// Dispatches `events` attributed to the system.
async fn record(auditor: &RequestAuditor, events: Vec<DomainEvent>) -> Result<(), AppError> {
    auditor
        .dispatch_by(&ActorRef::System, events)
        .await
        .or_internal()
}

impl ErasureReport {
    /// This report and `other` added together.
    fn plus(self, other: Self) -> Self {
        Self {
            completed: self.completed + other.completed,
            failed: self.failed + other.failed,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use async_trait::async_trait;
    use ianua_domain::shared::clock;
    use ianua_domain::types::{DataExportId, ErasureRequestId, HttpsUrl, UserId};
    use time::OffsetDateTime;

    use super::*;
    use crate::ports::identity::{DataExportFiles, DataExportStore as _};
    use crate::ports::runtime::Settlement;
    use crate::services::authorization::grant_revocation::GrantRevocation;
    use crate::test_support::agents::FakeDelegationStore;
    use crate::test_support::authentication::FakeSessionStore;
    use crate::test_support::identity::{
        FakeDataExportFiles, FakeDataExportStore, FakeErasureStore, FakeUserStore, ready_export_of,
        stored_erasure,
    };
    use crate::test_support::tenant::{FakeTenantStore, test_tenant_for_ctx};
    use crate::test_support::{
        FailingEventDispatcher, FakeEventDispatcher, RecordingUnitOfWork, block_on, test_auditor,
        test_ctx,
    };

    /// Export files that cannot be removed the first time they are asked
    /// to.
    #[derive(Default)]
    struct FailsOnce {
        failed: AtomicBool,
    }

    #[async_trait]
    impl DataExportFiles for FailsOnce {
        async fn download_link(
            &self,
            _: &ScopedTenant,
            _: &DataExportId,
            _: OffsetDateTime,
        ) -> Result<HttpsUrl, DomainError> {
            Err(DomainError::infra_msg("no link in these tests"))
        }

        async fn delete(&self, _: &ScopedTenant, _: &DataExportId) -> Result<(), DomainError> {
            if self.failed.swap(true, Ordering::SeqCst) {
                return Ok(());
            }
            Err(DomainError::infra_msg("files unreachable"))
        }
    }

    struct Harness {
        uc: ProcessErasuresUseCase,
        users: Arc<FakeUserStore>,
        erasures: Arc<FakeErasureStore>,
        exports: Arc<FakeDataExportStore>,
        audit: Arc<FakeEventDispatcher>,
        unit: Arc<RecordingUnitOfWork>,
    }

    fn harness(export_files: Arc<dyn DataExportFiles>) -> Harness {
        let users = Arc::new(FakeUserStore::empty());
        let erasures = Arc::new(FakeErasureStore::empty());
        let exports = Arc::new(FakeDataExportStore::empty());
        let audit = Arc::new(FakeEventDispatcher::new());
        let unit = Arc::new(RecordingUnitOfWork::default());
        let uc = ProcessErasuresUseCase::new(ProcessErasuresPorts {
            tenant_store: Arc::new(FakeTenantStore::holding(test_tenant_for_ctx())),
            erasure_store: erasures.clone(),
            user_store: users.clone(),
            removal: StandingRemoval {
                session_store: Arc::new(FakeSessionStore::empty()),
                grant_revocation: GrantRevocation::new(Arc::new(FakeDelegationStore::empty())),
                exports: exports.clone(),
                export_files,
            },
            unit_of_work: unit.clone(),
            ..ProcessErasuresPorts::fakes()
        });
        Harness {
            uc,
            users,
            erasures,
            exports,
            audit,
            unit,
        }
    }

    fn files() -> Arc<dyn DataExportFiles> {
        Arc::new(FakeDataExportFiles::default())
    }

    impl Harness {
        /// Seeds a user and an erasure of them asked `days_ago` days ago, with
        /// a grace period of `grace_days`.
        fn request_erasure(&self, days_ago: i64, grace_days: i64) -> ErasureRequestId {
            self.request_erasure_of(UserId::new(), days_ago, grace_days)
        }

        /// Seeds `user_id` and an erasure of them, as
        /// [`request_erasure`](Self::request_erasure) does.
        fn request_erasure_of(
            &self,
            user_id: UserId,
            days_ago: i64,
            grace_days: i64,
        ) -> ErasureRequestId {
            self.users.add_active_user(user_id, "leaving@acme.com");
            let request = stored_erasure(user_id, "leaving@acme.com", (days_ago, grace_days));
            block_on(self.erasures.save(&test_ctx().tenant(), &request)).unwrap();
            *request.id()
        }

        /// A due erasure of a user who asked for a data export, whose file
        /// goes with the account.
        fn due_with_an_export(&self) -> ErasureRequestId {
            let user_id = UserId::new();
            block_on(
                self.exports
                    .save(&test_ctx().tenant(), &ready_export_of(user_id)),
            )
            .unwrap();
            self.request_erasure_of(user_id, 2, 1)
        }

        fn due(&self) -> ErasureRequestId {
            self.request_erasure(2, 1)
        }

        fn run(&self) -> ErasureReport {
            block_on(self.uc.execute(
                &(),
                &test_auditor(self.audit.clone()),
                clock::now() + time::Duration::seconds(1),
            ))
            .unwrap()
        }
    }

    /// Lea's grace period ended yesterday. The run removes her account,
    /// marks the erasure done, and records its start and end.
    #[test]
    fn a_due_request_removes_the_account_and_is_recorded_as_completed() {
        let h = harness(files());
        let request = h.due();

        let report = h.run();

        assert_eq!(report.completed, 1);
        assert_eq!(h.users.count(), 0);
        assert_eq!(
            h.erasures.status_of(&request),
            Some(ErasureStatus::Completed)
        );
        assert_eq!(
            h.audit.records.lock().unwrap().as_slice(),
            ["identity.erasure_started", "identity.erasure_completed"]
        );
    }

    /// Lea asked an hour ago and has 30 days to change her mind. The run
    /// leaves her alone.
    #[test]
    fn a_request_still_in_its_grace_period_is_left_alone() {
        let h = harness(files());
        let request = h.request_erasure(0, 30);

        let report = h.run();

        assert_eq!(report, ErasureReport::default());
        assert_eq!(h.users.count(), 1);
        assert_eq!(h.erasures.status_of(&request), Some(ErasureStatus::Pending));
    }

    /// The file of Lea's data export cannot be removed on the first run, so
    /// her erasure fails. The next run tries again and finishes it.
    #[test]
    fn a_failed_erasure_is_retried_on_the_next_run() {
        let h = harness(Arc::new(FailsOnce::default()));
        let request = h.due_with_an_export();

        let first = h.run();
        assert_eq!(first.failed, 1);
        assert_eq!(h.erasures.status_of(&request), Some(ErasureStatus::Failed));

        let second = h.run();

        assert_eq!(second.completed, 1);
        assert_eq!(h.users.count(), 0);
        assert_eq!(
            h.erasures.status_of(&request),
            Some(ErasureStatus::Completed)
        );
    }

    /// A backlog exceeds one read and its oldest erasure fails. The sweep
    /// still completes later requests in bounded batches, leaves the failed
    /// account present for retry, and retries it only in the next sweep.
    #[test]
    fn erasure_batches_advance_past_failures_without_repeating_them() {
        let h = harness(Arc::new(FailsOnce::default()));
        let failed = h.due_with_an_export();
        for _ in 0..500 {
            h.due();
        }

        let first = h.run();

        assert_eq!(
            first,
            ErasureReport {
                completed: 500,
                failed: 1
            }
        );
        assert_eq!(h.users.count(), 1);
        assert_eq!(h.erasures.status_of(&failed), Some(ErasureStatus::Failed));
        assert_eq!(failed_records(&h), 1);
        assert_eq!(h.erasures.due_batch_sizes(), [500, 1]);

        let second = h.run();

        assert_eq!(
            second,
            ErasureReport {
                completed: 1,
                failed: 0
            }
        );
        assert_eq!(h.users.count(), 0);
        assert_eq!(h.erasures.due_batch_sizes(), [500, 1, 1]);
    }

    /// Counts failed erasures recorded during the sweep without counting other audit events.
    fn failed_records(harness: &Harness) -> usize {
        harness
            .audit
            .records
            .lock()
            .unwrap()
            .iter()
            .filter(|event| event.as_str() == "identity.erasure_failed")
            .count()
    }

    /// Failure to audit the first erasure's start aborts the sweep with an
    /// internal error. Both accounts remain, and only one rollback is requested.
    #[test]
    fn an_erasure_audit_failure_aborts_the_sweep() {
        let h = harness(files());
        h.due();
        h.due();

        let result = block_on(h.uc.execute(
            &(),
            &test_auditor(Arc::new(FailingEventDispatcher)),
            clock::now(),
        ));

        assert!(matches!(result, Err(AppError::Internal(_))));
        assert_eq!(h.users.count(), 2);
        assert_eq!(h.unit.settlements(), [Settlement::Rollback]);
    }

    /// The audit records of Lea's erasure outlive her data, so they name
    /// her account by its id and never by her address.
    #[test]
    fn the_audit_record_names_the_account_by_id_only() {
        let h = harness(files());
        h.due();

        h.run();

        let recorded = format!("{:?}", h.audit.payloads.lock().unwrap());
        assert!(
            !recorded.contains("leaving@acme.com"),
            "no address in {recorded}"
        );
    }

    /// Two erasures are due. Each is carried out and committed on its own.
    #[test]
    fn each_due_request_is_carried_out_as_one_unit() {
        let h = harness(files());
        h.due();
        h.due();

        h.run();

        assert_eq!(
            h.unit.settlements(),
            vec![Settlement::Commit, Settlement::Commit]
        );
    }
}
