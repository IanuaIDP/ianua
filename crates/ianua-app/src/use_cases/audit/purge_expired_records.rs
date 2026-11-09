//! Purge expired records: remove every tenant's audit records once the
//! retention its compliance posture keeps them for has ended.
//!
//! A deleted tenant is purged too: its teardown keeps its trail, which
//! still expires as its posture says.
//!
//! Each tenant's posture says how long its records are kept, and when the
//! retention was shortened, records written before keep the longer period
//! ([`CompliancePosture::retention_cutoff`]). So a cut from ten years to 30
//! days never deletes years of records people relied on.
//!
//! Each purge that removed records is itself recorded for its tenant, with
//! the cutoff and the count, in one unit with the removal: the trail shows
//! records went because the retention asked, never that they went missing.
//!
//! It runs on a schedule, outside any request, for nobody, so no one's
//! rights are asked.
//!
//! [`CompliancePosture::retention_cutoff`]: ianua_domain::domains::tenant::compliance::CompliancePosture::retention_cutoff

use std::sync::Arc;

use ianua_domain::domains::audit::retention::RetentionPurge;
use ianua_domain::domains::tenant::lifecycle::Tenant;
use ianua_domain::shared::clock;
use ianua_domain::types::ActorRef;
use time::OffsetDateTime;

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::audit::AuditRetentionStore;
use crate::ports::runtime::UnitOfWork;
use crate::ports::tenant::TenantStore;
use crate::services::kept_together::kept_together;
use crate::services::tenant_batches::TenantBatches;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;

/// What one purge did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PurgeReport {
    /// Tenants whose expired records were removed, or had none.
    pub purged: u64,
    /// Records removed across every tenant.
    pub removed: u64,
    /// Tenants whose records could not be purged this time.
    pub unpurged: u64,
}

impl PurgeReport {
    /// This report with one more tenant's purge counted: how many records
    /// went, or that none could.
    fn counting(self, removed: Option<u64>) -> Self {
        let Some(removed) = removed else {
            return Self {
                unpurged: self.unpurged.saturating_add(1),
                ..self
            };
        };
        Self {
            purged: self.purged.saturating_add(1),
            removed: self.removed.saturating_add(removed),
            ..self
        }
    }
}

/// The ports [`PurgeExpiredRecordsUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct PurgeExpiredRecordsPorts {
    /// Lists the tenants to purge.
    pub tenant_store: Arc<dyn TenantStore>,
    /// Removes a tenant's records older than a cutoff.
    pub retention: Arc<dyn AuditRetentionStore>,
    /// Keeps each tenant's removal and its record together.
    pub unit_of_work: Arc<dyn UnitOfWork>,
}

/// Removes every tenant's audit records past their retention.
pub struct PurgeExpiredRecordsUseCase {
    ports: PurgeExpiredRecordsPorts,
}

impl PurgeExpiredRecordsUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: PurgeExpiredRecordsPorts) -> Self {
        Self { ports }
    }

    /// Removes `tenant`'s records from before its cutoff at `now`, records
    /// the purge, and returns how many went. A failure of either is logged
    /// and answered with `None`, with nothing removed: the tenant is purged
    /// again next time, and the others still are now.
    async fn purge_one(
        &self,
        tenant: &Tenant,
        now: OffsetDateTime,
        auditor: &RequestAuditor,
    ) -> Option<u64> {
        let scoped = ScopedTenant::for_background(*tenant.id());
        let cutoff = tenant.compliance().retention_cutoff(now);
        let work = self.purged_and_recorded(&scoped, cutoff, auditor);
        match kept_together(self.ports.unit_of_work.as_ref(), work).await {
            Ok(removed) => Some(removed),
            Err(error) => {
                tracing::warn!(tenant_id = %tenant.id(), %error, "audit records not purged");
                None
            }
        }
    }

    /// Removes `tenant`'s records from before `cutoff` and records
    /// `tenant.audit_records_purged` for it, attributed to the system, when
    /// any went.
    ///
    /// # Errors
    ///
    /// `AppError::Internal` when the records cannot be removed or the purge
    /// cannot be recorded.
    async fn purged_and_recorded(
        &self,
        tenant: &ScopedTenant,
        cutoff: OffsetDateTime,
        auditor: &RequestAuditor,
    ) -> Result<u64, AppError> {
        let removed = self
            .ports
            .retention
            .purge_before(tenant, cutoff)
            .await
            .or_internal()?;
        let purge = RetentionPurge::new(cutoff, removed);
        auditor
            .with_tenant(**tenant)
            .dispatch_by(&ActorRef::System, purge.events(tenant))
            .await
            .or_internal()?;
        Ok(purge.removed())
    }
}

impl Command for PurgeExpiredRecordsUseCase {
    type Caller = ();
    type Input = ();
    type Output = Result<PurgeReport, AppError>;

    /// Removes, for every tenant, the audit records from before the cutoff
    /// its compliance posture sets now, and records
    /// `tenant.audit_records_purged` for each tenant that lost any, naming
    /// the cutoff and the count. A removal and its record are kept or
    /// dropped together.
    ///
    /// One tenant whose records cannot be removed or recorded does not stop
    /// the others; it is counted as unpurged and tried again next time.
    ///
    /// # Errors
    ///
    /// `AppError::Internal` when the tenant list cannot be read.
    async fn execute(
        &self,
        (): &(),
        auditor: &RequestAuditor,
        (): (),
    ) -> Result<PurgeReport, AppError> {
        let now = clock::now();
        let mut report = PurgeReport::default();
        let mut tenants = TenantBatches::over(self.ports.tenant_store.as_ref());
        while let Some(batch) = tenants.next().await? {
            for tenant in &batch {
                report = report.counting(self.purge_one(tenant, now, auditor).await);
            }
        }
        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::runtime::Settlement;
    use crate::ports::shared::EventDispatcher;
    use crate::test_support::retention::FakeRetainedRecords;
    use crate::test_support::tenant::{
        FakeTenantStore, test_tenant, test_tenant_deleted, test_tenant_for_ctx,
    };
    use crate::test_support::{
        FailingEventDispatcher, FakeEventDispatcher, RecordingUnitOfWork, block_on, test_auditor,
        test_ctx,
    };

    /// Runs the purge over `tenants`, recording into `audit`, each tenant's
    /// work settled through `unit`.
    fn purge_into(
        tenants: Vec<Tenant>,
        retention: Arc<FakeRetainedRecords>,
        audit: Arc<dyn EventDispatcher>,
        unit: Arc<RecordingUnitOfWork>,
    ) -> PurgeReport {
        let uc = PurgeExpiredRecordsUseCase::new(PurgeExpiredRecordsPorts {
            tenant_store: Arc::new(FakeTenantStore::holding_all(tenants)),
            retention,
            unit_of_work: unit,
        });
        block_on(uc.execute(&(), &test_auditor(audit), ())).unwrap()
    }

    fn purge(
        tenants: Vec<Tenant>,
        retention: Arc<FakeRetainedRecords>,
        audit: &Arc<FakeEventDispatcher>,
    ) -> PurgeReport {
        let unit = Arc::new(RecordingUnitOfWork::default());
        purge_into(tenants, retention, audit.clone(), unit)
    }

    /// Acme keeps its records 365 days. One is 400 days old and one a day
    /// old: the old one goes, the new one stays, and the purge is recorded
    /// for Acme with the count.
    #[test]
    fn records_past_the_retention_are_removed_and_the_purge_recorded() {
        let tenant_id = test_ctx().tenant_id();
        let retention = Arc::new(FakeRetainedRecords::aged(
            tenant_id,
            [time::Duration::days(400), time::Duration::days(1)],
        ));
        let audit = Arc::new(FakeEventDispatcher::new());

        let report = purge(vec![test_tenant_for_ctx()], retention.clone(), &audit);

        assert_eq!(report.removed, 1);
        assert_eq!(retention.left(tenant_id).len(), 1);
        assert_eq!(
            audit.records.lock().unwrap().as_slice(),
            ["tenant.audit_records_purged"]
        );
        assert_eq!(
            audit.tenant_of("tenant.audit_records_purged"),
            Some(tenant_id)
        );
        assert_eq!(
            audit.payload_of("tenant.audit_records_purged").get("count"),
            Some("1")
        );
    }

    /// Acme's records are all within its retention. Nothing goes and
    /// nothing is recorded.
    #[test]
    fn a_purge_that_removes_nothing_records_nothing() {
        let tenant_id = test_ctx().tenant_id();
        let retention = Arc::new(FakeRetainedRecords::aged(
            tenant_id,
            [time::Duration::days(1)],
        ));
        let audit = Arc::new(FakeEventDispatcher::new());

        let report = purge(vec![test_tenant_for_ctx()], retention, &audit);

        assert_eq!(report.removed, 0);
        assert!(audit.records.lock().unwrap().is_empty());
    }

    /// An audit failure counts the tenant as unpurged and settles the
    /// purge's unit of work as a rollback.
    #[test]
    fn a_purge_that_cannot_be_recorded_is_rolled_back() {
        let retention = Arc::new(FakeRetainedRecords::aged(
            test_ctx().tenant_id(),
            [time::Duration::days(400)],
        ));
        let unit = Arc::new(RecordingUnitOfWork::default());

        let report = purge_into(
            vec![test_tenant_for_ctx()],
            retention,
            Arc::new(FailingEventDispatcher),
            unit.clone(),
        );

        assert_eq!(report.unpurged, 1);
        assert_eq!(unit.settlements(), [Settlement::Rollback]);
    }

    /// One tenant's records cannot be removed this time. The other's still
    /// are, and the first is counted for next time.
    #[test]
    fn one_tenant_that_fails_does_not_stop_the_others() {
        let acme = test_tenant_for_ctx();
        let globex = test_tenant("globex", "globex.example.com");
        let retention = Arc::new(
            FakeRetainedRecords::aged(*globex.id(), [time::Duration::days(400)])
                .failing_for(*acme.id()),
        );
        let audit = Arc::new(FakeEventDispatcher::new());

        let report = purge(vec![acme, globex], retention, &audit);

        assert_eq!(report.purged, 1);
        assert_eq!(report.removed, 1);
        assert_eq!(report.unpurged, 1);
    }

    /// A deleted tenant's expired audit records are purged, with the tenant
    /// and removed record counted and the purge recorded.
    #[test]
    fn a_deleted_tenants_kept_trail_still_expires() {
        let gone = test_tenant_deleted();
        let retention = Arc::new(FakeRetainedRecords::aged(
            *gone.id(),
            [time::Duration::days(400)],
        ));
        let audit = Arc::new(FakeEventDispatcher::new());

        let report = purge(vec![gone], retention, &audit);

        assert_eq!((report.purged, report.removed), (1, 1));
        assert_eq!(
            audit.records.lock().unwrap().as_slice(),
            ["tenant.audit_records_purged"]
        );
    }
}
