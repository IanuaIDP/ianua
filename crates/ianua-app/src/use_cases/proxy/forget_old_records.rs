//! Forget old records: remove every tenant's request records and stream
//! records once the retention its compliance posture keeps records for has
//! passed them.
//!
//! The gateway writes a record for every request and every stream
//! connection, so a busy tenant writes millions. Each tenant's posture
//! says how long they are kept, and when the retention was shortened,
//! records written before keep the longer period
//! ([`CompliancePosture::retention_cutoff`]), as audit records do.
//!
//! A round removes a bounded number of each tenant's oldest records, in
//! short statements, so no tenant holds a lock for long or keeps the round
//! from the others; a tenant with more left is finished by the next rounds.
//! The records are what the gateway saw, not the audit trail, so their
//! removal is not recorded, as old notifications' is not.
//!
//! It runs on a schedule, outside any request, for nobody, so no one's
//! rights are asked.
//!
//! [`CompliancePosture::retention_cutoff`]: ianua_domain::domains::tenant::compliance::CompliancePosture::retention_cutoff

use std::num::NonZeroU32;
use std::sync::Arc;

use ianua_domain::domains::tenant::lifecycle::Tenant;
use ianua_domain::shared::errors::DomainError;
use time::OffsetDateTime;

use crate::auditor::RequestAuditor;
use crate::error::AppError;
use crate::ports::proxy::RequestRecordRetention;
use crate::ports::routing::StreamRecordRetention;
use crate::ports::tenant::TenantStore;
use crate::services::tenant_batches::TenantBatches;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;

/// The most records one statement removes.
const PER_STATEMENT: NonZeroU32 = NonZeroU32::MIN.saturating_add(4_999);

/// The most statements a round spends on one kind of a tenant's records:
/// 100,000 records an hour, over two million a day.
const STATEMENTS_PER_ROUND: u32 = 20;

/// What one round did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ForgetReport {
    /// Request records removed across every tenant.
    pub requests: u64,
    /// Stream records removed across every tenant.
    pub streams: u64,
    /// Tenants with records past their retention left for the next round.
    pub unfinished: u64,
    /// Tenants whose records could not be removed this time.
    pub failed: u64,
}

/// How one tenant's round went.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Forgotten {
    /// Everything past the retention went, or as much as a round removes.
    Removed { requests: Removed, streams: Removed },
    /// The records could not be removed; the next round tries again.
    Failed,
}

/// What a round removed of one kind of a tenant's records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Removed {
    count: u64,
    left: Left,
}

/// Whether records past the retention are left after a round.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Left {
    /// The round exhausted all records eligible for deletion.
    None,
    /// Some may be: the round removed as many as it removes.
    Some,
}

impl ForgetReport {
    /// This report with one more tenant's round counted.
    fn counting(self, forgotten: Forgotten) -> Self {
        let Forgotten::Removed { requests, streams } = forgotten else {
            return Self {
                failed: self.failed.saturating_add(1),
                ..self
            };
        };
        let unfinished = match (requests.left, streams.left) {
            (Left::None, Left::None) => self.unfinished,
            (Left::Some, _) | (_, Left::Some) => self.unfinished.saturating_add(1),
        };
        Self {
            requests: self.requests.saturating_add(requests.count),
            streams: self.streams.saturating_add(streams.count),
            unfinished,
            ..self
        }
    }
}

/// The ports [`ForgetOldRecordsUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ForgetOldRecordsPorts {
    /// Lists the tenants whose records to remove.
    pub tenant_store: Arc<dyn TenantStore>,
    /// Removes a tenant's old request records.
    pub requests: Arc<dyn RequestRecordRetention>,
    /// Removes a tenant's old stream records.
    pub streams: Arc<dyn StreamRecordRetention>,
}

/// Removes every tenant's gateway records past their retention.
pub struct ForgetOldRecordsUseCase {
    ports: ForgetOldRecordsPorts,
}

impl ForgetOldRecordsUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: ForgetOldRecordsPorts) -> Self {
        Self { ports }
    }

    /// Removes `tenant`'s request and stream records from before its
    /// cutoff at `now`. A failure is logged and answered as failed, so the
    /// other tenants are still served now.
    async fn forget_one(&self, tenant: &Tenant, now: OffsetDateTime) -> Forgotten {
        let scoped = ScopedTenant::for_background(*tenant.id());
        let cutoff = tenant.compliance().retention_cutoff(now);
        let requests = rounds(|| {
            self.ports
                .requests
                .forget_before(&scoped, cutoff, PER_STATEMENT)
        });
        let requests = match requests.await {
            Ok(removed) => removed,
            Err(error) => return failed(tenant, &error),
        };
        let streams = rounds(|| {
            self.ports
                .streams
                .forget_before(&scoped, cutoff, PER_STATEMENT)
        });
        match streams.await {
            Ok(streams) => Forgotten::Removed { requests, streams },
            Err(error) => failed(tenant, &error),
        }
    }
}

impl Command for ForgetOldRecordsUseCase {
    type Caller = ();
    type Input = OffsetDateTime;
    type Output = Result<ForgetReport, AppError>;

    /// Removes, for every tenant, the request and stream records from
    /// before the cutoff its compliance posture sets at `now`, up to a
    /// round's worth of each, and says how many went and how many tenants
    /// have more left.
    ///
    /// One tenant whose records cannot be removed does not stop the
    /// others; it is counted as failed and tried again next round.
    ///
    /// # Errors
    ///
    /// `AppError::Internal` when the tenant list cannot be read.
    async fn execute(
        &self,
        (): &(),
        _auditor: &RequestAuditor,
        now: OffsetDateTime,
    ) -> Result<ForgetReport, AppError> {
        let mut report = ForgetReport::default();
        let mut tenants = TenantBatches::over(self.ports.tenant_store.as_ref());
        while let Some(batch) = tenants.next().await? {
            for tenant in &batch {
                report = report.counting(self.forget_one(tenant, now).await);
            }
        }
        Ok(report)
    }
}

/// Runs `statement` until it removes fewer than a statement's worth, or a
/// round's statements are spent, and says how many went and whether more
/// may be left.
async fn rounds<F, Fut>(statement: F) -> Result<Removed, DomainError>
where
    F: Fn() -> Fut,
    Fut: Future<Output = Result<u64, DomainError>>,
{
    let mut count = 0_u64;
    for _ in 0..STATEMENTS_PER_ROUND {
        let removed = statement().await?;
        count = count.saturating_add(removed);
        if removed < u64::from(PER_STATEMENT.get()) {
            return Ok(Removed {
                count,
                left: Left::None,
            });
        }
    }
    Ok(Removed {
        count,
        left: Left::Some,
    })
}

/// `tenant`'s round, failed with `error`, logged.
fn failed(tenant: &Tenant, error: &DomainError) -> Forgotten {
    tracing::warn!(tenant_id = %tenant.id(), %error, "gateway records not removed");
    Forgotten::Failed
}

#[cfg(test)]
mod tests {
    use ianua_domain::shared::clock;
    use time::Duration;

    use super::*;
    use crate::test_support::retention::FakeRetainedRecords;
    use crate::test_support::tenant::{FakeTenantStore, test_tenant, test_tenant_for_ctx};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor};

    /// Runs one round at `now` over `tenants`.
    fn forget(
        tenants: Vec<Tenant>,
        requests: Arc<FakeRetainedRecords>,
        streams: Arc<FakeRetainedRecords>,
        now: OffsetDateTime,
    ) -> ForgetReport {
        let use_case = ForgetOldRecordsUseCase::new(ForgetOldRecordsPorts {
            tenant_store: Arc::new(FakeTenantStore::holding_all(tenants)),
            requests,
            streams,
        });
        let auditor = test_auditor(Arc::new(FakeEventDispatcher::new()));
        block_on(use_case.execute(&(), &auditor, now)).unwrap()
    }

    /// Acme keeps its records as long as its posture says. A request and a
    /// stream connection from before that go; yesterday's stay.
    #[test]
    fn records_past_the_retention_go_and_recent_ones_stay() {
        let acme = test_tenant_for_ctx();
        let now = clock::now();
        let cutoff = acme.compliance().retention_cutoff(now);
        let (old, recent) = (cutoff - Duration::days(1), now - Duration::days(1));
        let requests = Arc::new(FakeRetainedRecords::holding(*acme.id(), [old, recent]));
        let streams = Arc::new(FakeRetainedRecords::holding(*acme.id(), [old, recent]));

        let report = forget(vec![acme.clone()], requests.clone(), streams.clone(), now);

        assert_eq!((report.requests, report.streams), (1, 1));
        assert_eq!(requests.left(*acme.id()), [recent]);
        assert_eq!(streams.left(*acme.id()), [recent]);
        assert_eq!(report.unfinished, 0);
    }

    /// Globex's records are all within its retention. Acme's old ones go,
    /// and none of Globex's.
    #[test]
    fn another_tenants_recent_records_stay() {
        let (acme, globex) = (
            test_tenant_for_ctx(),
            test_tenant("globex", "globex.example.com"),
        );
        let now = clock::now();
        let old = acme.compliance().retention_cutoff(now) - Duration::days(1);
        let recent = now - Duration::hours(1);
        let requests = Arc::new(FakeRetainedRecords::holding(*acme.id(), [old]));
        let streams = Arc::new(FakeRetainedRecords::holding(*globex.id(), [recent]));

        let report = forget(vec![acme, globex.clone()], requests, streams.clone(), now);

        assert_eq!((report.requests, report.streams), (1, 0));
        assert_eq!(streams.left(*globex.id()), [recent]);
    }

    /// A busy tenant with more old records than a round removes keeps the
    /// rest for the next round, and is counted as unfinished.
    #[test]
    fn a_round_removes_a_bounded_number_and_says_more_are_left() {
        let acme = test_tenant_for_ctx();
        let now = clock::now();
        let old = acme.compliance().retention_cutoff(now) - Duration::days(1);
        let per_round = u64::from(PER_STATEMENT.get()) * u64::from(STATEMENTS_PER_ROUND);
        let held = usize::try_from(per_round).unwrap() + 3;
        let requests = Arc::new(FakeRetainedRecords::holding(*acme.id(), vec![old; held]));

        let report = forget(
            vec![acme.clone()],
            requests.clone(),
            Arc::new(FakeRetainedRecords::default()),
            now,
        );

        assert_eq!(report.requests, per_round);
        assert_eq!(report.unfinished, 1);
        assert_eq!(requests.left(*acme.id()).len(), 3);
    }

    /// Acme's records cannot be removed this time. Globex's still are, and
    /// Acme is counted for the next round.
    #[test]
    fn one_tenant_that_fails_does_not_stop_the_others() {
        let (acme, globex) = (
            test_tenant_for_ctx(),
            test_tenant("globex", "globex.example.com"),
        );
        let now = clock::now();
        let old = globex.compliance().retention_cutoff(now) - Duration::days(1);
        let requests =
            Arc::new(FakeRetainedRecords::holding(*globex.id(), [old]).failing_for(*acme.id()));

        let report = forget(
            vec![acme, globex],
            requests,
            Arc::new(FakeRetainedRecords::default()),
            now,
        );

        assert_eq!((report.requests, report.failed), (1, 1));
    }
}
