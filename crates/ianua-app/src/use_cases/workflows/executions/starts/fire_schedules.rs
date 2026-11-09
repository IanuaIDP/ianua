//! Fire schedules: the sweep that runs each minute and starts every version
//! in service whose schedule fires in that minute, read in its tenant's
//! timezone.
//!
//! Each firing is queued as a job keyed by the version and the minute, so a
//! minute swept twice, by two workers or after a retry, starts the version
//! once.

use std::sync::Arc;

use time::OffsetDateTime;

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::listing::{Limit, PageRequest};
use crate::ports::scheduling::TimeZones;
use crate::ports::workflows::{ScheduledVersion, ScheduledWorkflows};
use crate::use_case::Command;
use crate::use_cases::scheduling::PlanReport;
use crate::use_cases::workflows::executions::starts::schedule_job::ScheduledStarts;

/// How many scheduled versions are read at a time.
const PAGE: u32 = 500;

/// Seconds in a minute, which firings are counted in.
const MINUTE: i64 = 60;

/// The ports [`FireSchedulesUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct FireSchedulesPorts {
    /// The versions in service that start on a schedule, across tenants.
    pub scheduled: Arc<dyn ScheduledWorkflows>,
    /// Reads the moment as each tenant's clock shows it.
    pub time_zones: Arc<dyn TimeZones>,
    /// Where schedule jobs are queued.
    pub jobs: ScheduledStarts,
}

/// Starts the versions whose schedule fires now.
///
/// It runs as a sweep: no one calls it, so it takes no caller.
pub struct FireSchedulesUseCase {
    ports: FireSchedulesPorts,
}

impl FireSchedulesUseCase {
    /// A sweep over `ports`.
    #[must_use]
    pub fn new(ports: FireSchedulesPorts) -> Self {
        Self { ports }
    }

    /// Whether `version`'s schedule fires at `now`. A tenant whose timezone
    /// cannot be read is logged and skipped this minute.
    fn fires(&self, version: &ScheduledVersion, now: OffsetDateTime) -> bool {
        match self.ports.time_zones.local(&version.timezone, now) {
            Ok(local) => version.schedule.fires_at(local),
            Err(error) => {
                tracing::warn!(
                    workflow_id = %version.workflow_id,
                    %error,
                    "schedule not read: the tenant's timezone is unknown"
                );
                false
            }
        }
    }
}

impl Command for FireSchedulesUseCase {
    type Caller = ();
    type Input = OffsetDateTime;
    type Output = Result<PlanReport, AppError>;

    /// Queues a start for each version in service whose schedule fires in
    /// the minute `now` falls in. Records nothing: each start records
    /// itself, or its refusal, when its job runs.
    ///
    /// # Errors
    ///
    /// - `AppError::Internal` when the versions cannot be read or a job
    ///   cannot be queued. The minute's sweep runs again, and what was
    ///   queued is not queued twice.
    async fn execute(
        &self,
        (): &(),
        _auditor: &RequestAuditor,
        now: OffsetDateTime,
    ) -> Result<PlanReport, AppError> {
        let minute = now.unix_timestamp().div_euclid(MINUTE);
        let mut report = PlanReport::default();
        let mut next = Some(PageRequest::first(Limit::internal(PAGE)));
        while let Some(asked) = next.take() {
            let page = self
                .ports
                .scheduled
                .list_scheduled(&asked)
                .await
                .or_internal()?;
            next = asked.following(&page);
            for version in page.items.iter().filter(|version| self.fires(version, now)) {
                let enqueued = self
                    .ports
                    .jobs
                    .queue(version.tenant_id, version.workflow_id, minute)
                    .await?;
                report = report.counting(enqueued);
            }
        }
        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;
    use std::sync::Mutex;

    use async_trait::async_trait;
    use ianua_domain::domains::workflows::triggers::CronSchedule;
    use ianua_domain::shared::errors::DomainError;
    use ianua_domain::types::{TenantId, Timezone, WorkflowId};

    use super::*;
    use crate::listing::{Page, SortOrder};
    use crate::ports::workflows::ScheduledVersionSortField;
    use crate::test_support::scheduling::{FakeJobQueue, UtcTimeZones};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor};
    use crate::use_cases::workflows::executions::starts::schedule_job::START_SCHEDULED_JOB;

    /// Scheduled versions a test lays out, handed out a page at a time.
    struct Laid(Mutex<Vec<ScheduledVersion>>);

    #[async_trait]
    impl ScheduledWorkflows for Laid {
        async fn list_scheduled(
            &self,
            request: &PageRequest,
        ) -> Result<Page<ScheduledVersion>, DomainError> {
            let all = self.0.lock().unwrap().clone();
            let order = SortOrder::<ScheduledVersionSortField>::default();
            Ok(request.keyset(&order)?.cut(all))
        }
    }

    fn version(schedule: &str) -> ScheduledVersion {
        ScheduledVersion {
            tenant_id: TenantId::new(),
            workflow_id: WorkflowId::new(),
            schedule: CronSchedule::parse(schedule).unwrap(),
            timezone: Timezone::new("UTC").unwrap(),
        }
    }

    fn sweep(
        versions: Vec<ScheduledVersion>,
        now: OffsetDateTime,
    ) -> (PlanReport, Arc<FakeJobQueue>) {
        let queue = Arc::new(FakeJobQueue::new());
        let uc = FireSchedulesUseCase::new(FireSchedulesPorts {
            scheduled: Arc::new(Laid(Mutex::new(versions))),
            time_zones: Arc::new(UtcTimeZones),
            jobs: ScheduledStarts {
                queue: queue.clone(),
                attempts: NonZeroU32::MIN,
            },
        });
        let report = block_on(uc.execute(
            &(),
            &test_auditor(Arc::new(FakeEventDispatcher::new())),
            now,
        ))
        .unwrap();
        (report, queue)
    }

    /// Monday 2026-10-26 at 09:00 UTC.
    fn monday_nine() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_793_005_200).unwrap()
    }

    /// At nine on a Monday, the weekday-morning report fires and the Sunday
    /// clean-up does not.
    #[test]
    fn only_the_versions_firing_this_minute_start() {
        let versions = vec![version("0 9 * * 1-5"), version("0 3 * * 0")];

        let (report, queue) = sweep(versions, monday_nine());

        assert_eq!(report.queued, 1);
        assert_eq!(queue.jobs_of(START_SCHEDULED_JOB).len(), 1);
    }

    /// More versions fire than one page holds. Every one of them starts.
    #[test]
    fn every_page_of_versions_is_swept() {
        let versions: Vec<ScheduledVersion> = (0..PAGE + 3).map(|_| version("* * * * *")).collect();

        let (report, _) = sweep(versions, monday_nine());

        assert_eq!(u64::from(report.queued), u64::from(PAGE + 3));
    }
}
