//! List dead jobs: the jobs that used up their tries, for operators to
//! look into, newest first and a page at a time.

use std::sync::Arc;

use ianua_domain::domains::scheduling::job::ScheduledJob;
use ianua_domain::domains::scheduling::job_type::JobType;
use ianua_domain::types::{JobId, TenantId};
use time::OffsetDateTime;

use crate::acting::OperatorAuthorities;
use crate::context::OperatorCaller;
use crate::error::AppError;
use crate::listing::{Page, PageRequest};
use crate::ports::scheduling::JobQueue;
use crate::use_case::Query;

/// A job given up on, as an operator reads it. The payload is left out:
/// it is the handler's, and may name what only its tenant should see.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeadJob {
    /// The job's id.
    pub id: JobId,
    /// What kind of work it was.
    pub job_type: JobType,
    /// The tenant it worked for, or `None` for the platform's own work.
    pub tenant_id: Option<TenantId>,
    /// How many times it ran.
    pub attempts: u32,
    /// Why its last run failed.
    pub reason: String,
    /// When it was queued.
    pub created_at: OffsetDateTime,
    /// When it last ran.
    pub last_attempted_at: Option<OffsetDateTime>,
}

/// The ports [`ListDeadUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ListDeadPorts {
    /// The job queue.
    pub queue: Arc<dyn JobQueue>,
    /// What an operator may do on the platform.
    pub operator_authorities: Arc<dyn OperatorAuthorities>,
}

/// Lists the jobs that used up their tries.
pub struct ListDeadUseCase {
    ports: ListDeadPorts,
}

impl ListDeadUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: ListDeadPorts) -> Self {
        Self { ports }
    }
}

impl Query for ListDeadUseCase {
    type Caller = OperatorCaller;
    type Input = PageRequest;
    type Output = Result<Page<DeadJob>, AppError>;

    /// The page of dead jobs `page` asks for, newest first, across every
    /// tenant.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the operator or the key no longer
    ///   exists.
    /// - `AppError::Forbidden` when the key is another operator's, no longer
    ///   works, or its operator is disabled.
    /// - `AppError::Internal` when the queue cannot be read.
    async fn execute(
        &self,
        caller: &OperatorCaller,
        page: PageRequest,
    ) -> Result<Page<DeadJob>, AppError> {
        self.ports.operator_authorities.authority(caller).await?;
        let jobs = self
            .ports
            .queue
            .list_dead(&page)
            .await
            .map_err(AppError::from_domain)?;
        Ok(jobs.map(|job| dead_job(&job)))
    }
}

/// `job` as an operator reads it.
fn dead_job(job: &ScheduledJob) -> DeadJob {
    DeadJob {
        id: *job.id(),
        job_type: job.job_type().clone(),
        tenant_id: job.tenant_id().copied(),
        attempts: job.attempt(),
        reason: job.error().unwrap_or_default().to_owned(),
        created_at: job.created_at(),
        last_attempted_at: job.last_attempted_at(),
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;

    use ianua_domain::domains::scheduling::job::NextAttempt;
    use ianua_domain::shared::clock;
    use ianua_domain::types::UntrustedText;

    use super::*;
    use crate::test_support::acting::{FakeOperatorAuthorities, Refusal};
    use crate::test_support::block_on;
    use crate::test_support::operator::test_operator_caller;
    use crate::test_support::scheduling::FakeJobQueue;

    /// A mail job that bounced on its only try.
    fn dead_mail() -> ScheduledJob {
        let mut job = ScheduledJob::new(
            JobType::new("mail.send").unwrap(),
            r#"{"to":"ann@acme.com"}"#.to_owned(),
            clock::now(),
            NonZeroU32::MIN,
        );
        job.mark_running().unwrap();
        job.mark_failed(UntrustedText::record("bounced"), NextAttempt::AsScheduled)
            .unwrap();
        job
    }

    fn pending_mail() -> ScheduledJob {
        ScheduledJob::new(
            JobType::new("mail.send").unwrap(),
            "{}".to_owned(),
            clock::now(),
            NonZeroU32::MIN,
        )
    }

    fn list(authorities: FakeOperatorAuthorities) -> Result<Page<DeadJob>, AppError> {
        let queue = Arc::new(FakeJobQueue::with_jobs(vec![dead_mail(), pending_mail()]));
        let uc = ListDeadUseCase::new(ListDeadPorts {
            queue,
            operator_authorities: Arc::new(authorities),
        });
        block_on(uc.execute(&test_operator_caller(), PageRequest::default()))
    }

    /// Olga, an operator, lists dead jobs. She sees the bounced mail and
    /// why, but not the pending one, nor the payload naming Ann.
    #[test]
    fn an_operator_sees_the_dead_jobs_and_why() {
        let page = list(FakeOperatorAuthorities::admitting()).unwrap();

        assert_eq!(page.items.len(), 1);
        assert_eq!(page.items[0].reason, "bounced");
        assert_eq!(page.items[0].attempts, 1);
    }

    /// A disabled operator's key is refused access to the dead-job list.
    #[test]
    fn a_disabled_operator_is_refused() {
        let result = list(FakeOperatorAuthorities::refusing(Refusal::Forbidden));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }
}
