//! Hearing that a job is due, so a worker takes it at once instead of at
//! its next poll.
//!
//! Queuing a job that is due now tells the job channel in the same
//! transaction, so the word goes out when the change commits and never for
//! one rolled back. A worker listens on the platform database's channel and
//! counts what it hears; each lane waits for the count to move or for its
//! poll interval, whichever comes first. The poll stays the floor: a word
//! lost while the listener reconnects, or a job of a tenant with a database
//! of its own, waits no longer than it did without the channel.

use std::sync::Arc;
use std::time::Duration;

use sqlx::postgres::PgListener;
use tokio::sync::watch;

use crate::postgres::foundation::pool::Databases;

/// The channel queued jobs are announced on, as
/// `queries/scheduled_jobs/announce.sql` names it.
const JOB_CHANNEL: &str = "ianua_jobs";

/// How long the listener waits before it connects again after losing the
/// database.
const RECONNECT_AFTER: Duration = Duration::from_secs(1);

/// What a worker has heard of jobs being queued: a count each lane watches.
#[derive(Debug)]
pub struct JobArrivals {
    heard: watch::Sender<u64>,
}

impl JobArrivals {
    /// Nothing heard yet.
    #[must_use]
    pub fn new() -> Self {
        Self {
            heard: watch::Sender::new(0),
        }
    }

    /// A watch on the count, for one lane to wait on.
    #[must_use]
    pub fn watch(&self) -> watch::Receiver<u64> {
        self.heard.subscribe()
    }

    /// Counts one job announced, waking every lane waiting on the count.
    pub fn count_heard(&self) {
        self.heard
            .send_modify(|count| *count = count.wrapping_add(1));
    }

    /// Listens on the platform database of `databases` for as long as it
    /// runs, counting every job announced, and connects again whenever the
    /// database is lost.
    pub async fn listen(self: Arc<Self>, databases: Arc<Databases>) {
        loop {
            if let Err(error) = self.heard_through(&databases).await {
                tracing::warn!(%error, "the job channel was lost; lanes poll until it is back");
            }
            tokio::time::sleep(RECONNECT_AFTER).await;
        }
    }

    /// Counts every announcement one connection to the channel hears,
    /// until the connection fails.
    async fn heard_through(&self, databases: &Databases) -> Result<(), sqlx::Error> {
        let mut listener = PgListener::connect_with(databases.platform()).await?;
        listener.listen(JOB_CHANNEL).await?;
        loop {
            listener.recv().await?;
            self.count_heard();
        }
    }
}

impl Default for JobArrivals {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::ports::runtime::{Settlement, atomically};
    use ianua_app::ports::scheduling::JobQueue;
    use ianua_domain::domains::scheduling::job::ScheduledJob;
    use ianua_domain::domains::scheduling::job_type::JobType;
    use ianua_domain::shared::clock;
    use ianua_domain::types::TenantId;

    use super::*;
    use crate::postgres::foundation::unit::PgUnitOfWork;
    use crate::postgres::scheduling::PgJobQueue;
    use crate::test_support::TestDb;

    /// How long an announcement is waited for, or watched for when it must
    /// not come.
    const WAIT: Duration = Duration::from_secs(3);

    /// A mail due now for a tenant of the platform database.
    fn due_mail() -> ScheduledJob {
        let job = ScheduledJob::new(
            JobType::new("mail.send").unwrap(),
            "{}".to_owned(),
            clock::now() - time::Duration::SECOND,
            std::num::NonZeroU32::new(3).unwrap(),
        );
        job.for_tenant(TenantId::new())
    }

    /// A worker listening on `db`, with a lane's watch on what it hears.
    async fn listening(db: &TestDb) -> watch::Receiver<u64> {
        let arrivals = Arc::new(JobArrivals::new());
        let mut lane = arrivals.watch();
        tokio::spawn(Arc::clone(&arrivals).listen(Arc::clone(&db.databases)));
        tokio::time::sleep(Duration::from_millis(300)).await;
        lane.borrow_and_update();
        lane
    }

    /// A mail queued due now is heard by the listening worker at once.
    #[tokio::test]
    async fn a_job_queued_due_now_is_heard() {
        let db = TestDb::fresh().await;
        let mut lane = listening(&db).await;

        PgJobQueue::new(Arc::clone(&db.databases))
            .enqueue(&due_mail())
            .await
            .unwrap();

        let heard = tokio::time::timeout(WAIT, lane.changed()).await;
        assert!(matches!(heard, Ok(Ok(()))), "the worker heard the job");
    }

    /// A mail queued in a change that is rolled back is never heard.
    #[tokio::test]
    async fn a_job_of_a_rolled_back_change_is_not_heard() {
        let db = TestDb::fresh().await;
        let mut lane = listening(&db).await;
        let queue = PgJobQueue::new(Arc::clone(&db.databases));

        atomically(
            &PgUnitOfWork,
            async {
                queue.enqueue(&due_mail()).await.unwrap();
            },
            |()| Settlement::Rollback,
        )
        .await
        .unwrap();

        let heard = tokio::time::timeout(WAIT, lane.changed()).await;
        assert!(heard.is_err(), "nobody heard of a job rolled back");
    }
}
