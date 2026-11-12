//! Hearing that work is waiting, so a worker's loop takes it at once
//! instead of at its next poll.
//!
//! Each kind of waiting work is announced on a channel of its own in the
//! transaction that made it, so the word goes out when the change commits
//! and never for one rolled back: a job due now, an event recorded for the
//! bus, an event the gateway kept for the trail. A worker listens on the
//! platform database's channels over one connection and counts what it
//! hears on each; a loop waits for its count to move or for its poll
//! interval, whichever comes first. The poll stays the floor: a word lost
//! while the listener reconnects, or work of a tenant with a database of
//! its own, waits no longer than it did without the channel.

use std::sync::Arc;
use std::time::Duration;

use sqlx::postgres::PgListener;
use tokio::sync::watch;

use crate::postgres::foundation::pool::Databases;

/// How long the listener waits before it connects again after losing the
/// database.
const RECONNECT_AFTER: Duration = Duration::from_secs(1);

/// A kind of waiting work, and the channel it is announced on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Channel {
    /// A job due now, as `queries/scheduled_jobs/announce.sql` says.
    Jobs,
    /// An event recorded for the bus, a tenant's or the platform's, as
    /// `queries/event_outbox/announce.sql` says.
    Events,
    /// An event the gateway kept for the trail, as
    /// `queries/gateway_events/announce.sql` says.
    GatewayEvents,
}

impl Channel {
    /// Every channel.
    const ALL: [Self; 3] = [Self::Jobs, Self::Events, Self::GatewayEvents];

    /// The channel's name in the database.
    fn name(self) -> &'static str {
        match self {
            Self::Jobs => "ianua_jobs",
            Self::Events => "ianua_events",
            Self::GatewayEvents => "ianua_gateway_events",
        }
    }

    /// The channel the database name `name` is.
    fn named(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|channel| channel.name() == name)
    }
}

/// What a worker has heard on each channel: a count each loop watches.
#[derive(Debug)]
pub struct Announcements {
    jobs: watch::Sender<u64>,
    events: watch::Sender<u64>,
    gateway_events: watch::Sender<u64>,
}

impl Announcements {
    /// Nothing heard yet.
    #[must_use]
    pub fn new() -> Self {
        Self {
            jobs: watch::Sender::new(0),
            events: watch::Sender::new(0),
            gateway_events: watch::Sender::new(0),
        }
    }

    /// A watch on what `channel` announced, for one loop to wait on.
    #[must_use]
    pub fn watch(&self, channel: Channel) -> watch::Receiver<u64> {
        self.count_of(channel).subscribe()
    }

    /// Counts one announcement on `channel`, waking every loop waiting on
    /// it.
    pub fn count_heard(&self, channel: Channel) {
        self.count_of(channel)
            .send_modify(|count| *count = count.wrapping_add(1));
    }

    /// Listens on the platform database of `databases` for as long as it
    /// runs, counting every announcement on every channel, and connects
    /// again whenever the database is lost.
    pub async fn listen(self: Arc<Self>, databases: Arc<Databases>) {
        loop {
            if let Err(error) = self.heard_through(&databases).await {
                tracing::warn!(%error, "the work channels were lost; loops poll until they are back");
            }
            tokio::time::sleep(RECONNECT_AFTER).await;
        }
    }

    /// Counts every announcement one connection to the channels hears,
    /// until the connection fails.
    async fn heard_through(&self, databases: &Databases) -> Result<(), sqlx::Error> {
        let mut listener = PgListener::connect_with(databases.platform()).await?;
        listener.listen_all(Channel::ALL.map(Channel::name)).await?;
        loop {
            let heard = listener.recv().await?;
            if let Some(channel) = Channel::named(heard.channel()) {
                self.count_heard(channel);
            }
        }
    }

    /// The count `channel` keeps.
    fn count_of(&self, channel: Channel) -> &watch::Sender<u64> {
        match channel {
            Channel::Jobs => &self.jobs,
            Channel::Events => &self.events,
            Channel::GatewayEvents => &self.gateway_events,
        }
    }
}

impl Default for Announcements {
    fn default() -> Self {
        Self::new()
    }
}

/// Waits until `heard` moves. A listener gone for good never moves it
/// again, so the loop is left to its poll.
pub async fn wait_for_announcement(heard: &mut watch::Receiver<u64>) {
    if heard.changed().await.is_err() {
        std::future::pending::<()>().await;
    }
}

#[cfg(test)]
mod tests {
    // The event test records straight through the trail's dispatcher to
    // raise an announcement, as no use case is under test here.
    #![allow(clippy::disallowed_methods)]

    use ianua_app::ports::runtime::{Settlement, atomically};
    use ianua_app::ports::scheduling::JobQueue;
    use ianua_app::ports::shared::EventDispatcher;
    use ianua_domain::domains::audit::builder::AuditContext;
    use ianua_domain::domains::scheduling::job::ScheduledJob;
    use ianua_domain::domains::scheduling::job_type::JobType;
    use ianua_domain::shared::clock;
    use ianua_domain::types::TenantId;

    use super::*;
    use crate::postgres::audit::PgEventDispatcher;
    use crate::postgres::foundation::unit::PgUnitOfWork;
    use crate::postgres::scheduling::PgJobQueue;
    use crate::test_support::TestDb;
    use crate::test_support::rows::audit::{
        chain_heads, failed_sign_in, saved_organization, saved_tenant_of,
    };

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

    /// A worker listening on `db`, with a loop's watch on `channel`.
    async fn listening(db: &TestDb, channel: Channel) -> watch::Receiver<u64> {
        let announcements = Arc::new(Announcements::new());
        let mut heard = announcements.watch(channel);
        tokio::spawn(Arc::clone(&announcements).listen(Arc::clone(&db.databases)));
        tokio::time::sleep(Duration::from_millis(300)).await;
        heard.borrow_and_update();
        heard
    }

    /// A mail queued due now is heard on the job channel at once.
    #[tokio::test]
    async fn a_job_queued_due_now_is_heard() {
        let db = TestDb::fresh().await;
        let mut heard = listening(&db, Channel::Jobs).await;

        PgJobQueue::new(Arc::clone(&db.databases))
            .enqueue(&due_mail())
            .await
            .unwrap();

        let moved = tokio::time::timeout(WAIT, heard.changed()).await;
        assert!(matches!(moved, Ok(Ok(()))), "the worker heard the job");
    }

    /// A mail queued in a change that is rolled back is never heard.
    #[tokio::test]
    async fn a_job_of_a_rolled_back_change_is_not_heard() {
        let db = TestDb::fresh().await;
        let mut heard = listening(&db, Channel::Jobs).await;
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

        let moved = tokio::time::timeout(WAIT, heard.changed()).await;
        assert!(moved.is_err(), "nobody heard of a job rolled back");
    }

    /// A failed sign-in recorded for one of Acme's tenants is heard on the
    /// event channel, so the relay sends it at once.
    #[tokio::test]
    async fn a_recorded_event_is_heard() {
        let db = TestDb::fresh().await;
        let organization = saved_organization(&db.databases).await;
        let tenant = saved_tenant_of(&db.databases, organization).await;
        let mut heard = listening(&db, Channel::Events).await;

        PgEventDispatcher::new(Arc::clone(&db.databases), chain_heads())
            .dispatch(&[failed_sign_in(*tenant, 1)], &AuditContext::system())
            .await
            .unwrap();

        let moved = tokio::time::timeout(WAIT, heard.changed()).await;
        assert!(matches!(moved, Ok(Ok(()))), "the relay heard the event");
    }

    /// A job announced is heard on the job channel alone, not on the
    /// others.
    #[tokio::test]
    async fn a_job_is_heard_on_its_own_channel_alone() {
        let db = TestDb::fresh().await;
        let mut events = listening(&db, Channel::Events).await;

        PgJobQueue::new(Arc::clone(&db.databases))
            .enqueue(&due_mail())
            .await
            .unwrap();

        let moved = tokio::time::timeout(WAIT, events.changed()).await;
        assert!(moved.is_err(), "the event channel heard nothing");
    }
}
