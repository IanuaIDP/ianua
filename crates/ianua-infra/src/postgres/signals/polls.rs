//! The tokens poll streams hold until their receivers acknowledge them
//! (RFC 8936), each row under row-level security.
//!
//! Every call names the tenant and the stream, so a stream of another
//! tenant holds and hands back nothing. Tokens are handed back oldest
//! first, in the order they were queued, and dropped only once
//! acknowledged; deleting a stream drops what it held.

mod record;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::signals::{Backlog, PollBatch, PolledEvents, QueuedEvent, SignalPollQueue};
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{SignalId, SignalStreamId};
use uuid::Uuid;

use self::record::EventRecord;
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The Postgres queue of tokens held for poll streams.
pub struct PgSignalPollQueue {
    databases: Arc<Databases>,
}

impl TenantScoped for PgSignalPollQueue {}

impl PgSignalPollQueue {
    /// A queue keeping held tokens in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

/// What a poll hands back from `held`, read one past `batch`: at most
/// `batch` of them, and whether more wait.
fn polled(mut held: Vec<QueuedEvent>, batch: PollBatch) -> PolledEvents {
    let most = usize::from(batch.get());
    let backlog = if held.len() > most {
        Backlog::MoreWaiting
    } else {
        Backlog::Drained
    };
    held.truncate(most);
    PolledEvents {
        events: held,
        backlog,
    }
}

#[async_trait]
impl SignalPollQueue for PgSignalPollQueue {
    async fn enqueue(
        &self,
        tenant_id: &ScopedTenant,
        stream_id: &SignalStreamId,
        event: &QueuedEvent,
    ) -> Result<(), DomainError> {
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/signal_poll_events/enqueue.sql",
                    tenant_id.as_uuid(),
                    stream_id.as_uuid(),
                    event.jti.as_uuid(),
                    event.token.as_str()
                )
                .execute(connection)
                .await?;
                Ok(())
            },
        )
        .await
    }

    async fn acknowledge(
        &self,
        tenant_id: &ScopedTenant,
        stream_id: &SignalStreamId,
        jtis: &[SignalId],
    ) -> Result<(), DomainError> {
        let jtis: Vec<Uuid> = jtis.iter().map(|jti| *jti.as_uuid()).collect();
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/signal_poll_events/acknowledge.sql",
                    tenant_id.as_uuid(),
                    stream_id.as_uuid(),
                    &jtis
                )
                .execute(connection)
                .await?;
                Ok(())
            },
        )
        .await
    }

    async fn next(
        &self,
        tenant_id: &ScopedTenant,
        stream_id: &SignalStreamId,
        batch: PollBatch,
    ) -> Result<PolledEvents, DomainError> {
        let read = i64::from(batch.get()).saturating_add(1);
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    EventRecord,
                    "queries/signal_poll_events/next.sql",
                    tenant_id.as_uuid(),
                    stream_id.as_uuid(),
                    read
                )
                .fetch_all(connection)
                .await
            },
        )
        .await?;
        let held = records.into_iter().map(EventRecord::into_event).collect();
        Ok(polled(held, batch))
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::ports::signals::{SignalStreamStore, StreamChallenge};
    use ianua_domain::domains::signals::stream::SignalStream;
    use ianua_domain::isolation::scope::ResolvedTenant;
    use ianua_domain::types::TenantId;

    use super::*;
    use crate::postgres::signals::PgSignalStreamStore;
    use crate::test_support::TestDb;
    use crate::test_support::rows::signals::{queued_event, stream_row};

    struct Fixture {
        db: TestDb,
        queue: PgSignalPollQueue,
        tenant: ScopedTenant,
        stream: SignalStreamId,
    }

    /// A fresh database, the queue on it, and a tenant with one stream.
    async fn fixture() -> Fixture {
        let db = TestDb::fresh().await;
        let tenant = ScopedTenant::for_background(TenantId::new());
        let stream = a_stream(&db, &tenant).await;
        Fixture {
            queue: PgSignalPollQueue::new(Arc::clone(&db.databases)),
            tenant,
            stream,
            db,
        }
    }

    /// Saves a stream in `tenant` through its store.
    async fn a_stream(db: &TestDb, tenant: &ScopedTenant) -> SignalStreamId {
        let stream: SignalStream<ResolvedTenant> =
            SignalStream::reconstitute(stream_row("https://app.acme.com/sse")).unwrap();
        PgSignalStreamStore::new(Arc::clone(&db.databases))
            .save(tenant, &stream, StreamChallenge::Kept)
            .await
            .unwrap();
        *stream.id()
    }

    fn batch(count: u16) -> PollBatch {
        PollBatch::new(count).unwrap()
    }

    fn tokens(polled: &PolledEvents) -> Vec<&str> {
        polled
            .events
            .iter()
            .map(|event| event.token.as_str())
            .collect()
    }

    impl Fixture {
        async fn enqueue_all(&self, events: &[&QueuedEvent]) {
            for event in events {
                self.queue
                    .enqueue(&self.tenant, &self.stream, event)
                    .await
                    .unwrap();
            }
        }

        async fn next(&self, count: u16) -> PolledEvents {
            self.queue
                .next(&self.tenant, &self.stream, batch(count))
                .await
                .unwrap()
        }
    }

    /// A poll hands the held tokens back oldest first, the batch's worth,
    /// and says more wait; nothing is dropped by handing it back.
    #[tokio::test]
    async fn a_poll_hands_back_the_oldest_tokens_first() {
        let fx = fixture().await;
        let (one, two, three) = (
            queued_event("one"),
            queued_event("two"),
            queued_event("three"),
        );
        fx.enqueue_all(&[&one, &two, &three]).await;

        let first = fx.next(2).await;
        let again = fx.next(10).await;

        assert_eq!(tokens(&first), ["one", "two"]);
        assert_eq!(first.backlog, Backlog::MoreWaiting);
        assert_eq!(tokens(&again), ["one", "two", "three"]);
        assert_eq!(again.backlog, Backlog::Drained);
        assert_eq!(again.events.first(), Some(&one));
    }

    /// An acknowledged token goes, the others stay, and an id the queue
    /// does not hold is passed over.
    #[tokio::test]
    async fn an_acknowledged_token_is_dropped() {
        let fx = fixture().await;
        let (one, two) = (queued_event("one"), queued_event("two"));
        fx.enqueue_all(&[&one, &two]).await;

        fx.queue
            .acknowledge(&fx.tenant, &fx.stream, &[one.jti, SignalId::new()])
            .await
            .unwrap();

        assert_eq!(tokens(&fx.next(10).await), ["two"]);
    }

    /// A token queued twice under one id is held once.
    #[tokio::test]
    async fn a_token_queued_twice_is_held_once() {
        let fx = fixture().await;
        let one = queued_event("one");

        fx.enqueue_all(&[&one, &one]).await;

        assert_eq!(tokens(&fx.next(10).await), ["one"]);
    }

    /// Another tenant's enqueue and acknowledgement leave the stream's
    /// original token intact, add no planted token, and reveal no events
    /// when polled.
    #[tokio::test]
    async fn another_tenant_reaches_nothing_a_stream_holds() {
        let fx = fixture().await;
        let mallory = ScopedTenant::for_background(TenantId::new());
        let held = queued_event("held");
        fx.enqueue_all(&[&held]).await;

        fx.queue
            .enqueue(&mallory, &fx.stream, &queued_event("planted"))
            .await
            .unwrap();
        fx.queue
            .acknowledge(&mallory, &fx.stream, &[held.jti])
            .await
            .unwrap();
        let read = fx
            .queue
            .next(&mallory, &fx.stream, batch(10))
            .await
            .unwrap();

        assert!(read.events.is_empty());
        assert_eq!(tokens(&fx.next(10).await), ["held"]);
    }

    /// A stream with nothing held hands back nothing, and nothing waits.
    #[tokio::test]
    async fn an_empty_stream_hands_back_nothing() {
        let fx = fixture().await;

        let polled = fx.next(10).await;

        assert!(polled.events.is_empty());
        assert_eq!(polled.backlog, Backlog::Drained);
    }

    /// Deleting a stream drops what it held.
    #[tokio::test]
    async fn a_deleted_stream_drops_what_it_held() {
        let fx = fixture().await;
        fx.enqueue_all(&[&queued_event("one")]).await;

        PgSignalStreamStore::new(Arc::clone(&fx.db.databases))
            .delete(&fx.tenant, &fx.stream)
            .await
            .unwrap();

        assert!(fx.next(10).await.events.is_empty());
    }

    /// A tenant with a database of its own holds its tokens there.
    #[tokio::test]
    async fn a_tenant_with_its_own_database_holds_its_tokens_there() {
        let fx = fixture().await;
        let own = TestDb::fresh().await;
        let apart = ScopedTenant::for_background(TenantId::new());
        fx.db.databases.register(*apart, own.as_dedicated());
        let stream = a_stream(&fx.db, &apart).await;

        fx.queue
            .enqueue(&apart, &stream, &queued_event("apart"))
            .await
            .unwrap();

        let there = PgSignalPollQueue::new(Arc::clone(&own.databases));
        let polled = there.next(&apart, &stream, batch(10)).await.unwrap();
        assert_eq!(tokens(&polled), ["apart"]);
    }
}
