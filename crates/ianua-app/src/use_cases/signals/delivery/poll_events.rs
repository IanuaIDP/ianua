//! Poll events: a poll stream's receiver acknowledges the events it took
//! and is handed the next ones waiting (RFC 8936).

use std::sync::Arc;

use ianua_domain::domains::signals::control::SignalsControlCheck as _;
use ianua_domain::domains::signals::stream::{DeliveryMethod, SignalStream};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::types::{SignalId, SignalStreamId};

use crate::acting::TenantAuthorities;
use crate::error::{AppError, OrInternal};
use crate::ports::signals::{
    PollBatch, PolledEvents, ReceiverKeys, SignalPollQueue, SignalStreamStore,
};
use crate::use_case::Query;
use crate::use_cases::signals::caller::{ReceiverSignIn, SignalsCaller, StreamActor};
use crate::use_cases::signals::lookup::existing_stream;

/// The receiver's acknowledgements and request for the next batch of security events.
pub struct PollEventsRequest {
    /// The stream polled.
    pub stream_id: SignalStreamId,
    /// The `jti` of every event the receiver took since its last poll,
    /// whether it accepted it (`ack`) or reported an error (`setErrs`).
    pub acknowledged: Vec<SignalId>,
    /// How many events to hand back at most.
    pub batch: PollBatch,
}

/// The ports [`PollEventsUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct PollEventsPorts {
    /// Where streams are kept.
    pub stream_store: Arc<dyn SignalStreamStore>,
    /// Holds each poll stream's events until they are acknowledged.
    pub poll_queue: Arc<dyn SignalPollQueue>,
    /// Hashes the key a receiver presents.
    pub receiver_keys: Arc<dyn ReceiverKeys>,
    /// What a person holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Acknowledges a poll stream's events and hands back the next ones.
pub struct PollEventsUseCase {
    ports: PollEventsPorts,
}

impl PollEventsUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: PollEventsPorts) -> Self {
        Self { ports }
    }
}

impl Query for PollEventsUseCase {
    type Caller = SignalsCaller;
    type Input = PollEventsRequest;
    type Output = Result<PolledEvents, AppError>;

    /// Drops the events `request.acknowledged` names from the stream's
    /// queue, then hands back the oldest still waiting, at most
    /// `request.batch`, and whether more wait. An event stays until it is
    /// acknowledged, so a poll whose answer is lost is handed the same
    /// events again.
    ///
    /// Nothing is put on record: polling is the stream's delivery itself,
    /// as often as the receiver reads, not a change anyone makes to the
    /// stream. Each event handed out was recorded when it was raised.
    ///
    /// The stream's own receiver polls with its key; a person who may
    /// change signal streams may poll any of the tenant's, since the events
    /// name people and what happened to them.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the session or key no longer
    ///   counts, or the receiver's key is not its stream's.
    /// - `AppError::Forbidden` when the person may not change signal
    ///   streams, or the receiver names another stream.
    /// - `AppError::NotFound` when the tenant has no such stream.
    /// - `AppError::Conflict` when the stream is pushed, not polled.
    /// - `AppError::Internal` on storage failure.
    async fn execute(
        &self,
        caller: &SignalsCaller,
        request: PollEventsRequest,
    ) -> Result<PolledEvents, AppError> {
        let tenant = caller.tenant();
        let streams = self.ports.stream_store.as_ref();
        let receivers = ReceiverSignIn {
            streams,
            keys: self.ports.receiver_keys.as_ref(),
        };
        let actor =
            StreamActor::of(caller, self.ports.tenant_authorities.as_ref(), receivers).await?;
        let stream = existing_stream(streams, &tenant, &request.stream_id).await?;
        actor
            .manager()
            .ensure_may_manage(stream.id())
            .map_err(AppError::from_domain)?;
        ensure_polled(&stream)?;
        let queue = self.ports.poll_queue.as_ref();
        if !request.acknowledged.is_empty() {
            queue
                .acknowledge(&tenant, stream.id(), &request.acknowledged)
                .await
                .or_internal()?;
        }
        queue
            .next(&tenant, stream.id(), request.batch)
            .await
            .or_internal()
    }
}

/// Refuses unless `stream` is polled.
///
/// # Errors
///
/// `AppError::Conflict` when it is pushed.
fn ensure_polled(stream: &SignalStream<ResolvedTenant>) -> Result<(), AppError> {
    match stream.delivery_method() {
        DeliveryMethod::Poll => Ok(()),
        DeliveryMethod::Push => Err(AppError::Conflict(message!(
            "signals-the-stream-is-pushed-to-its",
            "the stream is pushed to its endpoint, not polled"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{SignalsAction, SystemPermission};
    use ianua_domain::domains::signals::stream::{StreamStatus, StreamVerificationStatus};
    use ianua_domain::shared::security::secret::Secret;

    use super::*;
    use crate::ports::signals::{Backlog, QueuedEvent, SecurityEventToken};
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::signals::{
        FakeSignalPollQueue, FakeSignalStreamStore, TEST_RECEIVER_KEY, test_stream,
    };
    use crate::test_support::{block_on, test_ctx};
    use crate::use_cases::signals::caller::ReceiverCaller;

    /// The payroll app's poll stream, holding `waiting` events, and its id.
    fn seeded(waiting: usize) -> (PollEventsPorts, Arc<FakeSignalPollQueue>, SignalStreamId) {
        let mut row = test_stream(StreamStatus::Active, StreamVerificationStatus::Verified);
        row.delivery_method = DeliveryMethod::Poll;
        let id = row.id;
        let queue = Arc::new(FakeSignalPollQueue::empty());
        for n in 0..waiting {
            let event = QueuedEvent {
                jti: SignalId::new(),
                token: SecurityEventToken::new(format!("token-{n}")),
            };
            block_on(queue.enqueue(&test_ctx().tenant(), &id, &event)).unwrap();
        }
        let ports = PollEventsPorts {
            stream_store: Arc::new(FakeSignalStreamStore::holding(test_ctx().tenant_id(), row)),
            poll_queue: queue.clone(),
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding_everything()),
            ..PollEventsPorts::fakes()
        };
        (ports, queue, id)
    }

    /// Polls `stream_id` as `caller`, acknowledging `acknowledged`, two
    /// events at most.
    fn poll_as(
        ports: PollEventsPorts,
        caller: &SignalsCaller,
        stream_id: SignalStreamId,
        acknowledged: Vec<SignalId>,
    ) -> Result<PolledEvents, AppError> {
        let use_case = PollEventsUseCase::new(ports);
        block_on(use_case.execute(
            caller,
            PollEventsRequest {
                stream_id,
                acknowledged,
                batch: PollBatch::new(2).unwrap(),
            },
        ))
    }

    /// Polls `stream_id` as Ann.
    fn poll(
        ports: PollEventsPorts,
        stream_id: SignalStreamId,
        acknowledged: Vec<SignalId>,
    ) -> Result<PolledEvents, AppError> {
        let ann = SignalsCaller::Person(test_ctx());
        poll_as(ports, &ann, stream_id, acknowledged)
    }

    /// The receiver of `stream_id`, presenting `key`.
    fn receiver(stream_id: SignalStreamId, key: &str) -> SignalsCaller {
        SignalsCaller::Receiver(ReceiverCaller {
            tenant: test_ctx().tenant(),
            stream_id,
            key: Secret::new(key),
        })
    }

    /// Three events wait for the payroll app. It is handed the oldest two
    /// and told more wait.
    #[test]
    fn the_oldest_events_are_handed_back_with_word_of_more() {
        let (ports, _, id) = seeded(3);

        let polled = poll(ports, id, Vec::new()).unwrap();

        assert_eq!(polled.events.len(), 2);
        assert_eq!(polled.events[0].token.as_str(), "token-0");
        assert_eq!(polled.backlog, Backlog::MoreWaiting);
    }

    /// The payroll app's receiver polls with the key its stream was
    /// registered with, not a tenant API key. It is handed its events.
    #[test]
    fn the_streams_own_receiver_polls_with_its_key() {
        let (mut ports, _, id) = seeded(1);
        ports.tenant_authorities = Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        let polled = poll_as(ports, &receiver(id, TEST_RECEIVER_KEY), id, Vec::new()).unwrap();

        assert_eq!(polled.events.len(), 1);
    }

    /// Polling with an incorrect receiver key returns an unauthenticated
    /// error and leaves both events queued.
    #[test]
    fn a_receiver_with_another_key_may_not_poll() {
        let (ports, queue, id) = seeded(2);

        let result = poll_as(ports, &receiver(id, "crm-stream-key"), id, Vec::new());

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(queue.held_for(&id).len(), 2);
    }

    /// The payroll app acknowledges the two it took. Its next poll hands
    /// back the last one, and nothing more waits.
    #[test]
    fn acknowledged_events_are_not_handed_back_again() {
        let (ports, queue, id) = seeded(3);
        let taken: Vec<SignalId> = queue.held_for(&id)[..2]
            .iter()
            .map(|event| event.jti)
            .collect();

        let polled = poll(ports, id, taken).unwrap();

        assert_eq!(polled.events.len(), 1);
        assert_eq!(polled.events[0].token.as_str(), "token-2");
        assert_eq!(polled.backlog, Backlog::Drained);
    }

    /// The answer to a poll is lost on the way. The next poll, which
    /// acknowledges nothing, hands back the same events.
    #[test]
    fn unacknowledged_events_are_handed_back_again() {
        let (ports, queue, id) = seeded(1);
        let jti = queue.held_for(&id)[0].jti;

        let polled = poll(ports, id, Vec::new()).unwrap();

        assert_eq!(polled.events[0].jti, jti);
        assert_eq!(queue.held_for(&id).len(), 1);
    }

    /// A stream that is pushed to its endpoint is not polled.
    #[test]
    fn a_push_stream_is_not_polled() {
        let row = test_stream(StreamStatus::Active, StreamVerificationStatus::Verified);
        let id = row.id;
        let ports = PollEventsPorts {
            stream_store: Arc::new(FakeSignalStreamStore::holding(test_ctx().tenant_id(), row)),
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding_everything()),
            ..PollEventsPorts::fakes()
        };

        let result = poll(ports, id, Vec::new());

        assert!(matches!(result, Err(AppError::Conflict(_))));
    }

    /// Ann names a stream the tenant does not have. It is not found.
    #[test]
    fn an_unknown_stream_is_not_found() {
        let (ports, _, _) = seeded(1);

        let result = poll(ports, SignalStreamId::new(), Vec::new());

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Stream viewing rights do not permit polling with acknowledgements;
    /// the request is forbidden and both events remain queued.
    #[test]
    fn a_viewer_may_not_poll() {
        let (mut ports, queue, id) = seeded(2);
        ports.tenant_authorities = Arc::new(FakeTenantAuthorities::holding(&[
            SystemPermission::Signals(SignalsAction::View),
        ]));
        let waiting: Vec<SignalId> = queue.held_for(&id).iter().map(|event| event.jti).collect();

        let result = poll(ports, id, waiting);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(queue.held_for(&id).len(), 2);
    }

    /// Polling a stream with a signed-out session returns an
    /// unauthenticated error.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let (mut ports, _, id) = seeded(1);
        ports.tenant_authorities = Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        let result = poll(ports, id, Vec::new());

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
