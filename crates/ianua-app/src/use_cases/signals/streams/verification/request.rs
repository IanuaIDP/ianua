//! Request verification: send a stream a Shared Signals verification event
//! its receiver asked for, so it can see the stream works end to end.

use std::sync::Arc;

use ianua_domain::domains::signals::verification::RequestedState;
use ianua_domain::message;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::SignalStreamId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::signals::{ReceiverKeys, SignalStreamStore, VerificationThrottle};
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::signals::caller::{ReceiverSignIn, SignalsCaller, StreamActor};
use crate::use_cases::signals::lookup::existing_stream;
use crate::use_cases::signals::transmit::TransmitPorts;

/// A receiver's request for a verification event.
pub struct RequestVerificationRequest {
    /// The stream to send it down.
    pub stream_id: SignalStreamId,
    /// The `state` the event carries back, if the receiver gave one.
    pub state: RequestedState,
}

/// The ports [`RequestVerificationUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RequestVerificationPorts {
    /// Where streams are kept.
    pub stream_store: Arc<dyn SignalStreamStore>,
    /// Lets each stream ask only now and then.
    pub throttle: Arc<dyn VerificationThrottle>,
    /// Signs the event and pushes or holds it.
    pub transmit: TransmitPorts,
    /// Hashes the key a receiver presents.
    pub receiver_keys: Arc<dyn ReceiverKeys>,
    /// What a person holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Sends a stream the verification event its receiver asked for.
pub struct RequestVerificationUseCase {
    ports: RequestVerificationPorts,
}

impl RequestVerificationUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: RequestVerificationPorts) -> Self {
        Self { ports }
    }
}

impl Command for RequestVerificationUseCase {
    type Caller = SignalsCaller;
    type Input = RequestVerificationRequest;
    type Output = Result<(), AppError>;

    /// Signs a verification event carrying back `request.state`, records
    /// `signals.verification_requested`, and sends the event down the
    /// stream: pushed to the endpoint, or held for a poll. As the Shared
    /// Signals framework has it, the answer does not wait on the receiver;
    /// a send that fails is logged.
    ///
    /// The stream's own receiver asks with its key; a person who may change
    /// signal streams may ask for any of the tenant's.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for invalid session/key or a receiver key outside its stream; `Forbidden` without change rights or for another receiver's stream.
    /// - `AppError::NotFound` for a missing tenant stream; `Conflict` for an inactive stream or unverified endpoint.
    /// - `AppError::TooManyRequests` for a recent request; `Internal` on allowance lookup or audit failure.
    async fn execute(
        &self,
        caller: &SignalsCaller,
        auditor: &RequestAuditor,
        request: RequestVerificationRequest,
    ) -> Result<(), AppError> {
        let tenant = caller.tenant();
        let streams = self.ports.stream_store.as_ref();
        let receivers = ReceiverSignIn {
            streams,
            keys: self.ports.receiver_keys.as_ref(),
        };
        let actor =
            StreamActor::of(caller, self.ports.tenant_authorities.as_ref(), receivers).await?;
        let mut stream = existing_stream(streams, &tenant, &request.stream_id).await?;
        let event = stream
            .request_verification(request.state, &actor.manager())
            .map_err(AppError::from_domain)?;
        ensure_admitted(self.ports.throttle.as_ref(), &tenant, &request.stream_id).await?;

        auditor
            .dispatch_by(&caller.actor(), stream.take_events(&tenant))
            .await
            .or_internal()?;
        let transmitter = self.ports.transmit.transmitter();
        transmitter.verify(&tenant, &stream, &event).await;
        Ok(())
    }
}

/// Refuses unless the stream `stream_id` may be sent a verification event
/// now.
///
/// # Errors
///
/// - `AppError::TooManyRequests` when it asked a moment ago.
/// - `AppError::Internal` when the allowance cannot be read.
async fn ensure_admitted(
    throttle: &dyn VerificationThrottle,
    tenant: &ScopedTenant,
    stream_id: &SignalStreamId,
) -> Result<(), AppError> {
    if throttle.admit(tenant, stream_id).await.or_internal()? {
        return Ok(());
    }
    Err(AppError::TooManyRequests(message!(
        "signals-the-stream-asked-for-a-verification",
        "the stream asked for a verification event a moment ago"
    )))
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{SignalsAction, SystemPermission};
    use ianua_domain::domains::signals::stream::{
        DeliveryMethod, SignalStreamRow, StreamStatus, StreamVerificationStatus,
    };
    use ianua_domain::domains::signals::verification::ReceiverState;
    use ianua_domain::shared::security::secret::Secret;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::crypto::{FakeSigningKeyStore, premigration_keys};
    use crate::test_support::signals::{
        FakeSignalDeliverer, FakeSignalPollQueue, FakeSignalStreamStore, ShutVerificationThrottle,
        TEST_RECEIVER_KEY, test_stream,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};
    use crate::use_cases::signals::caller::ReceiverCaller;

    /// The use case with the fakes a test looks into.
    struct Verification {
        deliverer: Arc<FakeSignalDeliverer>,
        queue: Arc<FakeSignalPollQueue>,
        audit: Arc<FakeEventDispatcher>,
        id: SignalStreamId,
        ports: RequestVerificationPorts,
    }

    /// A request about the stream `row` by a caller holding `authorities`,
    /// in a tenant that has a signing key.
    fn verification(row: SignalStreamRow, authorities: FakeTenantAuthorities) -> Verification {
        let id = row.id;
        let deliverer = Arc::new(FakeSignalDeliverer::new());
        let queue = Arc::new(FakeSignalPollQueue::empty());
        let ports = RequestVerificationPorts {
            stream_store: Arc::new(FakeSignalStreamStore::holding(test_ctx().tenant_id(), row)),
            transmit: TransmitPorts {
                deliverer: deliverer.clone(),
                poll_queue: queue.clone(),
                key_store: Arc::new(FakeSigningKeyStore::holding(premigration_keys())),
                ..TransmitPorts::fakes()
            },
            tenant_authorities: Arc::new(authorities),
            ..RequestVerificationPorts::fakes()
        };
        Verification {
            deliverer,
            queue,
            audit: Arc::new(FakeEventDispatcher::new()),
            id,
            ports,
        }
    }

    /// The payroll app's active push stream, its endpoint verified.
    fn verified() -> SignalStreamRow {
        test_stream(StreamStatus::Active, StreamVerificationStatus::Verified)
    }

    /// The receiver of `stream_id`, presenting `key`.
    fn receiver(stream_id: SignalStreamId, key: &str) -> SignalsCaller {
        SignalsCaller::Receiver(ReceiverCaller {
            tenant: test_ctx().tenant(),
            stream_id,
            key: Secret::new(key),
        })
    }

    /// Asks, as `caller`, for an event carrying `state` down `stream_id`.
    fn ask_as(
        fixture: Verification,
        caller: &SignalsCaller,
        stream_id: SignalStreamId,
        state: RequestedState,
    ) -> Result<(), AppError> {
        let use_case = RequestVerificationUseCase::new(fixture.ports);
        let audit = test_auditor(fixture.audit);
        block_on(use_case.execute(
            caller,
            &audit,
            RequestVerificationRequest { stream_id, state },
        ))
    }

    /// Asks, as Ann, for an event carrying `state` down `stream_id`.
    fn ask(
        fixture: Verification,
        stream_id: SignalStreamId,
        state: RequestedState,
    ) -> Result<(), AppError> {
        ask_as(
            fixture,
            &SignalsCaller::Person(test_ctx()),
            stream_id,
            state,
        )
    }

    /// The `state` `req-42`, which the payroll app chose.
    fn req_42() -> RequestedState {
        RequestedState::Given(ReceiverState::new("req-42").unwrap())
    }

    /// The payroll app asks for a verification event with `req-42`. Its
    /// endpoint is pushed one, carrying `req-42` back, and the request is
    /// recorded.
    #[test]
    fn the_endpoint_is_pushed_an_event_carrying_its_state() {
        let fixture = verification(verified(), FakeTenantAuthorities::holding_everything());
        let (deliverer, audit, id) = (fixture.deliverer.clone(), fixture.audit.clone(), fixture.id);

        ask(fixture, id, req_42()).unwrap();

        let sent = deliverer.verifications();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].verification_state().as_deref(), Some("req-42"));
        assert_eq!(
            audit.records.lock().unwrap().as_slice(),
            ["signals.verification_requested"]
        );
    }

    /// The payroll app's receiver asks with the key its stream was
    /// registered with, not a tenant API key. Its endpoint is pushed the
    /// event.
    #[test]
    fn the_streams_own_receiver_asks_with_its_key() {
        let fixture = verification(
            verified(),
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
        );
        let (deliverer, id) = (fixture.deliverer.clone(), fixture.id);

        ask_as(fixture, &receiver(id, TEST_RECEIVER_KEY), id, req_42()).unwrap();

        assert_eq!(deliverer.verifications().len(), 1);
    }

    /// Requesting verification with an incorrect receiver key returns an
    /// unauthenticated error and pushes nothing.
    #[test]
    fn a_receiver_with_the_wrong_key_is_refused() {
        let fixture = verification(verified(), FakeTenantAuthorities::holding_everything());
        let (deliverer, id) = (fixture.deliverer.clone(), fixture.id);

        let result = ask_as(fixture, &receiver(id, "guessed-key"), id, req_42());

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert!(deliverer.pushes.lock().unwrap().is_empty());
    }

    /// A stream the payroll app polls has the event held for its next poll
    /// instead.
    #[test]
    fn a_poll_stream_has_the_event_queued() {
        let mut row = verified();
        row.delivery_method = DeliveryMethod::Poll;
        let fixture = verification(row, FakeTenantAuthorities::holding_everything());
        let (queue, deliverer, id) = (fixture.queue.clone(), fixture.deliverer.clone(), fixture.id);

        ask(fixture, id, RequestedState::NotGiven).unwrap();

        assert_eq!(queue.held_for(&id).len(), 1);
        assert!(deliverer.pushes.lock().unwrap().is_empty());
    }

    /// Requesting verification while endpoint proof is pending returns a
    /// conflict without pushing or recording an event.
    #[test]
    fn a_stream_waiting_on_its_endpoint_is_sent_nothing() {
        let row = test_stream(StreamStatus::Active, StreamVerificationStatus::Pending);
        let fixture = verification(row, FakeTenantAuthorities::holding_everything());
        let (deliverer, audit, id) = (fixture.deliverer.clone(), fixture.audit.clone(), fixture.id);

        let result = ask(fixture, id, req_42());

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert!(deliverer.pushes.lock().unwrap().is_empty());
        assert!(audit.records.lock().unwrap().is_empty());
    }

    /// A verification request rejected by the throttle returns too many
    /// requests without pushing or recording an event.
    #[test]
    fn a_stream_that_asked_a_moment_ago_is_refused() {
        let mut fixture = verification(verified(), FakeTenantAuthorities::holding_everything());
        fixture.ports.throttle = Arc::new(ShutVerificationThrottle);
        let (deliverer, audit, id) = (fixture.deliverer.clone(), fixture.audit.clone(), fixture.id);

        let result = ask(fixture, id, req_42());

        assert!(matches!(result, Err(AppError::TooManyRequests(_))));
        assert!(deliverer.pushes.lock().unwrap().is_empty());
        assert!(audit.records.lock().unwrap().is_empty());
    }

    /// Ann names a stream the tenant does not have. It is not found.
    #[test]
    fn an_unknown_stream_is_not_found() {
        let fixture = verification(verified(), FakeTenantAuthorities::holding_everything());

        let result = ask(fixture, SignalStreamId::new(), req_42());

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Stream viewing rights do not permit requesting verification events;
    /// the request is forbidden and nothing is pushed.
    #[test]
    fn a_viewer_is_refused() {
        let fixture = verification(
            verified(),
            FakeTenantAuthorities::holding(&[SystemPermission::Signals(SignalsAction::View)]),
        );
        let (deliverer, id) = (fixture.deliverer.clone(), fixture.id);

        let result = ask(fixture, id, req_42());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(deliverer.pushes.lock().unwrap().is_empty());
    }

    /// Requesting verification with a signed-out session returns an
    /// unauthenticated error.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let fixture = verification(
            verified(),
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
        );
        let id = fixture.id;

        let result = ask(fixture, id, req_42());

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
