//! Signal streams: the relying parties in a tenant that receive security
//! signals.

mod changes;
mod receiver_requests;

use std::marker::PhantomData;

use time::OffsetDateTime;

use crate::domains::signals::control::SignalsControlCheck;
use crate::domains::signals::delivery::ReceiverAuthorization;
use crate::domains::signals::events::{
    SignalStreamDeleted, SignalStreamDisabled, SignalStreamPaused, SignalStreamRegistered,
    SignalStreamResumed,
};
use crate::domains::signals::signal::{SecuritySignal, SecuritySignalType};
use crate::domains::signals::subjects::{DefaultSubjects, StreamSubjects};
use crate::domains::signals::verification::{VerificationEvent, VerificationState};
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{Raised, Raises, SavedFor};
use crate::shared::model::row_check::RowCheck;
use crate::shared::model::transition::{InvalidTransition, checked};
use crate::shared::validation::{TextValue, Validator, text_value};
use crate::types::{
    FailureLimit, FailureOutcome, FailureStreak, PublicHttpsUrl, SignalStreamId, Threshold,
    TokenHash,
};

text_value! {
    redacted
    /// The value a stream's endpoint must echo to show it is the
    /// receiver's.
    ///
    /// The caller makes it at random, as it makes a domain's DNS token, and
    /// sends it to the endpoint. Until the endpoint gives it back, the stream
    /// delivers nothing. Whoever reads it could confirm an endpoint that
    /// never saw it, so it never prints.
    pub struct EndpointChallenge;
}

impl TextValue for EndpointChallenge {
    const FIELD: &'static str = "endpoint_challenge";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.token(Self::MIN_LEN..=Self::MAX_LEN)
    }
}

impl EndpointChallenge {
    /// The shortest challenge, long enough that nobody guesses it.
    const MIN_LEN: usize = 32;
    /// The longest challenge, which still fits a header or a small body.
    const MAX_LEN: usize = 256;
}

/// Whether a stream's endpoint has shown it belongs to the receiver, as
/// storage keeps it.
///
/// Signals go only to a verified endpoint. A new stream, and one moved to
/// another endpoint, waits until that endpoint echoes the challenge sent to
/// it. So a stream pointed at a server that never asked for the tenant's
/// signals sends it nothing.
///
/// Only a stored row holds it. The stream never hands its challenge back,
/// see [`SignalStream::verification`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EndpointVerification {
    /// The endpoint has not echoed this challenge yet.
    Pending(EndpointChallenge),
    /// The endpoint echoed its challenge.
    Verified,
}

/// Whether a stream's endpoint has shown it belongs to the receiver,
/// without the challenge it waits for.
///
/// Sam may view the streams. If reading one gave him its challenge, he
/// would point the payroll app's stream at his own server and confirm it
/// himself with the value he read, and every security signal would reach
/// him.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamVerificationStatus {
    /// The endpoint has not echoed its challenge yet.
    Pending,
    /// The endpoint echoed its challenge.
    Verified,
}

/// The challenge to send to a stream's endpoint, handed out once, when the
/// endpoint is set.
///
/// The caller sends it to the endpoint and stores it with the stream. The
/// stream gives it out nowhere else, so nobody reads it back later to
/// confirm an endpoint that never saw it.
#[derive(Debug)]
pub struct ChallengeToSend {
    stream_id: SignalStreamId,
    endpoint: PublicHttpsUrl,
    challenge: EndpointChallenge,
}

impl ChallengeToSend {
    /// The challenge for `stream_id`'s newly set `endpoint`.
    fn new(
        stream_id: SignalStreamId,
        endpoint: &PublicHttpsUrl,
        challenge: &EndpointChallenge,
    ) -> Self {
        Self {
            stream_id,
            endpoint: endpoint.clone(),
            challenge: challenge.clone(),
        }
    }

    /// The stream whose endpoint it is.
    #[must_use]
    pub fn stream_id(&self) -> &SignalStreamId {
        &self.stream_id
    }

    /// The endpoint to send it to.
    #[must_use]
    pub fn endpoint(&self) -> &PublicHttpsUrl {
        &self.endpoint
    }

    /// The challenge the endpoint must echo.
    #[must_use]
    pub fn challenge(&self) -> &EndpointChallenge {
        &self.challenge
    }

    /// The challenge as the specification's verification event, which
    /// carries it as its `state`.
    #[must_use]
    pub fn verification_event(&self) -> VerificationEvent {
        VerificationEvent::new(
            self.stream_id,
            self.endpoint.clone(),
            VerificationState::Challenge(self.challenge.clone()),
        )
    }
}

/// Delivery method for security signals.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum DeliveryMethod {
    /// The `IdP` POSTs SETs to the receiver's endpoint.
    Push,

    /// The receiver asks the `IdP`'s endpoint for new signals.
    Poll,
}

/// Status of a signal stream receiver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum StreamStatus {
    /// Stream is active and delivering signals.
    Active,

    /// Stream is paused. Signals raised while paused are dropped, not queued.
    Paused,

    /// Stream has been permanently disabled.
    Disabled,
}

impl StreamStatus {
    /// Gives the new status when moving from `self` to `to` is allowed.
    ///
    /// Active and paused move between each other. Either can be disabled. A
    /// disabled stream stays disabled.
    ///
    /// # Errors
    ///
    /// - [`InvalidTransition`] for any other move.
    pub fn try_transition(self, to: Self) -> Result<Self, InvalidTransition<Self>> {
        checked(self, to, |from, to| {
            matches!(
                (from, to),
                (Self::Active, Self::Paused | Self::Disabled)
                    | (Self::Paused, Self::Active | Self::Disabled)
            )
        })
    }
}

/// A registered receiver for security signals within a tenant.
///
/// Each relying party registers a stream. The stream says which signal types
/// it wants and how they are delivered.
#[derive(Debug)]
pub struct SignalStream<T: TenantScope> {
    /// Unique stream identifier.
    id: SignalStreamId,
    /// The receiver's endpoint URL, used for push delivery.
    endpoint: PublicHttpsUrl,
    /// Whether the endpoint has shown it is the receiver's.
    verification: EndpointVerification,
    /// How signals are delivered.
    delivery_method: DeliveryMethod,
    /// What a push sends in the `Authorization` header.
    authorization: ReceiverAuthorization,
    /// The digest of the key the receiver manages the stream with.
    receiver_key: TokenHash,
    /// Which signal types this stream receives, at least one.
    signal_types: Vec<SecuritySignalType>,
    /// Which users and agents it hears about.
    subjects: StreamSubjects,
    /// Current stream status.
    status: StreamStatus,
    /// Number of consecutive delivery failures.
    failures: FailureStreak,
    /// When this stream was registered.
    created_at: OffsetDateTime,
    /// When this stream was last modified.
    updated_at: OffsetDateTime,
    /// The events raised since they were last taken.
    raised: Raised<T>,
    /// Which plane this belongs to. See [`crate::isolation`].
    _scope: PhantomData<T>,
}

/// What an update changes about a stream. `None` leaves a field as it is.
pub struct StreamUpdate {
    /// A new endpoint, with the challenge it must echo before it is sent
    /// anything.
    pub endpoint: Option<(PublicHttpsUrl, EndpointChallenge)>,
    /// A new delivery method.
    pub delivery_method: Option<DeliveryMethod>,
    /// New signal types, at least one.
    pub signal_types: Option<Vec<SecuritySignalType>>,
    /// A new `Authorization` header for pushes, or none.
    pub authorization: Option<ReceiverAuthorization>,
}

/// Parameters for registering a new signal stream.
pub struct RegisterStreamParams {
    /// The id the stream is kept under, chosen before it is registered so
    /// its receiver's header can be sealed for it.
    pub id: SignalStreamId,
    /// The receiver's endpoint URL.
    pub endpoint: PublicHttpsUrl,
    /// The challenge sent to the endpoint, which it must echo before the
    /// stream delivers anything.
    pub challenge: EndpointChallenge,
    /// How signals are delivered.
    pub delivery_method: DeliveryMethod,
    /// What a push sends in the `Authorization` header.
    pub authorization: ReceiverAuthorization,
    /// The digest of the key handed to the receiver, once, to manage the
    /// stream with.
    pub receiver_key: TokenHash,
    /// Which signal types to receive, at least one.
    pub signal_types: Vec<SecuritySignalType>,
    /// Whether it starts hearing about every subject or none.
    pub default_subjects: DefaultSubjects,
}

/// Stored fields of a [`SignalStream`], read back by repositories.
pub struct SignalStreamRow {
    /// Unique stream identifier.
    pub id: SignalStreamId,
    /// The receiver's endpoint URL.
    pub endpoint: PublicHttpsUrl,
    /// Whether the endpoint has shown it is the receiver's.
    pub verification: EndpointVerification,
    /// How signals are delivered.
    pub delivery_method: DeliveryMethod,
    /// What a push sends in the `Authorization` header.
    pub authorization: ReceiverAuthorization,
    /// The digest of the key the receiver manages the stream with.
    pub receiver_key: TokenHash,
    /// Which signal types this stream receives.
    pub signal_types: Vec<SecuritySignalType>,
    /// Which users and agents it hears about.
    pub subjects: StreamSubjects,
    /// Current stream status.
    pub status: StreamStatus,
    /// Number of consecutive delivery failures.
    pub consecutive_failures: u32,
    /// When this stream was registered.
    pub created_at: OffsetDateTime,
    /// When this stream was last modified.
    pub updated_at: OffsetDateTime,
}

impl<T: TenantScope> SignalStream<T> {
    /// Registers a new active signal stream, on behalf of `by`, and hands
    /// out the challenge to send to its endpoint.
    ///
    /// [`PublicHttpsUrl`] already refuses `localhost`, internal names and
    /// internal, loopback and link-local addresses. The stream delivers
    /// nothing until its endpoint echoes `params.challenge`, see
    /// [`confirm_endpoint`](Self::confirm_endpoint). Raises
    /// `signals.stream_registered`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not change signal streams.
    /// - [`DomainError::Validation`] when `params` names no signal type.
    pub fn register(
        params: RegisterStreamParams,
        by: &impl SignalsControlCheck,
    ) -> Result<(Self, ChallengeToSend), DomainError> {
        by.ensure_may_change_streams()?;
        ensure_names_a_type(&params.signal_types)?;
        let now = crate::shared::clock::now();
        let id = params.id;
        let to_send = ChallengeToSend::new(id, &params.endpoint, &params.challenge);
        let mut stream = Self {
            id,
            endpoint: params.endpoint,
            verification: EndpointVerification::Pending(params.challenge),
            delivery_method: params.delivery_method,
            authorization: params.authorization,
            receiver_key: params.receiver_key,
            signal_types: params.signal_types,
            subjects: StreamSubjects::starting_with(params.default_subjects),
            status: StreamStatus::Active,
            failures: FailureStreak::default(),
            created_at: now,
            updated_at: now,
            raised: Raised::default(),
            _scope: PhantomData,
        };
        stream.raised.raise(SignalStreamRegistered {
            stream_id: stream.id,
            endpoint: stream.endpoint.origin(),
            occurred_at: now,
        });
        Ok((stream, to_send))
    }

    /// Rebuilds a signal stream from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the row says the stream changed
    ///   before it was registered, names no signal type, or lists more
    ///   subjects than a stream keeps.
    pub fn reconstitute(row: SignalStreamRow) -> Result<Self, DomainError> {
        Self::ensure_consistent(&row)?;
        Ok(Self {
            id: row.id,
            endpoint: row.endpoint,
            verification: row.verification,
            delivery_method: row.delivery_method,
            authorization: row.authorization,
            receiver_key: row.receiver_key,
            signal_types: row.signal_types,
            subjects: row.subjects,
            status: row.status,
            failures: FailureStreak::from_stored(row.consecutive_failures),
            created_at: row.created_at,
            updated_at: row.updated_at,
            raised: Raised::default(),
            _scope: PhantomData,
        })
    }

    /// Refuses a stored row that breaks a rule this keeps.
    fn ensure_consistent(row: &SignalStreamRow) -> Result<(), DomainError> {
        RowCheck::of("signal stream")
            .in_order(
                row.created_at,
                row.updated_at,
                "changed before it was registered",
            )
            .holds(!row.signal_types.is_empty(), "names no signal type")
            .holds(row.subjects.within_bounds(), "lists too many subjects")
            .finish()
    }

    /// Unique stream identifier.
    #[must_use]
    pub fn id(&self) -> &SignalStreamId {
        &self.id
    }

    /// The receiver's endpoint URL.
    #[must_use]
    pub fn endpoint(&self) -> &PublicHttpsUrl {
        &self.endpoint
    }

    /// Whether the endpoint has shown it is the receiver's.
    ///
    /// It never gives out the challenge the endpoint must echo. That goes
    /// out once, as the [`ChallengeToSend`] setting the endpoint returns.
    #[must_use]
    pub fn verification(&self) -> StreamVerificationStatus {
        match self.verification {
            EndpointVerification::Pending(_) => StreamVerificationStatus::Pending,
            EndpointVerification::Verified => StreamVerificationStatus::Verified,
        }
    }

    /// How signals are delivered.
    #[must_use]
    pub fn delivery_method(&self) -> DeliveryMethod {
        self.delivery_method
    }

    /// What a push sends in the `Authorization` header, sealed.
    #[must_use]
    pub fn authorization(&self) -> &ReceiverAuthorization {
        &self.authorization
    }

    /// The digest of the key the receiver manages the stream with, for
    /// storage. The key itself was shown once, at registration.
    #[must_use]
    pub fn receiver_key(&self) -> &TokenHash {
        &self.receiver_key
    }

    /// Which signal types this stream receives, at least one.
    #[must_use]
    pub fn signal_types(&self) -> &[SecuritySignalType] {
        &self.signal_types
    }

    /// Which users and agents it hears about.
    #[must_use]
    pub fn subjects(&self) -> &StreamSubjects {
        &self.subjects
    }

    /// Current stream status.
    #[must_use]
    pub fn status(&self) -> StreamStatus {
        self.status
    }

    /// Number of consecutive delivery failures.
    #[must_use]
    pub fn consecutive_failures(&self) -> u32 {
        self.failures.count()
    }

    /// When this stream was registered.
    #[must_use]
    pub fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    /// When this stream was last modified.
    #[must_use]
    pub fn updated_at(&self) -> OffsetDateTime {
        self.updated_at
    }

    /// Whether this stream is actively delivering signals.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.status == StreamStatus::Active
    }

    /// Whether `signal` is sent to this stream now.
    ///
    /// It is when the stream is active, its endpoint is verified, the
    /// signal's type is in its list and the stream hears about the user or
    /// agent it concerns. Anything else sends nothing.
    #[must_use]
    pub fn receives(&self, signal: &SecuritySignal) -> bool {
        self.is_delivering()
            && self.signal_types.contains(&signal.signal_type())
            && self.subjects.covers(signal.subject())
    }

    /// Whether the stream is active and its endpoint verified, so it may be
    /// sent anything at all.
    fn is_delivering(&self) -> bool {
        self.is_active() && self.verification == EndpointVerification::Verified
    }

    /// Records that the endpoint echoed `echoed`, the challenge sent to it.
    /// From then on the stream delivers to it.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `echoed` is not the challenge sent
    ///   to the endpoint. The endpoint stays unverified.
    /// - [`DomainError::InvalidTransition`] when the endpoint is already
    ///   verified.
    pub fn confirm_endpoint(&mut self, echoed: &EndpointChallenge) -> Result<(), DomainError> {
        let EndpointVerification::Pending(challenge) = &self.verification else {
            return Err(DomainError::invalid_transition(message!(
                "signals-the-stream-s-endpoint-is-already",
                "the stream's endpoint is already verified"
            )));
        };
        if challenge != echoed {
            return Err(DomainError::forbidden(message!(
                "signals-the-endpoint-did-not-echo-the",
                "the endpoint did not echo the challenge sent to it"
            )));
        }
        self.verification = EndpointVerification::Verified;
        self.touch();
        Ok(())
    }

    /// Pauses the stream. Signals raised while paused are not delivered.
    /// Raises `signals.stream_paused`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not change signal streams.
    /// - [`DomainError::InvalidTransition`] unless the stream is active.
    pub fn pause(&mut self, by: &impl SignalsControlCheck) -> Result<(), DomainError> {
        by.ensure_may_change_streams()?;
        self.move_to(StreamStatus::Paused)?;
        self.raised.raise(SignalStreamPaused {
            stream_id: self.id,
            endpoint: self.endpoint.origin(),
            occurred_at: self.updated_at,
        });
        Ok(())
    }

    /// Resumes a paused stream. Signals raised from now on are delivered.
    /// Raises `signals.stream_resumed`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not change signal streams.
    /// - [`DomainError::InvalidTransition`] unless the stream is paused. A
    ///   disabled stream stays disabled.
    pub fn resume(&mut self, by: &impl SignalsControlCheck) -> Result<(), DomainError> {
        by.ensure_may_change_streams()?;
        self.move_to(StreamStatus::Active)?;
        self.raised.raise(SignalStreamResumed {
            stream_id: self.id,
            endpoint: self.endpoint.origin(),
            occurred_at: self.updated_at,
        });
        Ok(())
    }

    /// Permanently disables the stream. Raises `signals.stream_disabled`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not change signal streams.
    /// - [`DomainError::InvalidTransition`] when it is already disabled.
    pub fn disable(&mut self, by: &impl SignalsControlCheck) -> Result<(), DomainError> {
        by.ensure_may_change_streams()?;
        self.move_to(StreamStatus::Disabled)?;
        self.raise_disabled();
        Ok(())
    }

    /// Raises `signals.stream_disabled` for the stream as it is now.
    fn raise_disabled(&mut self) {
        self.raised.raise(SignalStreamDisabled {
            stream_id: self.id,
            endpoint: self.endpoint.origin(),
            occurred_at: self.updated_at,
        });
    }

    fn move_to(&mut self, to: StreamStatus) -> Result<(), DomainError> {
        self.status = self.status.try_transition(to)?;
        self.touch();
        Ok(())
    }

    /// Deletes this stream once `by` may change signal streams and it is
    /// disabled. Raises `signals.stream_deleted`, taken once the stream is
    /// removed from storage.
    ///
    /// Sam may only view the streams. Without this check, he deletes the
    /// payroll app's stream, and the app never again learns a session was
    /// revoked. A stream that may still deliver is disabled first, so none
    /// is deleted while a receiver relies on it.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not change signal streams.
    /// - [`DomainError::Conflict`] unless the stream is disabled.
    pub fn delete(&mut self, by: &impl SignalsControlCheck) -> Result<(), DomainError> {
        by.ensure_may_change_streams()?;
        if self.status != StreamStatus::Disabled {
            return Err(DomainError::conflict(message!(
                "signals-a-stream-is-disabled-before-it",
                "a stream is disabled before it is deleted"
            )));
        }
        self.raised.raise(SignalStreamDeleted {
            stream_id: self.id,
            endpoint: self.endpoint.origin(),
            occurred_at: crate::shared::clock::now(),
        });
        Ok(())
    }

    /// Records a successful delivery.
    pub fn record_success(&mut self) {
        self.failures.reset();
        self.touch();
    }

    /// Records a failed delivery, and disables an active stream after
    /// `disable_after` failures in a row.
    ///
    /// A paused or disabled stream keeps its status. A failure that disables
    /// the stream raises `signals.stream_disabled`, so it is recorded exactly
    /// when a receiver stops getting signals, and the outcome says so.
    #[must_use = "a stream the failure disabled must be reported"]
    pub fn record_failure(&mut self, disable_after: FailureLimit) -> FailureOutcome {
        let threshold = self.failures.record(disable_after);
        self.touch();
        if threshold == Threshold::Below || self.status != StreamStatus::Active {
            return FailureOutcome::Counted;
        }
        let Ok(disabled) = self.status.try_transition(StreamStatus::Disabled) else {
            return FailureOutcome::Counted;
        };
        self.status = disabled;
        self.raise_disabled();
        FailureOutcome::Disabled
    }

    /// Bumps the `updated_at` timestamp.
    fn touch(&mut self) {
        self.updated_at = crate::shared::clock::now();
    }
}

impl<T: TenantScope> Raises for SignalStream<T> {
    fn take_events(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent> {
        self.raised.take(saved_for)
    }
}

/// Refuses a list that names no signal type.
///
/// A stream receives only the types it names. An empty list is refused
/// rather than read as every type, so no receiver is sent every signal about
/// every user because a list was left out.
///
/// # Errors
///
/// - [`DomainError::Validation`] when `signal_types` is empty.
fn ensure_names_a_type(signal_types: &[SecuritySignalType]) -> Result<(), DomainError> {
    if signal_types.is_empty() {
        return Err(DomainError::invalid(message!(
            "signals-a-signal-stream-names-at-least",
            "a signal stream names at least one signal type"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::authorization::authority::TenantAuthority;
    use crate::domains::authorization::permission::{SignalsAction, SystemPermission};
    use crate::domains::signals::signal::{
        CredentialChangeType, CredentialKind, NewSecuritySignal, SignalEvent, SignalSubject,
    };
    use crate::domains::signals::verification::{ReceiverState, RequestedState, VerificationState};
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::model::row_check::refused_as_corrupt;
    use crate::test_support::authority::anyone_holding;
    use crate::test_support::events::raised_names;
    use crate::types::{AgentId, SealedSecret, TenantId, UserId};

    /// Ann, a user of the tenant.
    fn ann() -> SignalSubject {
        SignalSubject::User(UserId::from_uuid(uuid::Uuid::from_u128(0xa)))
    }

    /// A signal of `event` about `subject`, raised now.
    fn signal_of(subject: SignalSubject, event: SignalEvent) -> SecuritySignal {
        SecuritySignal::new(NewSecuritySignal {
            tenant_id: TenantId::new(),
            subject,
            event,
            occurred_at: crate::shared::clock::now(),
        })
        .unwrap()
    }

    /// A signal of `event` about Ann, raised now.
    fn about_ann(event: SignalEvent) -> SecuritySignal {
        signal_of(ann(), event)
    }

    fn admin() -> &'static TenantAuthority {
        anyone_holding(&[SystemPermission::Signals(SignalsAction::Update)])
    }

    fn viewer() -> &'static TenantAuthority {
        anyone_holding(&[SystemPermission::Signals(SignalsAction::View)])
    }

    fn limit(count: u32) -> FailureLimit {
        FailureLimit::new(count).unwrap()
    }

    fn first_challenge() -> EndpointChallenge {
        EndpointChallenge::new("a".repeat(40)).unwrap()
    }

    fn second_challenge() -> EndpointChallenge {
        EndpointChallenge::new("b".repeat(40)).unwrap()
    }

    fn params() -> RegisterStreamParams {
        RegisterStreamParams {
            id: SignalStreamId::new(),
            endpoint: PublicHttpsUrl::new("https://app.acme.com/.well-known/sse").unwrap(),
            challenge: first_challenge(),
            delivery_method: DeliveryMethod::Push,
            authorization: ReceiverAuthorization::NotRequired,
            receiver_key: TokenHash::from_stored("receiver-key-hash".to_owned()),
            signal_types: vec![
                SecuritySignalType::SessionRevoked,
                SecuritySignalType::AccountLocked,
            ],
            default_subjects: DefaultSubjects::All,
        }
    }

    /// A stream registered from [`params`] whose endpoint echoed its
    /// challenge.
    fn test_stream() -> SignalStream<ResolvedTenant> {
        let (mut stream, _) = SignalStream::register(params(), admin()).unwrap();
        stream.confirm_endpoint(&first_challenge()).unwrap();
        stream
    }

    fn row_of(stream: &SignalStream<ResolvedTenant>) -> SignalStreamRow {
        SignalStreamRow {
            id: *stream.id(),
            endpoint: stream.endpoint().clone(),
            verification: stream.verification.clone(),
            delivery_method: stream.delivery_method(),
            authorization: stream.authorization().clone(),
            receiver_key: stream.receiver_key().clone(),
            signal_types: stream.signal_types().to_vec(),
            subjects: stream.subjects().clone(),
            status: stream.status(),
            consecutive_failures: stream.consecutive_failures(),
            created_at: stream.created_at(),
            updated_at: stream.updated_at(),
        }
    }

    /// Registering a stream with view permission alone is forbidden.
    #[test]
    fn a_viewer_may_not_register_a_stream() {
        let registered = SignalStream::<ResolvedTenant>::register(params(), viewer());

        assert!(matches!(registered, Err(DomainError::Forbidden(_))));
    }

    /// A viewer cannot change the endpoint, signal types or delivery method,
    /// pause the stream or disable it. It retains its verified endpoint,
    /// two signal types, push delivery and active status.
    #[test]
    fn a_viewer_may_not_change_a_stream() {
        let mut stream = test_stream();
        let sams = PublicHttpsUrl::new("https://sam.example.com/sse").unwrap();

        let refused = [
            stream
                .change_endpoint(sams, second_challenge(), viewer())
                .map(drop),
            stream.replace_signal_types(vec![SecuritySignalType::RiskLevelChanged], viewer()),
            stream.change_delivery_method(DeliveryMethod::Poll, viewer()),
            stream.pause(viewer()),
            stream.disable(viewer()),
        ];

        for change in refused {
            assert!(matches!(change, Err(DomainError::Forbidden(_))));
        }
        assert_eq!(
            stream.endpoint().as_str(),
            "https://app.acme.com/.well-known/sse"
        );
        assert_eq!(stream.signal_types().len(), 2);
        assert_eq!(stream.delivery_method(), DeliveryMethod::Push);
        assert!(stream.is_active());
        assert_eq!(stream.verification(), StreamVerificationStatus::Verified);
    }

    /// Acme registers a push stream for two signal types. It starts active
    /// with both types and no failures counted.
    #[test]
    fn register_creates_active_stream() {
        let stream = test_stream();
        assert!(stream.is_active());
        assert_eq!(stream.delivery_method(), DeliveryMethod::Push);
        assert_eq!(stream.signal_types().len(), 2);
        assert_eq!(stream.consecutive_failures(), 0);
    }

    /// A stream subscribed to session-revoked and account-locked receives
    /// those two. It does not receive a credential change.
    #[test]
    fn a_stream_receives_the_types_it_lists() {
        let stream = test_stream();
        assert!(stream.receives(&about_ann(SignalEvent::SessionRevoked)));
        assert!(stream.receives(&about_ann(SignalEvent::AccountLocked)));
        assert!(!stream.receives(&about_ann(SignalEvent::CredentialChanged {
            credential: CredentialKind::Password,
            change: CredentialChangeType::Update,
        })));
    }

    /// A newly registered stream does not receive a session revocation.
    /// A wrong challenge is refused and leaves delivery blocked; confirming
    /// the issued challenge makes the stream eligible for that signal.
    #[test]
    fn a_new_stream_receives_nothing_until_its_endpoint_echoes_the_challenge() {
        let (mut stream, _) = SignalStream::<ResolvedTenant>::register(params(), admin()).unwrap();
        let before = stream.receives(&about_ann(SignalEvent::SessionRevoked));

        let guessed = stream.confirm_endpoint(&second_challenge());
        let after_guess = stream.receives(&about_ann(SignalEvent::SessionRevoked));
        stream.confirm_endpoint(&first_challenge()).unwrap();

        assert!(!before);
        assert!(matches!(guessed, Err(DomainError::Forbidden(_))));
        assert!(!after_guess);
        assert!(stream.receives(&about_ann(SignalEvent::SessionRevoked)));
    }

    /// Moving a verified stream to another endpoint suspends delivery and
    /// requires the new challenge. The old challenge is refused; confirming
    /// the new one restores eligibility for session revocations.
    #[test]
    fn moving_the_endpoint_holds_signals_until_the_new_endpoint_echoes_its_challenge() {
        let mut stream = test_stream();
        let sams = PublicHttpsUrl::new("https://sam.example.com/sse").unwrap();

        stream
            .change_endpoint(sams, second_challenge(), admin())
            .unwrap();
        let moved = stream.receives(&about_ann(SignalEvent::SessionRevoked));
        let with_old = stream.confirm_endpoint(&first_challenge());

        assert!(!moved);
        assert_eq!(stream.verification(), StreamVerificationStatus::Pending);
        assert!(matches!(with_old, Err(DomainError::Forbidden(_))));
        stream.confirm_endpoint(&second_challenge()).unwrap();
        assert!(stream.receives(&about_ann(SignalEvent::SessionRevoked)));
    }

    /// Acme registers a stream and later moves it to a new endpoint. Each
    /// time the challenge comes back once, naming the endpoint to send it
    /// to, and echoing it confirms that endpoint. Reading the stream shows
    /// only that it waits.
    #[test]
    fn the_challenge_is_handed_out_once_for_the_endpoint_it_was_set_for() {
        let (mut stream, sent) =
            SignalStream::<ResolvedTenant>::register(params(), admin()).unwrap();
        let first_waits = stream.verification();
        stream.confirm_endpoint(sent.challenge()).unwrap();
        let new = PublicHttpsUrl::new("https://new.acme.com/sse").unwrap();

        let moved = stream
            .change_endpoint(new, second_challenge(), admin())
            .unwrap();

        assert_eq!(sent.endpoint(), &params().endpoint);
        assert_eq!(first_waits, StreamVerificationStatus::Pending);
        assert_eq!(moved.endpoint().as_str(), "https://new.acme.com/sse");
        assert!(stream.confirm_endpoint(moved.challenge()).is_ok());
        assert_eq!(stream.verification(), StreamVerificationStatus::Verified);
    }

    /// Deletion is forbidden for a viewer and conflicts while the stream is
    /// active. An authorized caller can delete it once disabled.
    #[test]
    fn deleting_a_stream_needs_the_right_and_a_disabled_stream() {
        let mut stream = test_stream();

        let by_viewer = stream.delete(viewer());
        let while_active = stream.delete(admin());
        stream.disable(admin()).unwrap();

        assert!(matches!(by_viewer, Err(DomainError::Forbidden(_))));
        assert!(matches!(while_active, Err(DomainError::Conflict(_))));
        assert!(stream.delete(admin()).is_ok());
    }

    /// An endpoint already verified is confirmed again. It is refused.
    #[test]
    fn a_verified_endpoint_is_not_confirmed_twice() {
        let mut stream = test_stream();

        let again = stream.confirm_endpoint(&first_challenge());

        assert!(matches!(again, Err(DomainError::InvalidTransition(_))));
    }

    /// A paused stream whose endpoint is verified receives nothing.
    #[test]
    fn a_paused_stream_receives_nothing() {
        let mut stream = test_stream();

        stream.pause(admin()).unwrap();

        assert!(!stream.receives(&about_ann(SignalEvent::SessionRevoked)));
    }

    /// Registration and updates reject empty signal type lists. A refused
    /// update leaves the existing stream's two types in place.
    #[test]
    fn a_stream_naming_no_signal_type_is_refused() {
        let mut stream = test_stream();

        let registered = SignalStream::<ResolvedTenant>::register(
            RegisterStreamParams {
                signal_types: Vec::new(),
                ..params()
            },
            admin(),
        );
        let emptied = stream.replace_signal_types(Vec::new(), admin());

        assert!(matches!(registered, Err(DomainError::Validation(_))));
        assert!(matches!(emptied, Err(DomainError::Validation(_))));
        assert_eq!(stream.signal_types().len(), 2);
    }

    /// A stored stream naming no signal type is refused as corrupt. The
    /// same row with its types reads back.
    #[test]
    fn a_stored_stream_naming_no_signal_type_is_corrupt() {
        let stream = test_stream();
        let emptied = SignalStreamRow {
            signal_types: Vec::new(),
            ..row_of(&stream)
        };

        assert!(refused_as_corrupt(
            &SignalStream::<ResolvedTenant>::reconstitute(emptied)
        ));
        assert!(SignalStream::<ResolvedTenant>::reconstitute(row_of(&stream)).is_ok());
    }

    /// An admin pauses a stream and then resumes it. It is inactive while
    /// paused and active again after.
    #[test]
    fn pause_and_resume() {
        let mut stream = test_stream();

        stream.pause(admin()).unwrap();
        assert_eq!(stream.status(), StreamStatus::Paused);
        assert!(!stream.is_active());

        stream.resume(admin()).unwrap();
        assert!(stream.is_active());
    }

    /// A stream is disabled. Resuming, pausing or disabling it again is
    /// refused and it stays disabled.
    #[test]
    fn disable_is_permanent() {
        let mut stream = test_stream();
        stream.disable(admin()).unwrap();

        assert!(stream.resume(admin()).is_err());
        assert!(stream.pause(admin()).is_err());
        assert!(stream.disable(admin()).is_err());
        assert_eq!(stream.status(), StreamStatus::Disabled);
    }

    /// An admin resumes a stream that was never paused. It is refused.
    #[test]
    fn an_active_stream_cannot_be_resumed() {
        let mut stream = test_stream();

        assert!(stream.resume(admin()).is_err());
    }

    /// A stream is registered and paused one second later. Its last-changed
    /// time moves forward to the pause.
    #[test]
    fn mutations_bump_updated_at() {
        let start = crate::shared::clock::now();
        let mut stream = {
            let _frozen = crate::shared::clock::freeze(start);
            test_stream()
        };
        let _later = crate::shared::clock::freeze(start + time::Duration::seconds(1));

        stream.pause(admin()).unwrap();

        assert!(stream.updated_at() > start);
    }

    /// Endpoint validation rejects localhost, a LAN hostname and a bare
    /// internal hostname.
    #[test]
    fn a_stream_cannot_be_pointed_at_a_local_or_internal_host() {
        for url in [
            "https://localhost/sse",
            "https://signals.lan/sse",
            "https://receiver/sse",
        ] {
            assert!(PublicHttpsUrl::new(url).is_err(), "{url} was accepted");
        }
    }

    /// Acme moves its receiver to `new.acme.com`. The stream points there
    /// and its last-changed time moves forward.
    #[test]
    fn changing_the_endpoint_moves_delivery_and_bumps_updated_at() {
        let mut stream = test_stream();
        let before = stream.updated_at();
        std::thread::sleep(std::time::Duration::from_millis(2));

        stream
            .change_endpoint(
                PublicHttpsUrl::new("https://new.acme.com/sse").unwrap(),
                second_challenge(),
                admin(),
            )
            .unwrap();

        assert_eq!(stream.endpoint().as_str(), "https://new.acme.com/sse");
        assert!(stream.updated_at() > before);
    }

    /// A receiver fails five deliveries in a row with a limit of five. The
    /// first four are only counted, and the fifth disables the stream and
    /// says so.
    #[test]
    fn record_failure_disables_after_threshold() {
        let mut stream = test_stream();

        for _ in 0..4 {
            assert_eq!(stream.record_failure(limit(5)), FailureOutcome::Counted);
            assert!(stream.is_active());
        }
        assert_eq!(stream.record_failure(limit(5)), FailureOutcome::Disabled);
        assert_eq!(stream.status(), StreamStatus::Disabled);
    }

    /// A paused stream fails once with a limit of one. The failure is
    /// counted but the stream stays paused, so an admin can still resume it.
    #[test]
    fn a_failure_does_not_disable_a_paused_stream() {
        let mut stream = test_stream();
        stream.pause(admin()).unwrap();

        assert_eq!(stream.record_failure(limit(1)), FailureOutcome::Counted);
        assert_eq!(stream.status(), StreamStatus::Paused);
    }

    /// A stream fails twice and then delivers. The count goes back to zero,
    /// so old failures never add up to a disable.
    #[test]
    fn record_success_resets_failures() {
        let mut stream = test_stream();
        assert_eq!(stream.record_failure(limit(10)), FailureOutcome::Counted);
        assert_eq!(stream.record_failure(limit(10)), FailureOutcome::Counted);
        assert_eq!(stream.consecutive_failures(), 2);

        stream.record_success();
        assert_eq!(stream.consecutive_failures(), 0);
    }

    /// A stream gets a real id and is switched to poll delivery for
    /// credential changes only. Both edits read back, so the stream stops
    /// sending the old types the old way.
    #[test]
    fn a_stream_carries_its_id_and_the_edits_made_to_it() {
        let mut stream = test_stream();

        assert!(!stream.id().as_uuid().is_nil());

        stream
            .change_delivery_method(DeliveryMethod::Poll, admin())
            .unwrap();
        stream
            .replace_signal_types(vec![SecuritySignalType::CredentialChanged], admin())
            .unwrap();

        assert_eq!(stream.delivery_method(), DeliveryMethod::Poll);
        assert_eq!(
            stream.signal_types(),
            &[SecuritySignalType::CredentialChanged]
        );
    }

    /// An update moving the payroll app's stream to `new.acme.com`,
    /// switching it to poll and narrowing it to credential changes.
    fn full_update() -> StreamUpdate {
        StreamUpdate {
            endpoint: Some((
                PublicHttpsUrl::new("https://new.acme.com/sse").unwrap(),
                second_challenge(),
            )),
            delivery_method: Some(DeliveryMethod::Poll),
            signal_types: Some(vec![SecuritySignalType::CredentialChanged]),
            authorization: None,
        }
    }

    /// Acme registers a stream. Its registration is raised.
    #[test]
    fn registering_raises_signals_stream_registered() {
        let (mut stream, _) = SignalStream::<ResolvedTenant>::register(params(), admin()).unwrap();

        assert_eq!(raised_names(&mut stream), ["signals.stream_registered"]);
    }

    /// Ann pauses the payroll app's stream, resumes it, disables it and
    /// deletes it. Each step is raised, in order.
    #[test]
    fn each_status_change_is_raised_in_order() {
        let mut stream = test_stream();
        raised_names(&mut stream);

        stream.pause(admin()).unwrap();
        stream.resume(admin()).unwrap();
        stream.disable(admin()).unwrap();
        stream.delete(admin()).unwrap();

        assert_eq!(
            raised_names(&mut stream),
            [
                "signals.stream_paused",
                "signals.stream_resumed",
                "signals.stream_disabled",
                "signals.stream_deleted",
            ]
        );
    }

    /// Ann moves the payroll app's stream, switches it to poll and narrows
    /// its types in one update. One update is raised, and the new endpoint
    /// gets its challenge.
    #[test]
    fn an_update_is_raised_once_for_all_it_changes() {
        let mut stream = test_stream();
        raised_names(&mut stream);

        let to_send = stream.update(full_update(), admin()).unwrap();

        assert_eq!(raised_names(&mut stream), ["signals.stream_updated"]);
        assert_eq!(stream.delivery_method(), DeliveryMethod::Poll);
        assert_eq!(
            to_send.unwrap().endpoint().as_str(),
            "https://new.acme.com/sse"
        );
    }

    /// An update naming no change changes nothing and raises nothing.
    #[test]
    fn an_empty_update_raises_nothing() {
        let mut stream = test_stream();
        raised_names(&mut stream);
        let nothing = StreamUpdate {
            endpoint: None,
            delivery_method: None,
            signal_types: None,
            authorization: None,
        };

        let to_send = stream.update(nothing, admin()).unwrap();

        assert!(to_send.is_none());
        assert!(raised_names(&mut stream).is_empty());
    }

    /// Ann switches the payroll app's stream to poll and empties its types
    /// in one update. The update is refused and the stream keeps pushing.
    #[test]
    fn a_refused_update_leaves_the_stream_as_it_was() {
        let mut stream = test_stream();
        let emptied = StreamUpdate {
            endpoint: None,
            delivery_method: Some(DeliveryMethod::Poll),
            signal_types: Some(Vec::new()),
            authorization: None,
        };

        let updated = stream.update(emptied, admin());

        assert!(matches!(updated, Err(DomainError::Validation(_))));
        assert_eq!(stream.delivery_method(), DeliveryMethod::Push);
    }

    /// A receiver fails five deliveries in a row with a limit of five. Only
    /// the failure that disables the stream raises anything.
    #[test]
    fn a_failure_that_disables_the_stream_raises_its_disabling() {
        let mut stream = test_stream();
        raised_names(&mut stream);

        for _ in 0..4 {
            let _ = stream.record_failure(limit(5));
        }
        let counted = raised_names(&mut stream);
        let _ = stream.record_failure(limit(5));

        assert!(counted.is_empty());
        assert_eq!(raised_names(&mut stream), ["signals.stream_disabled"]);
    }

    /// A viewer's pause, update, disable and delete attempts all fail and
    /// raise no stream events.
    #[test]
    fn a_refused_stream_change_raises_nothing() {
        let mut stream = test_stream();
        raised_names(&mut stream);

        let refused = [
            stream.pause(viewer()),
            stream.update(full_update(), viewer()).map(drop),
            stream.disable(viewer()),
            stream.delete(viewer()),
        ];

        assert!(refused.iter().all(Result::is_err));
        assert!(raised_names(&mut stream).is_empty());
    }

    /// A stream read back from storage has raised nothing; only a change
    /// made after loading is recorded.
    #[test]
    fn a_stream_read_back_from_storage_has_raised_nothing() {
        let stream = test_stream();

        let mut stored = SignalStream::<ResolvedTenant>::reconstitute(row_of(&stream)).unwrap();

        assert!(raised_names(&mut stored).is_empty());
    }

    /// A stream that starts with no subject hears nothing about Ann. Once
    /// she is added, it does, and the addition is raised; adding her again
    /// raises nothing more.
    #[test]
    fn a_stream_hears_about_a_subject_once_it_is_added() {
        let (mut stream, sent) = SignalStream::<ResolvedTenant>::register(
            RegisterStreamParams {
                default_subjects: DefaultSubjects::None,
                ..params()
            },
            admin(),
        )
        .unwrap();
        stream.confirm_endpoint(sent.challenge()).unwrap();
        raised_names(&mut stream);
        let before = stream.receives(&about_ann(SignalEvent::SessionRevoked));

        stream.add_subject(ann(), admin()).unwrap();
        stream.add_subject(ann(), admin()).unwrap();

        assert!(!before);
        assert!(stream.receives(&about_ann(SignalEvent::SessionRevoked)));
        assert_eq!(raised_names(&mut stream), ["signals.subject_added"]);
    }

    /// The payroll app's stream hears about everyone. The billing agent is
    /// removed from it, and a signal about the agent is no longer sent
    /// while one about Ann still is.
    #[test]
    fn a_removed_subject_is_no_longer_heard_about() {
        let mut stream = test_stream();
        let agent = SignalSubject::Agent(AgentId::new());
        raised_names(&mut stream);

        stream.remove_subject(agent, admin()).unwrap();

        assert!(!stream.receives(&signal_of(agent, SignalEvent::AccountDisabled)));
        assert!(stream.receives(&about_ann(SignalEvent::AccountLocked)));
        assert_eq!(raised_names(&mut stream), ["signals.subject_removed"]);
    }

    /// A viewer cannot remove a user or add an agent to a stream. The stream
    /// still receives the user's session revocation and raises no events.
    #[test]
    fn a_viewer_may_not_add_or_remove_a_subject() {
        let mut stream = test_stream();
        raised_names(&mut stream);

        let removed = stream.remove_subject(ann(), viewer());
        let added = stream.add_subject(SignalSubject::Agent(AgentId::new()), viewer());

        assert!(matches!(removed, Err(DomainError::Forbidden(_))));
        assert!(matches!(added, Err(DomainError::Forbidden(_))));
        assert!(stream.receives(&about_ann(SignalEvent::SessionRevoked)));
        assert!(raised_names(&mut stream).is_empty());
    }

    /// The payroll app asks its verified stream for a verification event
    /// with the state `req-42`. It is handed one for the stream's endpoint
    /// carrying that state, and the request is raised.
    #[test]
    fn a_verified_stream_hands_out_the_verification_event_asked_for() {
        let mut stream = test_stream();
        raised_names(&mut stream);
        let state = ReceiverState::new("req-42").unwrap();

        let event = stream
            .request_verification(RequestedState::Given(state.clone()), admin())
            .unwrap();

        assert_eq!(event.stream_id(), stream.id());
        assert_eq!(event.endpoint(), stream.endpoint());
        assert_eq!(event.state(), &VerificationState::Echo(state));
        assert_eq!(
            raised_names(&mut stream),
            ["signals.verification_requested"]
        );
    }

    /// The payroll app's receiver signs in with the key its stream was
    /// registered with, and asks its own stream for a verification event.
    #[test]
    fn a_receiver_signed_in_with_its_key_manages_its_stream() {
        let mut stream = test_stream();
        let key = TokenHash::from_stored("receiver-key-hash".to_owned());

        let receiver = stream.sign_in_receiver(&key).unwrap();
        let asked = stream.request_verification(RequestedState::NotGiven, &receiver);

        assert_eq!(receiver.stream(), stream.id());
        assert!(asked.is_ok());
    }

    /// A key that does not match the stream's receiver key is unauthorized.
    #[test]
    fn a_wrong_receiver_key_signs_no_one_in() {
        let stream = test_stream();

        let result = stream.sign_in_receiver(&TokenHash::from_stored("guess".to_owned()));

        assert!(matches!(result, Err(DomainError::Unauthorized(_))));
    }

    /// A receiver authenticated for one stream is forbidden from removing
    /// a subject from another stream.
    #[test]
    fn a_receiver_may_not_manage_another_stream() {
        let crm = test_stream();
        let mut payroll = test_stream();
        let crm_receiver = crm
            .sign_in_receiver(&TokenHash::from_stored("receiver-key-hash".to_owned()))
            .unwrap();

        let removed = payroll.remove_subject(SignalSubject::User(UserId::new()), &crm_receiver);

        assert!(matches!(removed, Err(DomainError::Forbidden(_))));
    }

    /// Verification requests conflict for unverified and paused streams.
    /// A viewer's request is forbidden even when the stream can deliver.
    #[test]
    fn verification_is_sent_only_to_a_stream_that_may_deliver() {
        let (mut unverified, _) =
            SignalStream::<ResolvedTenant>::register(params(), admin()).unwrap();
        let mut paused = test_stream();
        paused.pause(admin()).unwrap();

        let to_unverified = unverified.request_verification(RequestedState::NotGiven, admin());
        let to_paused = paused.request_verification(RequestedState::NotGiven, admin());
        let by_viewer = test_stream().request_verification(RequestedState::NotGiven, viewer());

        assert!(matches!(to_unverified, Err(DomainError::Conflict(_))));
        assert!(matches!(to_paused, Err(DomainError::Conflict(_))));
        assert!(matches!(by_viewer, Err(DomainError::Forbidden(_))));
    }

    /// Acme registers a stream. The challenge it hands out names the
    /// stream, and goes out as the specification's verification event,
    /// with the challenge as its state.
    #[test]
    fn the_challenge_goes_out_as_a_verification_event() {
        let (stream, sent) = SignalStream::<ResolvedTenant>::register(params(), admin()).unwrap();

        let event = sent.verification_event();

        assert_eq!(sent.stream_id(), stream.id());
        assert_eq!(event.endpoint(), stream.endpoint());
        assert_eq!(
            event.state(),
            &VerificationState::Challenge(first_challenge())
        );
    }

    /// The payroll app asks for its pushes to carry an `Authorization`
    /// header. An update sets it, and the stream keeps it sealed.
    #[test]
    fn an_update_sets_the_receivers_authorization_header() {
        let mut stream = test_stream();
        let header = ReceiverAuthorization::Header(SealedSecret::new("v1.aGVhZGVy").unwrap());

        stream
            .update(
                StreamUpdate {
                    endpoint: None,
                    delivery_method: None,
                    signal_types: None,
                    authorization: Some(header.clone()),
                },
                admin(),
            )
            .unwrap();

        assert_eq!(stream.authorization(), &header);
        assert!(!format!("{stream:?}").contains("v1.aGVhZGVy"));
    }

    /// A viewer cannot set the receiver's authorization header. The stream
    /// continues to require no authorization header.
    #[test]
    fn a_viewer_may_not_change_the_authorization_header() {
        let mut stream = test_stream();
        let sams = ReceiverAuthorization::Header(SealedSecret::new("v1.c2Ftcw").unwrap());

        let result = stream.change_authorization(sams, viewer());

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
        assert_eq!(stream.authorization(), &ReceiverAuthorization::NotRequired);
    }

    /// A stored stream listing more subjects than a stream keeps is refused
    /// as corrupt.
    #[test]
    fn a_stored_stream_with_too_many_subjects_is_corrupt() {
        let stream = test_stream();
        let listed: Vec<SignalSubject> = (1_u128..=10_001)
            .map(|n| SignalSubject::User(UserId::from_uuid(uuid::Uuid::from_u128(n))))
            .collect();
        let row = SignalStreamRow {
            subjects: StreamSubjects::Only(listed),
            ..row_of(&stream)
        };

        assert!(refused_as_corrupt(
            &SignalStream::<ResolvedTenant>::reconstitute(row)
        ));
    }
}
