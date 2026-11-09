//! Handing one signal to one stream: signing the Security Event Token,
//! pushing it or holding it for a poll, keeping the attempt and the
//! stream's failure count, and a stream it switched off together with the
//! record of that.
//!
//! Each stream stands alone. Whatever goes wrong with one receiver is kept
//! against that stream and logged, and never stops the signal reaching
//! another.

use ianua_domain::domains::signals::delivery::{SignalDelivery, SignalDeliveryAttempt};
use ianua_domain::domains::signals::set::SecurityEventTokenClaims;
use ianua_domain::domains::signals::signal::SecuritySignal;
use ianua_domain::domains::signals::stream::SignalStream;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{
    DeliveryOutcome, DeliveryResult, FailureLimit, FailureOutcome, SignalDeliveryId,
};

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::runtime::UnitOfWork;
use crate::ports::signals::{
    SecurityEventToken, SignalDeliveryOutcome, SignalStreamStore, StreamChallenge,
};
use crate::services::kept_together::kept_together;
use crate::tenancy::ScopedTenant;
use crate::use_cases::signals::delivery::Dispatched;
use crate::use_cases::signals::transmit::{SetSigning, Transmitter};

/// Everything handing the signal to a stream needs besides the stream.
pub(super) struct Push<'a> {
    /// Where streams and their attempts are kept.
    pub(super) streams: &'a dyn SignalStreamStore,
    /// Signs the token and pushes or queues it.
    pub(super) transmitter: &'a Transmitter<'a>,
    /// The tenant's issuer and signing key now.
    pub(super) signing: &'a SetSigning,
    /// Keeps a stream the push switched off and the record of it together.
    pub(super) unit: &'a dyn UnitOfWork,
    /// Records a stream the push switched off.
    pub(super) auditor: &'a RequestAuditor,
    /// The tenant the signal was raised in.
    pub(super) tenant: &'a ScopedTenant,
    /// The signal being sent.
    pub(super) signal: &'a SecuritySignal,
    /// How many failures in a row switch a stream off.
    pub(super) disable_after: FailureLimit,
}

impl Push<'_> {
    /// Pushes the signal to `stream`, keeps the attempt, counts the outcome
    /// against the stream, and says how the push went.
    pub(super) async fn to(&self, mut stream: SignalStream<ResolvedTenant>) -> Dispatched {
        let outcome = self.signed_and_sent(&stream).await.unwrap_or_else(|error| {
            tracing::warn!(stream_id = %stream.id(), %error, "signal dispatch: push failed");
            unreachable_outcome()
        });
        let attempt = attempt_of(
            &stream,
            self.signal,
            SignalDelivery::Pushed(outcome.outcome),
            outcome.duration_ms,
        );
        record_attempt(self.streams, self.tenant, &attempt).await;
        let switched_off = counted(&mut stream, outcome.outcome, self.disable_after);
        let kept = kept_together(self.unit, self.save(&mut stream, switched_off)).await;
        if let Err(error) = kept {
            tracing::warn!(stream_id = %stream.id(), %error, "signal dispatch: stream not saved");
        }
        dispatched(outcome.outcome, switched_off)
    }

    /// Holds the signal for `stream`'s receiver to poll, and keeps a
    /// `Queued` attempt once it is held.
    pub(super) async fn queue(&self, stream: &SignalStream<ResolvedTenant>) -> Dispatched {
        if let Err(error) = self.sign_and_queue(stream).await {
            tracing::warn!(stream_id = %stream.id(), %error, "signal dispatch: not queued");
            return Dispatched::Failed;
        }
        let attempt = attempt_of(stream, self.signal, SignalDelivery::Queued, 0);
        record_attempt(self.streams, self.tenant, &attempt).await;
        Dispatched::Queued
    }

    /// Saves `stream` with its count, and records it switched off when the
    /// push did that. Both go in one unit: a stream switched off with no
    /// record of it would leave its owner nothing to see why.
    ///
    /// # Errors
    ///
    /// `AppError::Internal` when the stream cannot be saved or the record
    /// kept.
    async fn save(
        &self,
        stream: &mut SignalStream<ResolvedTenant>,
        switched_off: FailureOutcome,
    ) -> Result<(), AppError> {
        self.streams
            .save(self.tenant, stream, StreamChallenge::Kept)
            .await
            .or_internal()?;
        if switched_off != FailureOutcome::Disabled {
            return Ok(());
        }
        self.auditor
            .with_tenant(**self.tenant)
            .dispatch(&stream.take_events(self.tenant))
            .await
            .or_internal()
    }

    /// The signal as a token for `stream`, with its `jti`.
    ///
    /// # Errors
    ///
    /// `DomainError` when the token cannot be signed.
    async fn token_for(
        &self,
        stream: &SignalStream<ResolvedTenant>,
    ) -> Result<SecurityEventToken, DomainError> {
        let claims = SecurityEventTokenClaims::from_signal(
            self.signing.issuer().clone(),
            stream.endpoint().as_https().clone(),
            self.signal,
        );
        self.transmitter.signed(self.signing, &claims).await
    }

    /// Signs the signal for `stream` and pushes it.
    ///
    /// # Errors
    ///
    /// `DomainError` when it cannot be signed or the endpoint is refused.
    async fn signed_and_sent(
        &self,
        stream: &SignalStream<ResolvedTenant>,
    ) -> Result<SignalDeliveryOutcome, DomainError> {
        let token = self.token_for(stream).await?;
        self.transmitter.pushed(self.tenant, stream, &token).await
    }

    /// Signs the signal for `stream` and holds it for a poll.
    ///
    /// # Errors
    ///
    /// `DomainError` when it cannot be signed or queued.
    async fn sign_and_queue(
        &self,
        stream: &SignalStream<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let token = self.token_for(stream).await?;
        self.transmitter
            .queue(self.tenant, stream, *self.signal.id(), token)
            .await
    }
}

/// Keeps one attempt. A failure is logged, not returned, so it cannot fail
/// the signal reaching other streams.
async fn record_attempt(
    streams: &dyn SignalStreamStore,
    tenant: &ScopedTenant,
    attempt: &SignalDeliveryAttempt,
) {
    if let Err(error) = streams.record_delivery(tenant, attempt).await {
        tracing::warn!(stream_id = %attempt.stream_id, %error, "signal dispatch: attempt not kept");
    }
}

/// Counts `outcome` against `stream`, saying whether it switched it off.
fn counted(
    stream: &mut SignalStream<ResolvedTenant>,
    outcome: DeliveryOutcome,
    disable_after: FailureLimit,
) -> FailureOutcome {
    if outcome.result() == DeliveryResult::Success {
        stream.record_success();
        return FailureOutcome::Counted;
    }
    stream.record_failure(disable_after)
}

/// How a push that ended in `outcome` went, given whether it switched the
/// stream off.
fn dispatched(outcome: DeliveryOutcome, switched_off: FailureOutcome) -> Dispatched {
    match (outcome.result(), switched_off) {
        (DeliveryResult::Success, _) => Dispatched::Delivered,
        (_, FailureOutcome::Disabled) => Dispatched::SwitchedOff,
        (_, FailureOutcome::Counted) => Dispatched::Failed,
    }
}

/// The outcome kept for a push that never got an answer: the token could
/// not be signed or the receiver could not be reached.
fn unreachable_outcome() -> SignalDeliveryOutcome {
    SignalDeliveryOutcome {
        outcome: DeliveryOutcome::Unreachable,
        duration_ms: 0,
    }
}

/// The record of `signal` reaching `stream` by `delivery`, taking
/// `duration_ms`.
fn attempt_of(
    stream: &SignalStream<ResolvedTenant>,
    signal: &SecuritySignal,
    delivery: SignalDelivery,
    duration_ms: u32,
) -> SignalDeliveryAttempt {
    SignalDeliveryAttempt {
        id: SignalDeliveryId::new(),
        stream_id: *stream.id(),
        signal_id: *signal.id(),
        signal_type: signal.signal_type(),
        delivery,
        duration_ms,
        attempt_number: 0,
        attempted_at: clock::now(),
    }
}
