//! A signal sent to a stream as its row holds it: read back into the
//! delivery record, and written out from it.

use ianua_domain::domains::signals::delivery::{
    SignalDelivery, SignalDeliveryAttempt, SignalDeliveryStatus,
};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{
    DeliveryOutcome, DeliveryResult, SignalDeliveryId, SignalId, SignalStreamId,
};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::foundation::stored::{Stored, StoredWord as _};

const DELIVERY: Stored = Stored("signal delivery");

/// A delivery as it is read. The store's checked queries fill it.
pub(super) struct DeliveryRecord {
    pub(super) id: Uuid,
    pub(super) stream_id: Uuid,
    pub(super) signal_id: Uuid,
    pub(super) signal_type: String,
    pub(super) status: String,
    pub(super) response_code: Option<i32>,
    pub(super) duration_ms: i64,
    pub(super) attempt_number: i16,
    pub(super) attempted_at: OffsetDateTime,
}

impl DeliveryRecord {
    /// The delivery the record holds, through the domain's own readings of
    /// an outcome.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a word is unknown, a
    /// number is out of range, or the code contradicts the outcome.
    pub(super) fn into_attempt(self) -> Result<SignalDeliveryAttempt, DomainError> {
        let out_of_range = || DomainError::corrupt_row(DELIVERY.0, "a number out of range");
        Ok(SignalDeliveryAttempt {
            id: SignalDeliveryId::from_uuid(self.id),
            stream_id: SignalStreamId::from_uuid(self.stream_id),
            signal_id: SignalId::from_uuid(self.signal_id),
            signal_type: DELIVERY.choice(&self.signal_type)?,
            delivery: delivery_from(DELIVERY.choice(&self.status)?, self.response_code)?,
            duration_ms: u32::try_from(self.duration_ms).map_err(|_| out_of_range())?,
            attempt_number: u8::try_from(self.attempt_number).map_err(|_| out_of_range())?,
            attempted_at: self.attempted_at,
        })
    }
}

/// How the signal reached its stream, from the stored status and code.
fn delivery_from(
    status: SignalDeliveryStatus,
    code: Option<i32>,
) -> Result<SignalDelivery, DomainError> {
    let code = code
        .map(u16::try_from)
        .transpose()
        .map_err(|_| DomainError::corrupt_row(DELIVERY.0, "a response code out of range"))?;
    let result = match status {
        SignalDeliveryStatus::Queued => return queued(code),
        SignalDeliveryStatus::Success => DeliveryResult::Success,
        SignalDeliveryStatus::Failed => DeliveryResult::Failed,
        SignalDeliveryStatus::Timeout => DeliveryResult::Timeout,
        SignalDeliveryStatus::Unreachable => DeliveryResult::Unreachable,
    };
    DeliveryOutcome::from_stored(result, code).map(SignalDelivery::Pushed)
}

/// A signal held for polling, which no receiver answered with a code.
fn queued(code: Option<u16>) -> Result<SignalDelivery, DomainError> {
    match code {
        None => Ok(SignalDelivery::Queued),
        Some(_) => Err(DomainError::corrupt_row(
            DELIVERY.0,
            "a signal held for polling with a response code",
        )),
    }
}

/// A delivery's columns, as they are written.
pub(super) struct DeliveryColumns<'a> {
    pub(super) id: &'a Uuid,
    pub(super) stream_id: &'a Uuid,
    pub(super) signal_id: &'a Uuid,
    pub(super) signal_type: &'static str,
    pub(super) status: &'static str,
    pub(super) response_code: Option<i32>,
    pub(super) duration_ms: i64,
    pub(super) attempt_number: i16,
    pub(super) attempted_at: OffsetDateTime,
}

impl<'a> DeliveryColumns<'a> {
    /// The columns `attempt` is written to.
    pub(super) fn of(attempt: &'a SignalDeliveryAttempt) -> Self {
        Self {
            id: attempt.id.as_uuid(),
            stream_id: attempt.stream_id.as_uuid(),
            signal_id: attempt.signal_id.as_uuid(),
            signal_type: attempt.signal_type.word(),
            status: attempt.delivery.status().word(),
            response_code: attempt.delivery.response_code().map(i32::from),
            duration_ms: i64::from(attempt.duration_ms),
            attempt_number: i16::from(attempt.attempt_number),
            attempted_at: attempt.attempted_at,
        }
    }
}
