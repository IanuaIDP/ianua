//! Signal delivery attempt records.

use time::OffsetDateTime;

use crate::domains::signals::signal::SecuritySignalType;
use crate::types::{
    DeliveryOutcome, DeliveryResult, SealedSecret, SignalDeliveryId, SignalId, SignalStreamId,
};

/// What a push stream sends in the `Authorization` header, as its receiver
/// asked (RFC 8935 2, `authorization_header` in the Shared Signals
/// framework).
///
/// The value is the receiver's own credential, so it is sealed at rest and
/// opened only to push. Its `Debug` never shows it. A poll stream sends
/// nothing, so it never sends one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiverAuthorization {
    /// The receiver asked for no header.
    NotRequired,
    /// The header value, sealed.
    Header(SealedSecret),
}

/// The outcome of a signal delivery attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum SignalDeliveryStatus {
    /// The receiver returned a 2xx response.
    Success,
    /// The receiver returned a non-2xx response.
    Failed,
    /// The request timed out.
    Timeout,
    /// The request could not be sent, for example after a DNS failure or a
    /// refused connection.
    Unreachable,
    /// The stream uses poll delivery, so the signal was recorded but not
    /// pushed. No endpoint hands it to the receiver.
    Queued,
}

/// How a signal reached its stream.
///
/// It was either pushed, with how the push ended, or held for the receiver
/// to poll.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignalDelivery {
    /// Pushed to the receiver's endpoint.
    Pushed(DeliveryOutcome),
    /// Recorded for a poll-delivery stream and not pushed.
    Queued,
}

impl SignalDelivery {
    /// The outcome label this delivery carries.
    #[must_use]
    pub fn status(self) -> SignalDeliveryStatus {
        match self {
            Self::Queued => SignalDeliveryStatus::Queued,
            Self::Pushed(outcome) => match outcome.result() {
                DeliveryResult::Success => SignalDeliveryStatus::Success,
                DeliveryResult::Failed => SignalDeliveryStatus::Failed,
                DeliveryResult::Timeout => SignalDeliveryStatus::Timeout,
                DeliveryResult::Unreachable => SignalDeliveryStatus::Unreachable,
            },
        }
    }

    /// The code the receiver answered with, if it was pushed and answered.
    #[must_use]
    pub fn response_code(self) -> Option<u16> {
        match self {
            Self::Queued => None,
            Self::Pushed(outcome) => outcome.response_code(),
        }
    }
}

/// A record of a single signal delivery attempt.
///
/// Operators read these to see what was sent to a receiver and whether it
/// arrived. Delivery is tried once and not retried, so there is one record
/// per stream and signal.
#[derive(Debug, Clone)]
pub struct SignalDeliveryAttempt {
    /// Unique attempt identifier.
    pub id: SignalDeliveryId,
    /// The stream this delivery was for.
    pub stream_id: SignalStreamId,
    /// The signal that was delivered.
    pub signal_id: SignalId,
    /// The signal type that triggered the delivery.
    pub signal_type: SecuritySignalType,
    /// How the signal reached the stream.
    pub delivery: SignalDelivery,
    /// How long the request took in milliseconds.
    pub duration_ms: u32,
    /// Which attempt this is. `0` is the first try, and the only one made.
    pub attempt_number: u8,
    /// When the attempt was made.
    pub attempted_at: OffsetDateTime,
}
