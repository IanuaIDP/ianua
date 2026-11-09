//! Rows the signals store tests build from.

use ianua_app::ports::signals::{QueuedEvent, SecurityEventToken};
use ianua_domain::domains::signals::delivery::{
    ReceiverAuthorization, SignalDelivery, SignalDeliveryAttempt,
};
use ianua_domain::domains::signals::signal::SecuritySignalType;
use ianua_domain::domains::signals::stream::{
    DeliveryMethod, EndpointChallenge, EndpointVerification, SignalStreamRow, StreamStatus,
};
use ianua_domain::domains::signals::subjects::{DefaultSubjects, StreamSubjects};
use ianua_domain::types::{
    DeliveryOutcome, PublicHttpsUrl, SignalDeliveryId, SignalId, SignalStreamId, TokenHash,
};

use crate::test_support::rows::at;

/// An active push stream at `endpoint`, its endpoint verified, for revoked
/// sessions about every subject, asking for no `Authorization` header,
/// registered at the fixed moment.
///
/// # Panics
///
/// When `endpoint` is not a public HTTPS URL, which is a mistake in the
/// test.
#[must_use]
pub fn stream_row(endpoint: &str) -> SignalStreamRow {
    SignalStreamRow {
        id: SignalStreamId::new(),
        endpoint: PublicHttpsUrl::new(endpoint).expect("a public HTTPS URL"),
        verification: EndpointVerification::Verified,
        delivery_method: DeliveryMethod::Push,
        authorization: ReceiverAuthorization::NotRequired,
        receiver_key: TokenHash::from_stored("hash:receiver-key".to_owned()),
        signal_types: vec![SecuritySignalType::SessionRevoked],
        subjects: StreamSubjects::starting_with(DefaultSubjects::All),
        status: StreamStatus::Active,
        consecutive_failures: 0,
        created_at: at(0),
        updated_at: at(0),
    }
}

/// The challenge `text`, padded to the length a challenge must have.
///
/// # Panics
///
/// When `text` holds a character no challenge may, which is a mistake in
/// the test.
#[must_use]
pub fn challenge(text: &str) -> EndpointChallenge {
    EndpointChallenge::new(format!("{text}-0123456789abcdef0123456789abcdef"))
        .expect("a valid challenge")
}

/// `stream_id`'s first and only try at sending a revoked session, at
/// `seconds` after the fixed moment, that reached it as `delivery`.
#[must_use]
pub fn delivery_row(
    stream_id: SignalStreamId,
    seconds: i64,
    delivery: SignalDelivery,
) -> SignalDeliveryAttempt {
    SignalDeliveryAttempt {
        id: SignalDeliveryId::new(),
        stream_id,
        signal_id: SignalId::new(),
        signal_type: SecuritySignalType::SessionRevoked,
        delivery,
        duration_ms: 12,
        attempt_number: 0,
        attempted_at: at(seconds),
    }
}

/// A push the receiver took with a `200`.
#[must_use]
pub fn taken() -> SignalDelivery {
    SignalDelivery::Pushed(DeliveryOutcome::Answered { code: 200 })
}

/// A token held for polling, named `token`, under a fresh `jti`.
#[must_use]
pub fn queued_event(token: &str) -> QueuedEvent {
    QueuedEvent {
        jti: SignalId::new(),
        token: SecurityEventToken::new(token.to_owned()),
    }
}
