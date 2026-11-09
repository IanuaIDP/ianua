//! A token a poll stream holds, as its row holds it: read back into the
//! port's queued event.

use ianua_app::ports::signals::{QueuedEvent, SecurityEventToken};
use ianua_domain::types::SignalId;
use uuid::Uuid;

/// A held token as it is read. The store's checked queries fill it.
pub(super) struct EventRecord {
    pub(super) jti: Uuid,
    pub(super) token: String,
}

impl EventRecord {
    /// The event the record holds.
    pub(super) fn into_event(self) -> QueuedEvent {
        QueuedEvent {
            jti: SignalId::from_uuid(self.jti),
            token: SecurityEventToken::new(self.token),
        }
    }
}
