//! The signal stream a request names.

use ianua_domain::types::SignalStreamId;
use serde::Deserialize;
use uuid::Uuid;

/// `.../streams/{id}/...`.
#[derive(Deserialize)]
pub(crate) struct StreamPath {
    id: Uuid,
}

impl StreamPath {
    /// The stream named.
    #[must_use]
    pub(crate) fn stream(&self) -> SignalStreamId {
        SignalStreamId::from_uuid(self.id)
    }
}
