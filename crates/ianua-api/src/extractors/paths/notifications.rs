//! The notification an inbox request names, and the destination an
//! organization's request names.

use ianua_domain::types::{NotificationDestinationId, NotificationId};
use serde::Deserialize;
use uuid::Uuid;

/// `.../notifications/{id}/...`, in any inbox.
#[derive(Deserialize)]
pub(crate) struct NotificationPath {
    id: Uuid,
}

impl NotificationPath {
    /// The notification named.
    #[must_use]
    pub(crate) fn notification(&self) -> NotificationId {
        NotificationId::from_uuid(self.id)
    }
}

/// `.../notifications/destinations/{destination_id}/...`.
#[derive(Deserialize)]
pub(crate) struct DestinationPath {
    destination_id: Uuid,
}

impl DestinationPath {
    /// The destination named.
    #[must_use]
    pub(crate) fn destination(&self) -> NotificationDestinationId {
        NotificationDestinationId::from_uuid(self.destination_id)
    }
}
