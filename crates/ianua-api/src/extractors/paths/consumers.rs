//! The consumer a request names.

use ianua_domain::types::ConsumerId;
use serde::Deserialize;
use uuid::Uuid;

/// `.../consumers/{id}/...`.
#[derive(Deserialize)]
pub(crate) struct ConsumerPath {
    id: Uuid,
}

impl ConsumerPath {
    /// The consumer named.
    #[must_use]
    pub(crate) fn consumer(&self) -> ConsumerId {
        ConsumerId::from_uuid(self.id)
    }
}
