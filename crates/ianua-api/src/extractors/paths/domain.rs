//! The registered domain a custom domain request names.

use ianua_domain::types::DomainId;
use serde::Deserialize;
use uuid::Uuid;

/// `.../domains/{id}/...`.
#[derive(Deserialize)]
pub(crate) struct DomainPath {
    id: Uuid,
}

impl DomainPath {
    /// The registration named.
    #[must_use]
    pub(crate) fn domain(&self) -> DomainId {
        DomainId::from_uuid(self.id)
    }
}
