//! The user or group a SCIM request names.

use ianua_domain::types::{GroupId, UserId};
use serde::Deserialize;
use uuid::Uuid;

/// `.../Users/{id}` or `.../Groups/{id}`.
#[derive(Deserialize)]
pub(crate) struct ScimResourcePath {
    id: Uuid,
}

impl ScimResourcePath {
    /// The user named.
    #[must_use]
    pub(crate) fn user(&self) -> UserId {
        UserId::from_uuid(self.id)
    }

    /// The group named.
    #[must_use]
    pub(crate) fn group(&self) -> GroupId {
        GroupId::from_uuid(self.id)
    }
}
