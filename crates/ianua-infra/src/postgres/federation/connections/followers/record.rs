//! A connection that follows a metadata address, as its row tells it: the
//! port's own value, two ids, with no aggregate to rebuild.

use ianua_app::ports::federation::MetadataFollower;
use ianua_domain::types::{ConnectionId, TenantId};
use uuid::Uuid;

/// A follower as it is read. The store's checked query fills it.
pub(super) struct FollowerRecord {
    pub(super) tenant_id: Uuid,
    pub(super) id: Uuid,
}

impl FollowerRecord {
    /// The follower the record names.
    pub(super) fn into_follower(self) -> MetadataFollower {
        MetadataFollower {
            tenant_id: TenantId::from_uuid(self.tenant_id),
            connection_id: ConnectionId::from_uuid(self.id),
        }
    }
}
