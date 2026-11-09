//! A SAML sign-in request in flight as its row holds it: the port's own
//! value, each part rebuilt through its own constructor.

use ianua_app::ports::federation::SamlLoginRequest;
use ianua_domain::types::{ConnectionId, TokenHash};
use uuid::Uuid;

/// A request in flight as it is read. The store's checked queries fill it.
pub(super) struct RequestRecord {
    pub(super) connection_id: Uuid,
    pub(super) binding_hash: String,
    pub(super) dashboard_hash: String,
}

impl RequestRecord {
    /// The request the record holds.
    pub(super) fn into_request(self) -> SamlLoginRequest {
        SamlLoginRequest {
            connection_id: ConnectionId::from_uuid(self.connection_id),
            binding_hash: TokenHash::from_stored(self.binding_hash),
            dashboard_hash: TokenHash::from_stored(self.dashboard_hash),
        }
    }
}
