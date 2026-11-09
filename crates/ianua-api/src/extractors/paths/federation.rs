//! The connection, the account linked through it, or the SAML app a
//! federation request names.

use ianua_domain::types::{ConnectionId, SamlServiceProviderId, UserId};
use serde::Deserialize;
use uuid::Uuid;

/// `.../federation/connections/{id}/...`
#[derive(Deserialize)]
pub(crate) struct ConnectionPath {
    id: Uuid,
}

impl ConnectionPath {
    /// The connection named.
    #[must_use]
    pub(crate) fn connection(&self) -> ConnectionId {
        ConnectionId::from_uuid(self.id)
    }
}

/// `.../federation/connections/{id}/links/{user_id}`: one user's link
/// through a connection.
#[derive(Deserialize)]
pub(crate) struct ConnectionLinkPath {
    id: Uuid,
    user_id: Uuid,
}

impl ConnectionLinkPath {
    /// The connection named.
    #[must_use]
    pub(crate) fn connection(&self) -> ConnectionId {
        ConnectionId::from_uuid(self.id)
    }

    /// The user whose link it is.
    #[must_use]
    pub(crate) fn user(&self) -> UserId {
        UserId::from_uuid(self.user_id)
    }
}

/// `.../federation/users/{user_id}/...`: one user's federation records.
#[derive(Deserialize)]
pub(crate) struct FederatedUserPath {
    user_id: Uuid,
}

impl FederatedUserPath {
    /// The user named.
    #[must_use]
    pub(crate) fn user(&self) -> UserId {
        UserId::from_uuid(self.user_id)
    }
}

/// `.../saml/apps/{app_id}/...`: one of the tenant's SAML apps.
#[derive(Deserialize)]
pub(crate) struct SamlAppPath {
    app_id: Uuid,
}

impl SamlAppPath {
    /// The app named.
    #[must_use]
    pub(crate) fn app(&self) -> SamlServiceProviderId {
        SamlServiceProviderId::from_uuid(self.app_id)
    }
}
