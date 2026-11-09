//! Home realm discovery bodies: the connection a person's address is sent
//! to sign in through.

use ianua_app::use_cases::federation::connections::HomeRealm;
use ianua_domain::domains::federation::connection::FederationProtocol;
use ianua_domain::types::{ConnectionId, Email};
use serde::{Deserialize, Serialize};

use crate::error::ApiError;

/// Request body for finding where an address signs in.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct DiscoverRealmBody {
    /// The address the person typed.
    pub email: String,
}

impl TryFrom<DiscoverRealmBody> for Email {
    type Error = ApiError;

    fn try_from(body: DiscoverRealmBody) -> Result<Self, ApiError> {
        Email::new(body.email).map_err(ApiError::validation)
    }
}

/// Where an address signs in: through a connection, or the tenant's own
/// sign-in when `routed` is `false`.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct HomeRealmResponse {
    /// Whether the address's domain is sent to a connection.
    pub routed: bool,
    /// The connection to sign in through, when routed.
    #[schema(value_type = Option<String>, format = Uuid)]
    pub connection_id: Option<ConnectionId>,
    /// The provider's name, when routed.
    pub provider_name: Option<String>,
    /// `Saml` or `Oidc`, when routed.
    #[schema(schema_with = crate::dto::schemas::federation_protocol)]
    pub protocol: Option<FederationProtocol>,
}

impl From<HomeRealm> for HomeRealmResponse {
    fn from(realm: HomeRealm) -> Self {
        match realm {
            HomeRealm::Provider {
                connection_id,
                provider_name,
                protocol,
            } => Self {
                routed: true,
                connection_id: Some(connection_id),
                provider_name: Some(provider_name.as_str().to_owned()),
                protocol: Some(protocol),
            },
            HomeRealm::NotRouted => Self {
                routed: false,
                connection_id: None,
                provider_name: None,
                protocol: None,
            },
        }
    }
}
