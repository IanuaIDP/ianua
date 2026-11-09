//! An account's channel on the wire: the address to give a service and
//! what it still waits for. A key is taken in and never given back; a
//! token is given back once asked for, to paste at the service.

use ianua_app::use_cases::workflows::accounts::channels::{ChannelView, SetKeyRequest};
use ianua_domain::domains::workflows::triggers::channel::{
    ChannelKey, ChannelSetup, ChannelStatus,
};
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::IntegrationAccountId;
use serde::{Deserialize, Serialize};

use crate::error::ApiError;

/// How a channel gets to ready.
#[derive(Serialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ChannelSetupBody {
    /// The platform registers it at the service.
    Registered,
    /// A person pastes the service's key in.
    PastedKey,
    /// The service sends a token that a person pastes back at the service.
    TokenFromService,
}

/// Where a channel is.
#[derive(Serialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ChannelStatusBody {
    /// It is being registered at the service.
    Registering,
    /// It waits for its owner to paste in the service's key.
    AwaitingKey,
    /// It waits for the service to send its token.
    AwaitingToken,
    /// It holds the token and waits for its owner to confirm they pasted
    /// it back.
    AwaitingConfirmation,
    /// It takes the service's events.
    Live,
    /// It lapsed, and its events start nothing.
    Lapsed,
}

/// An account's channel.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct ChannelResponse {
    /// The address to give the service.
    pub address: String,
    /// How it gets to ready.
    pub setup: ChannelSetupBody,
    /// Where it is.
    pub status: ChannelStatusBody,
}

impl From<ChannelView> for ChannelResponse {
    fn from(view: ChannelView) -> Self {
        Self {
            address: view.address,
            setup: match view.setup {
                ChannelSetup::Registered => ChannelSetupBody::Registered,
                ChannelSetup::PastedKey => ChannelSetupBody::PastedKey,
                ChannelSetup::TokenFromService => ChannelSetupBody::TokenFromService,
            },
            status: match view.status {
                ChannelStatus::Registering => ChannelStatusBody::Registering,
                ChannelStatus::AwaitingKey => ChannelStatusBody::AwaitingKey,
                ChannelStatus::AwaitingToken => ChannelStatusBody::AwaitingToken,
                ChannelStatus::AwaitingConfirmation => ChannelStatusBody::AwaitingConfirmation,
                ChannelStatus::Live => ChannelStatusBody::Live,
                ChannelStatus::Lapsed => ChannelStatusBody::Lapsed,
            },
        }
    }
}

/// Request body for pasting in the key a service signs its deliveries with.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct SetChannelKeyBody {
    /// The key, in the clear. At least 16 characters. It is sealed before
    /// it is kept and never shown again.
    pub key: String,
}

impl SetChannelKeyBody {
    /// The request to set this key on `account_id`'s channel.
    ///
    /// # Errors
    ///
    /// [`ApiError`] when the key is too short or too long.
    pub(crate) fn request(
        self,
        account_id: IntegrationAccountId,
    ) -> Result<SetKeyRequest, ApiError> {
        Ok(SetKeyRequest {
            account_id,
            key: ChannelKey::new(self.key).map_err(ApiError::validation)?,
        })
    }
}

/// The token a service sent, to paste back at the service.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct ChannelTokenResponse {
    /// What the channel's owner pastes back at the service.
    pub token: String,
}

impl From<Secret> for ChannelTokenResponse {
    fn from(token: Secret) -> Self {
        Self {
            token: token.expose().to_owned(),
        }
    }
}
