//! The token endpoint and the endpoints beside it that a client proves
//! itself to: one use case per grant (authorization code, refresh token,
//! client credentials, device code, token exchange), introspection and
//! revocation, with the client proof, the issuing and the refusals they
//! share.

pub(crate) mod authorization_code;
pub mod client_auth;
pub(crate) mod client_credentials;
pub(crate) mod device_code;
pub(crate) mod exchange;
pub(crate) mod introspect;
pub mod issuing;
pub(crate) mod refresh;
pub mod refusal;
pub(crate) mod revoke;

pub use authorization_code::{CodeGrant, RedeemCodePorts, RedeemCodeUseCase};
pub use client_credentials::{
    ClientCredentialsGrant, ClientCredentialsPorts, ClientCredentialsUseCase, MachineScopes,
};
pub use device_code::{CollectDeviceTokensPorts, CollectDeviceTokensUseCase, DeviceCodeGrant};
pub use exchange::{ActorSent, ExchangeGrant, ExchangePorts, ExchangeUseCase};
pub use introspect::{IntrospectPorts, IntrospectRequest, IntrospectUseCase, IntrospectionResult};
pub use refresh::{RefreshGrant, RefreshTokensPorts, RefreshTokensUseCase};
pub use revoke::{RevokePorts, RevokeRequest, RevokeUseCase, TypeHint};
