//! OAuth bodies, by app area: clients and API keys and what they are
//! registered with, apps registering themselves, the browser and device
//! flows, what the token endpoint and the endpoints beside it answer, the
//! OIDC discovery document, and the protocol's error body.

pub mod api_keys;
pub mod browser;
pub mod clients;
pub mod device;
pub mod errors;
pub mod forms;
pub mod metadata;
pub mod provider;
pub mod registration;
pub mod tokens;
