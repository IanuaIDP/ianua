//! What a connection is set up with, as read and stored.

pub(super) mod allowed_domains;
pub(super) mod issuer;
pub(crate) mod provider_config;
pub(super) mod stored_config;
pub use provider_config::{OidcProviderConfig, ProviderConfig, SamlProviderConfig};
