//! Domain events for OAuth.

/// Events about the OAuth clients and API keys a tenant registers.
pub mod clients;
/// Events about the consent a person gives an OAuth client.
pub mod consent;
/// Events about what OAuth hands out: authorization codes, device authorizations and tokens.
pub mod grants;
