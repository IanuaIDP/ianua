//! The clients a tenant registers and what they are allowed.

/// API keys a tenant gives to machines.
pub mod api_key;
/// `OAuth2` clients registered by a tenant and the grant types they may use.
pub mod client;
pub mod consent;
/// How a client proves itself at the token endpoint.
pub mod credential;
/// How long a client's tokens last.
pub mod lifetimes;
/// Apps registering themselves as clients, and managing themselves after.
pub mod registration;
/// The rules every client keeps.
pub mod rules;
/// What a client is set up with beyond its redirects, grants and scopes.
pub mod settings;
/// OAuth client status: active or revoked.
pub mod status;
