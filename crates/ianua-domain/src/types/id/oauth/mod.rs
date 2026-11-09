//! Ids of OAuth clients, their requests and API keys.

/// Id of an API key.
pub(crate) mod api_key;
/// The public identifier of an OAuth client.
pub(crate) mod client;
/// Id of an OAuth client's stored record.
pub(crate) mod client_record;
/// Id of an initial access token for registering an OAuth client.
pub(crate) mod initial_access_token;
/// The visible start of an API key.
pub(crate) mod key_prefix;
/// Id of a pushed authorization request.
pub(crate) mod pushed_request;

pub use api_key::ApiKeyId;
pub use client::ClientId;
pub use client_record::OAuthClientId;
pub use initial_access_token::InitialAccessTokenId;
pub use key_prefix::KeyPrefix;
pub use pushed_request::PushedRequestId;
