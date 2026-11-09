//! Apps registering themselves as clients (RFC 7591) and managing their
//! own registration afterwards (RFC 7592), and the initial access tokens
//! the tenant hands out so they may.

pub(crate) mod delete;
pub(crate) mod issue_initial_access_token;
pub(crate) mod list_initial_access_tokens;
pub mod managed;
pub(crate) mod read;
pub(crate) mod register_client;
pub(crate) mod revoke_initial_access_token;
pub(crate) mod update;

pub use delete::DeleteUseCase;
pub use issue_initial_access_token::{
    IssueInitialAccessTokenPorts, IssueInitialAccessTokenRequest, IssueInitialAccessTokenUseCase,
    IssuedInitialAccessToken,
};
pub use list_initial_access_tokens::{
    ListInitialAccessTokensPorts, ListInitialAccessTokensUseCase,
};
pub use read::ReadUseCase;
pub use register_client::{
    ClientMetadata, RegisterClientPorts, RegisterClientRequest, RegisterClientUseCase,
    RegisteredClient,
};
pub use revoke_initial_access_token::{
    RevokeInitialAccessTokenPorts, RevokeInitialAccessTokenUseCase,
};
pub use update::{UpdateRequest, UpdateUseCase};
