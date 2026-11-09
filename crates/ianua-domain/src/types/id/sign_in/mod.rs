//! Ids of how people sign in and stay signed in: sessions, passkeys, outside providers, tokens.

/// Id of one in-flight `WebAuthn` ceremony.
pub(crate) mod ceremony;
/// Id of a federated identity provider connection.
pub(crate) mod connection;
/// Who a person is at an external identity provider.
pub(crate) mod federated_subject;
/// The `kid` naming a signing key.
pub(crate) mod key;
/// Id of a registered passkey.
pub(crate) mod passkey;
/// The id an authenticator gave a passkey.
pub(crate) mod passkey_credential;
/// Id of a refresh token family.
pub(crate) mod refresh_family;
/// Id of a session.
pub(crate) mod session;
/// A token's `jti`, used to spot replays.
pub(crate) mod token;

pub use ceremony::CeremonyId;
pub use connection::ConnectionId;
pub use federated_subject::FederatedSubject;
pub use key::KeyId;
pub use passkey::PasskeyId;
pub use passkey_credential::PasskeyCredentialId;
pub use refresh_family::RefreshFamilyId;
pub use session::SessionId;
pub use token::TokenId;
