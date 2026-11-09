//! What a client is registered to prove itself with, and the fresh id and
//! secret that come with it: shared by an admin creating a client and an
//! app registering itself.

use ianua_domain::domains::oauth::clients::credential::{
    CertificateSubject, ClientCredential, ClientKeys, ClientSecret, SecretSentBy,
};
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::ClientId;

use crate::error::{AppError, OrInternal};
use crate::ports::oauth::ClientSecretGenerator;

/// How a new client will prove itself at the token endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientProving {
    /// A secret, sent in the `Authorization: Basic` header.
    SecretInHeader,
    /// A secret, sent in the form body.
    SecretInBody,
    /// A JWT signed with one of these keys (`private_key_jwt`).
    SignedJwt(ClientKeys),
    /// A TLS client certificate with this subject (`tls_client_auth`).
    Certificate(CertificateSubject),
    /// Nothing: a public client.
    Nothing,
}

/// The secret a new client was handed, if it proves itself with one.
pub enum ShownSecret {
    /// None: it proves itself another way.
    NotIssued,
    /// This one, shown once and never stored.
    Shown(Secret),
}

/// A fresh client id, and what the client proves itself with: for a client
/// holding a secret, a fresh secret's hash, its raw value shown once.
///
/// # Errors
///
/// - `AppError::Internal` when the randomness source fails.
pub(in crate::use_cases::oauth) async fn fresh_credentials(
    generator: &dyn ClientSecretGenerator,
    proving: ClientProving,
) -> Result<(ClientId, ClientCredential, ShownSecret), AppError> {
    let credential = match proving {
        ClientProving::SecretInHeader => return with_secret(generator, SecretSentBy::Basic).await,
        ClientProving::SecretInBody => return with_secret(generator, SecretSentBy::Post).await,
        ClientProving::SignedJwt(keys) => ClientCredential::PrivateKeyJwt(keys),
        ClientProving::Certificate(subject) => ClientCredential::TlsClientAuth(subject),
        ClientProving::Nothing => ClientCredential::Public,
    };
    let id = generator.generate_client_id().await.or_internal()?;
    Ok((id, credential, ShownSecret::NotIssued))
}

/// A fresh client id and secret, the secret sent `sent_by`.
///
/// # Errors
///
/// - `AppError::Internal` when the randomness source fails.
async fn with_secret(
    generator: &dyn ClientSecretGenerator,
    sent_by: SecretSentBy,
) -> Result<(ClientId, ClientCredential, ShownSecret), AppError> {
    let made = generator.generate().await.or_internal()?;
    let credential = ClientCredential::Secret(ClientSecret::new(made.secret_hash, sent_by));
    Ok((
        made.client_id_value,
        credential,
        ShownSecret::Shown(made.raw_secret),
    ))
}
