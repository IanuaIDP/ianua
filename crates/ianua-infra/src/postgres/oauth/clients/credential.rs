//! How a client proves itself, in the shape its `credential` column keeps:
//! a secret's hashes, never the secret, the client's public keys or where
//! they are published, its certificate's subject, or nothing.

use ianua_domain::domains::oauth::clients::credential::{
    CertificateSubject, ClientCredential, ClientJwks, ClientKeys, ClientSecret, PreviousSecret,
    SecretSentBy,
};
use ianua_domain::types::{HttpsUrl, TokenHash};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

/// A client's credential as it is stored.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "method")]
pub(super) enum StoredCredential {
    /// A secret, as the hash of the current one and maybe the one before.
    Secret {
        current: TokenHash,
        previous: Option<StoredPrevious>,
        sent_by: StoredSentBy,
    },
    /// A JWT signed with the client's own key.
    PrivateKeyJwt { keys: StoredKeys },
    /// A TLS client certificate with this subject.
    TlsClientAuth { subject: CertificateSubject },
    /// Nothing: a public client.
    Public,
}

/// The secret before the current one, while it is still taken.
#[derive(Serialize, Deserialize)]
pub(super) struct StoredPrevious {
    hash: TokenHash,
    #[serde(with = "time::serde::rfc3339")]
    until: OffsetDateTime,
}

/// How a secret is sent.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum StoredSentBy {
    Basic,
    Post,
}

/// Where a key-signing client's public keys are.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum StoredKeys {
    Listed(ClientJwks),
    Published(HttpsUrl),
}

impl From<&ClientCredential> for StoredCredential {
    fn from(credential: &ClientCredential) -> Self {
        match credential {
            ClientCredential::Secret(secret) => Self::Secret {
                current: secret.current().clone(),
                previous: previous_of(secret.previous()),
                sent_by: StoredSentBy::from(secret.sent_by()),
            },
            ClientCredential::PrivateKeyJwt(keys) => Self::PrivateKeyJwt {
                keys: StoredKeys::from(keys),
            },
            ClientCredential::TlsClientAuth(subject) => Self::TlsClientAuth {
                subject: subject.clone(),
            },
            ClientCredential::Public => Self::Public,
        }
    }
}

impl From<StoredCredential> for ClientCredential {
    fn from(stored: StoredCredential) -> Self {
        match stored {
            StoredCredential::Secret {
                current,
                previous,
                sent_by,
            } => Self::Secret(ClientSecret::from_stored(
                current,
                previous.map_or(PreviousSecret::Retired, |previous| {
                    PreviousSecret::AcceptedUntil {
                        hash: previous.hash,
                        until: previous.until,
                    }
                }),
                SecretSentBy::from(sent_by),
            )),
            StoredCredential::PrivateKeyJwt { keys } => Self::PrivateKeyJwt(ClientKeys::from(keys)),
            StoredCredential::TlsClientAuth { subject } => Self::TlsClientAuth(subject),
            StoredCredential::Public => Self::Public,
        }
    }
}

/// The secret before the current one, as it is stored: none once retired.
fn previous_of(previous: &PreviousSecret) -> Option<StoredPrevious> {
    match previous {
        PreviousSecret::Retired => None,
        PreviousSecret::AcceptedUntil { hash, until } => Some(StoredPrevious {
            hash: hash.clone(),
            until: *until,
        }),
    }
}

impl From<SecretSentBy> for StoredSentBy {
    fn from(sent_by: SecretSentBy) -> Self {
        match sent_by {
            SecretSentBy::Basic => Self::Basic,
            SecretSentBy::Post => Self::Post,
        }
    }
}

impl From<StoredSentBy> for SecretSentBy {
    fn from(stored: StoredSentBy) -> Self {
        match stored {
            StoredSentBy::Basic => Self::Basic,
            StoredSentBy::Post => Self::Post,
        }
    }
}

impl From<&ClientKeys> for StoredKeys {
    fn from(keys: &ClientKeys) -> Self {
        match keys {
            ClientKeys::Listed(jwks) => Self::Listed(jwks.clone()),
            ClientKeys::Published(url) => Self::Published(url.clone()),
        }
    }
}

impl From<StoredKeys> for ClientKeys {
    fn from(stored: StoredKeys) -> Self {
        match stored {
            StoredKeys::Listed(jwks) => Self::Listed(jwks),
            StoredKeys::Published(url) => Self::Published(url),
        }
    }
}
