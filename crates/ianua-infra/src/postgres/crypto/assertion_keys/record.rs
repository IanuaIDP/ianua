//! An assertion key as its row holds it: read back into the domain's key,
//! with or without its sealed private half, and a set's keys written out.

use ianua_domain::domains::crypto::assertion_key::{AssertionKey, AssertionKeyRow, PrivateHalf};
use ianua_domain::domains::crypto::key_status::KeyState;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{KeyId, PublicKeyPem, SealedSecret};
use time::OffsetDateTime;

use crate::postgres::foundation::stored::{Stored, StoredWord as _};

const ASSERTION_KEY: Stored = Stored("assertion key");

/// A key as the side that rotates and publishes keys reads it: no private
/// half. The store's checked queries fill it.
pub(super) struct AssertionKeyRecord {
    pub(super) kid: String,
    pub(super) algorithm: String,
    pub(super) public_key: String,
    pub(super) status: String,
    pub(super) rotated_at: Option<OffsetDateTime>,
    pub(super) created_at: OffsetDateTime,
}

impl AssertionKeyRecord {
    /// The key the record holds, rebuilt through the domain's checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a value no longer passes
    /// its rules, a word is unknown, or the row breaks a rule the key keeps.
    pub(super) fn into_key(self) -> Result<AssertionKey, DomainError> {
        let status = ASSERTION_KEY.choice(&self.status)?;
        AssertionKey::reconstitute(AssertionKeyRow {
            kid: ASSERTION_KEY.value("kid", KeyId::new(self.kid))?,
            algorithm: ASSERTION_KEY.choice(&self.algorithm)?,
            public_key: ASSERTION_KEY.value("public key", PublicKeyPem::new(self.public_key))?,
            state: KeyState::from_stored(status, self.rotated_at)?,
            created_at: self.created_at,
        })
    }
}

/// A key as the gateway reads it, its private half still sealed.
pub(super) struct SealedAssertionKeyRecord {
    pub(super) kid: String,
    pub(super) algorithm: String,
    pub(super) public_key: String,
    pub(super) private_key_sealed: String,
    pub(super) status: String,
    pub(super) rotated_at: Option<OffsetDateTime>,
    pub(super) created_at: OffsetDateTime,
}

impl SealedAssertionKeyRecord {
    /// The record's public part, and its private half as the record keeps
    /// it, sealed.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the private column holds
    /// nothing a sealer could have written.
    pub(super) fn split(self) -> Result<(AssertionKeyRecord, SealedSecret), DomainError> {
        let sealed = ASSERTION_KEY.value(
            "private key",
            SealedSecret::new(self.private_key_sealed.as_str()),
        )?;
        let public = AssertionKeyRecord {
            kid: self.kid,
            algorithm: self.algorithm,
            public_key: self.public_key,
            status: self.status,
            rotated_at: self.rotated_at,
            created_at: self.created_at,
        };
        Ok((public, sealed))
    }
}

/// The standing of a set's keys, one list per column and one place per
/// key, as one statement writes them.
pub(super) struct StandingColumns {
    pub(super) kids: Vec<String>,
    pub(super) statuses: Vec<String>,
    pub(super) rotated_at: Vec<Option<OffsetDateTime>>,
}

impl StandingColumns {
    /// The standing of each of `keys`.
    pub(super) fn of<'k>(keys: impl IntoIterator<Item = &'k AssertionKey>) -> Self {
        let mut columns = Self {
            kids: Vec::new(),
            statuses: Vec::new(),
            rotated_at: Vec::new(),
        };
        for key in keys {
            columns.kids.push(key.kid().as_str().to_owned());
            columns.statuses.push(key.status().word().to_owned());
            columns.rotated_at.push(key.rotated_at());
        }
        columns
    }
}

/// New keys' columns, each private half replaced by its sealed form, as one
/// statement adds them.
pub(super) struct AddedColumns {
    pub(super) kids: Vec<String>,
    pub(super) algorithms: Vec<String>,
    pub(super) public_keys: Vec<String>,
    pub(super) private_keys: Vec<String>,
    pub(super) statuses: Vec<String>,
    pub(super) rotated_at: Vec<Option<OffsetDateTime>>,
    pub(super) created_at: Vec<OffsetDateTime>,
}

impl AddedColumns {
    /// The columns of `added`, each with the sealed form of its private
    /// half.
    pub(super) fn of(added: &[(&AssertionKey, SealedSecret)]) -> Self {
        Self {
            kids: added
                .iter()
                .map(|(key, _)| key.kid().as_str().to_owned())
                .collect(),
            algorithms: added
                .iter()
                .map(|(key, _)| key.algorithm().word().to_owned())
                .collect(),
            public_keys: added
                .iter()
                .map(|(key, _)| key.public_key().as_str().to_owned())
                .collect(),
            private_keys: added
                .iter()
                .map(|(_, sealed)| sealed.as_str().to_owned())
                .collect(),
            statuses: added
                .iter()
                .map(|(key, _)| key.status().word().to_owned())
                .collect(),
            rotated_at: added.iter().map(|(key, _)| key.rotated_at()).collect(),
            created_at: added.iter().map(|(key, _)| key.created_at()).collect(),
        }
    }
}

/// Whether `key` is new to storage: made here and not read back.
pub(super) fn is_new(key: &AssertionKey) -> bool {
    matches!(key.private_half(), PrivateHalf::Fresh(_))
}
