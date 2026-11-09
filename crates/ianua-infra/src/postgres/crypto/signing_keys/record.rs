//! A signing key as its row holds it: read back into the domain's key, or
//! into its public half alone, and a key set written out from it, every
//! private key sealed.

use ianua_domain::domains::crypto::key_status::KeyState;
use ianua_domain::domains::crypto::signing_key::{SigningKey, SigningKeyRow};
use ianua_domain::domains::crypto::verifying_key::{VerifyingKey, VerifyingKeyRow};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{Expiry, KeyId, PublicKeyPem, SealedSecret};
use time::OffsetDateTime;

use crate::postgres::foundation::stored::{Stored, StoredWord as _};

const SIGNING_KEY: Stored = Stored("signing key");

/// A key as it is read, its private key still sealed. The store's checked
/// queries fill it.
pub(super) struct SigningKeyRecord {
    pub(super) kid: String,
    pub(super) algorithm: String,
    pub(super) public_key: String,
    pub(super) private_key_sealed: String,
    pub(super) status: String,
    pub(super) rotated_at: Option<OffsetDateTime>,
    pub(super) expires_at: Option<OffsetDateTime>,
    pub(super) created_at: OffsetDateTime,
}

impl SigningKeyRecord {
    /// The private key as the record keeps it, sealed.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the column holds nothing
    /// a sealer could have written.
    pub(super) fn sealed_private_key(&self) -> Result<SealedSecret, DomainError> {
        SIGNING_KEY.value(
            "private key",
            SealedSecret::new(self.private_key_sealed.as_str()),
        )
    }

    /// The key the record holds, with `private_key` opened from its sealed
    /// form, rebuilt through the domain's checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a value no longer passes
    /// its rules, a word is unknown, or the row breaks a rule the key keeps.
    pub(super) fn into_signing_key(self, private_key: Secret) -> Result<SigningKey, DomainError> {
        let status = SIGNING_KEY.choice(&self.status)?;
        SigningKey::reconstitute(SigningKeyRow {
            kid: SIGNING_KEY.value("kid", KeyId::new(self.kid))?,
            algorithm: SIGNING_KEY.choice(&self.algorithm)?,
            public_key: SIGNING_KEY.value("public key", PublicKeyPem::new(self.public_key))?,
            private_key,
            state: KeyState::from_stored(status, self.rotated_at)?,
            created_at: self.created_at,
            expires_at: self.expires_at.map_or(Expiry::Never, Expiry::At),
        })
    }
}

/// The public half of a key as it is read, for a role that may not read
/// the private one. The store's checked queries fill it.
pub(super) struct VerifyingKeyRecord {
    pub(super) kid: String,
    pub(super) algorithm: String,
    pub(super) public_key: String,
    pub(super) status: String,
    pub(super) rotated_at: Option<OffsetDateTime>,
    pub(super) expires_at: Option<OffsetDateTime>,
    pub(super) created_at: OffsetDateTime,
}

impl VerifyingKeyRecord {
    /// The public half the record holds, rebuilt through the domain's
    /// checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a value no longer passes
    /// its rules, a word is unknown, or the row breaks a rule the key keeps.
    pub(super) fn into_verifying_key(self) -> Result<VerifyingKey, DomainError> {
        let status = SIGNING_KEY.choice(&self.status)?;
        VerifyingKey::reconstitute(VerifyingKeyRow {
            kid: SIGNING_KEY.value("kid", KeyId::new(self.kid))?,
            algorithm: SIGNING_KEY.choice(&self.algorithm)?,
            public_key: SIGNING_KEY.value("public key", PublicKeyPem::new(self.public_key))?,
            state: KeyState::from_stored(status, self.rotated_at)?,
            created_at: self.created_at,
            expires_at: self.expires_at.map_or(Expiry::Never, Expiry::At),
        })
    }
}

/// A key set's columns, one list per column and one place per key, as one
/// statement writes them.
pub(super) struct KeySetColumns {
    pub(super) kids: Vec<String>,
    pub(super) algorithms: Vec<String>,
    pub(super) public_keys: Vec<String>,
    pub(super) private_keys: Vec<String>,
    pub(super) statuses: Vec<String>,
    pub(super) rotated_at: Vec<Option<OffsetDateTime>>,
    pub(super) expires_at: Vec<Option<OffsetDateTime>>,
    pub(super) created_at: Vec<OffsetDateTime>,
}

impl KeySetColumns {
    /// The columns `keys` are written to, each private key replaced by its
    /// sealed form at the same place in `sealed`.
    pub(super) fn of(keys: &[SigningKey], sealed: &[SealedSecret]) -> Self {
        Self {
            kids: keys
                .iter()
                .map(|key| key.kid().as_str().to_owned())
                .collect(),
            algorithms: keys
                .iter()
                .map(|key| key.algorithm().word().to_owned())
                .collect(),
            public_keys: keys
                .iter()
                .map(|key| key.public_key().as_str().to_owned())
                .collect(),
            private_keys: sealed
                .iter()
                .map(|sealed| sealed.as_str().to_owned())
                .collect(),
            statuses: keys
                .iter()
                .map(|key| key.status().word().to_owned())
                .collect(),
            rotated_at: keys.iter().map(SigningKey::rotated_at).collect(),
            expires_at: keys.iter().map(|key| key.expires_at().instant()).collect(),
            created_at: keys.iter().map(SigningKey::created_at).collect(),
        }
    }
}
