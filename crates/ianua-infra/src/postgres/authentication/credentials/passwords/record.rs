//! An account's password as its row holds it: read back into the hash and
//! who set it when, each through its own constructor.

use ianua_domain::domains::authentication::credentials::password_rules::{
    CurrentPassword, PasswordOrigin,
};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::PasswordHash;
use time::OffsetDateTime;

use crate::postgres::foundation::stored::{Stored, StoredWord as _};

const PASSWORD: Stored = Stored("password");

/// A password as it is read. The store's checked queries fill it.
pub(super) struct PasswordRecord {
    pub(super) password_hash: String,
    pub(super) origin: String,
    pub(super) changed_at: OffsetDateTime,
}

impl PasswordRecord {
    /// The hash the record holds.
    pub(super) fn into_hash(self) -> PasswordHash {
        PasswordHash::from_stored(self.password_hash)
    }

    /// Who set the password the record holds, and when.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the origin is unknown.
    pub(super) fn into_current_password(self) -> Result<CurrentPassword, DomainError> {
        Ok(CurrentPassword {
            origin: PASSWORD.choice(&self.origin)?,
            changed_at: self.changed_at,
        })
    }
}

/// The word `origin` is written as.
pub(super) fn origin_word(origin: PasswordOrigin) -> &'static str {
    origin.word()
}
