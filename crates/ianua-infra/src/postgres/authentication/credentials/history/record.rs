//! A retired password as its row holds it: read back into its hash.

use ianua_domain::types::PasswordHash;

/// A retired password as it is read. The store's checked queries fill it.
pub(super) struct RetiredRecord {
    pub(super) password_hash: String,
}

impl RetiredRecord {
    /// The hash the record holds.
    pub(super) fn into_hash(self) -> PasswordHash {
        PasswordHash::from_stored(self.password_hash)
    }
}
