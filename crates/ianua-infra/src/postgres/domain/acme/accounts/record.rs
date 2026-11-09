//! An ACME account as its row holds it: the credentials, sealed, and once
//! opened, read back as the secret they are.

use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::SealedSecret;

use crate::postgres::foundation::stored::Stored;

const ACME_ACCOUNT: Stored = Stored("ACME account");

/// An account as it is read, its credentials still sealed. The store's
/// checked query fills it.
pub(super) struct AccountRecord {
    pub(super) credentials_sealed: String,
}

impl AccountRecord {
    /// The credentials as the record keeps them, sealed.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the column holds nothing
    /// a sealer could have written.
    pub(super) fn sealed(&self) -> Result<SealedSecret, DomainError> {
        ACME_ACCOUNT.value(
            "credentials",
            SealedSecret::new(self.credentials_sealed.as_str()),
        )
    }
}

/// The credentials `opened` holds, as the secret they are.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when they are not text, which no
/// store writes. The bytes are left out of the error, as they are the key.
pub(super) fn into_credentials(opened: Vec<u8>) -> Result<Secret, DomainError> {
    String::from_utf8(opened)
        .map(Secret::new)
        .map_err(|_| DomainError::corrupt_row(ACME_ACCOUNT.0, "credentials that are not text"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Opened credentials that are text come back as they were kept.
    #[test]
    fn text_credentials_come_back_as_kept() {
        let credentials = into_credentials(b"{\"id\":\"acct\"}".to_vec()).unwrap();

        assert_eq!(credentials.expose(), "{\"id\":\"acct\"}");
    }

    /// Opened ACME credentials containing invalid UTF-8 are rejected as
    /// corrupt storage.
    #[test]
    fn credentials_that_are_not_text_are_refused() {
        let result = into_credentials(vec![0xff, 0xfe]);

        assert!(matches!(result, Err(DomainError::Infrastructure(_))));
    }
}
