//! What an access or refresh token must be presented with, as its two
//! columns hold it: a word, and the thumbprint of the key or certificate
//! it is bound to.

use ianua_domain::domains::oauth::grants::token_binding::{
    CertThumbprint, JwkThumbprint, SenderBinding,
};
use ianua_domain::shared::errors::DomainError;

use crate::postgres::foundation::stored::Stored;

/// The columns `binding` is written to.
pub(crate) fn binding_columns(binding: &SenderBinding) -> (&'static str, Option<&str>) {
    match binding {
        SenderBinding::Bearer => ("bearer", None),
        SenderBinding::DpopKey(key) => ("dpop", Some(key.as_str())),
        SenderBinding::Certificate(certificate) => ("certificate", Some(certificate.as_str())),
    }
}

/// The binding the columns of a stored `entity` hold.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when the word is unknown, the
/// thumbprint does not fit it, or is no thumbprint.
pub(crate) fn binding_from(
    entity: Stored,
    word: &str,
    thumbprint: Option<String>,
) -> Result<SenderBinding, DomainError> {
    match (word, thumbprint) {
        ("bearer", None) => Ok(SenderBinding::Bearer),
        ("dpop", Some(key)) => Ok(SenderBinding::DpopKey(
            entity.value("DPoP key thumbprint", JwkThumbprint::new(key))?,
        )),
        ("certificate", Some(certificate)) => Ok(SenderBinding::Certificate(
            entity.value("certificate thumbprint", CertThumbprint::new(certificate))?,
        )),
        _ => Err(DomainError::corrupt_row(
            entity.0,
            "a binding this version cannot read",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: Stored = Stored("token");

    /// Every binding reads back from the columns it is written to.
    #[test]
    fn every_binding_reads_back_from_its_columns() {
        let thumbprint = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs";
        for binding in [
            SenderBinding::Bearer,
            SenderBinding::DpopKey(JwkThumbprint::new(thumbprint).unwrap()),
            SenderBinding::Certificate(CertThumbprint::new(thumbprint).unwrap()),
        ] {
            let (word, stored) = binding_columns(&binding);

            let read = binding_from(TOKEN, word, stored.map(str::to_owned)).unwrap();

            assert_eq!(read, binding);
        }
    }

    /// A bearer binding with a stored thumbprint is rejected as corrupt
    /// storage because those columns contradict each other.
    #[test]
    fn a_thumbprint_that_does_not_fit_the_word_is_refused() {
        let read = binding_from(TOKEN, "bearer", Some("x".to_owned()));

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
