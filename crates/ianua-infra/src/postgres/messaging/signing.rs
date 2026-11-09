//! The secret a rotation keeps signing beside the new one, as two columns
//! hold it: the old secret sealed, and when it stops signing, both empty
//! once none signs.
//!
//! Push subscriptions and webhooks keep it the same way, so the mapping is
//! written once, here.

use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{PreviousSigningSecret, SealedSecret};
use time::OffsetDateTime;

use crate::postgres::foundation::stored::Stored;

/// The two columns `previous` is written to.
pub(crate) fn previous_columns(
    previous: &PreviousSigningSecret,
) -> (Option<&str>, Option<OffsetDateTime>) {
    match previous {
        PreviousSigningSecret::Retired => (None, None),
        PreviousSigningSecret::SignsUntil { secret, until } => {
            (Some(secret.as_str()), Some(*until))
        }
    }
}

/// The old secret the two columns of a row of `entity` hold.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when only one of them is empty,
/// or the secret is nothing a sealer could have written.
pub(crate) fn previous_from(
    entity: Stored,
    sealed: Option<String>,
    until: Option<OffsetDateTime>,
) -> Result<PreviousSigningSecret, DomainError> {
    match (sealed, until) {
        (None, None) => Ok(PreviousSigningSecret::Retired),
        (Some(sealed), Some(until)) => Ok(PreviousSigningSecret::SignsUntil {
            secret: entity.value("previous secret", SealedSecret::new(sealed))?,
            until,
        }),
        (Some(_), None) | (None, Some(_)) => Err(DomainError::corrupt_row(
            entity.0,
            "an old secret without its end, or an end without one",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::rows::at;
    use crate::test_support::rows::branding::sealed;

    const NOTE: Stored = Stored("note");

    /// An old secret still signing reads back with when it stops.
    #[test]
    fn an_old_secret_reads_back_with_its_end() {
        let previous = PreviousSigningSecret::SignsUntil {
            secret: sealed("old"),
            until: at(60),
        };
        let (secret, until) = previous_columns(&previous);

        let read = previous_from(NOTE, secret.map(str::to_owned), until).unwrap();

        assert_eq!(read, previous);
    }

    /// A stored previous signing secret without its end time is rejected
    /// as corrupt storage.
    #[test]
    fn an_old_secret_without_its_end_is_refused() {
        let read = previous_from(NOTE, Some("v1.old".to_owned()), None);

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
