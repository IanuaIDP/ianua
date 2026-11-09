//! Whether a delegation is revoked, from the statuses its row and the rows
//! it draws its authority from hold, with the status of the key each minted
//! one was minted with: read back through the domain's own words, so an
//! unknown word refuses the row rather than letting it grant.

use ianua_domain::domains::agents::authority::delegation::DelegationStatus;
use ianua_domain::domains::crypto::key_status::KeyStatus;
use ianua_domain::shared::errors::DomainError;
use uuid::Uuid;

use crate::postgres::foundation::stored::Stored;

const DELEGATION: Stored = Stored("delegation");

const CREDENTIAL: Stored = Stored("agent credential");

/// One delegation in the chain, as the status query reads it.
pub(super) struct ChainLink {
    /// Its status, or `None` when it is gone.
    pub(super) status: Option<String>,
    /// The credential it was minted with, for a minted one.
    pub(super) minted_with: Option<Uuid>,
    /// That credential's status, or `None` when it is gone.
    pub(super) key_status: Option<String>,
}

/// Whether the delegation whose chain holds `links` is revoked: it is when
/// any of them is revoked or gone, or was minted with a key now revoked or
/// gone, or when nothing was read.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when a status is a word no status
/// has.
pub(super) fn into_revoked(links: Vec<ChainLink>) -> Result<bool, DomainError> {
    if links.is_empty() {
        return Ok(true);
    }
    links
        .into_iter()
        .try_fold(false, |revoked, link| Ok(revoked | stands_revoked(link)?))
}

/// Whether the one delegation `link` reads is revoked. One with no row is
/// gone, and so is revoked.
fn stands_revoked(link: ChainLink) -> Result<bool, DomainError> {
    let Some(status) = link.status else {
        return Ok(true);
    };
    let read: DelegationStatus = DELEGATION.choice(&status)?;
    if read == DelegationStatus::Revoked {
        return Ok(true);
    }
    key_revoked(link.minted_with, link.key_status)
}

/// Whether the key a minted delegation was minted with is revoked or gone.
/// A delegation minted with no key stands on its own status.
fn key_revoked(minted_with: Option<Uuid>, key_status: Option<String>) -> Result<bool, DomainError> {
    match (minted_with, key_status) {
        (None, _) => Ok(false),
        (Some(_), None) => Ok(true),
        (Some(_), Some(status)) => {
            Ok(CREDENTIAL.choice::<KeyStatus>(&status)? == KeyStatus::Revoked)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn link(status: Option<&str>) -> ChainLink {
        ChainLink {
            status: status.map(str::to_owned),
            minted_with: None,
            key_status: None,
        }
    }

    fn minted(key_status: Option<&str>) -> ChainLink {
        ChainLink {
            status: Some("active".to_owned()),
            minted_with: Some(Uuid::new_v4()),
            key_status: key_status.map(str::to_owned),
        }
    }

    fn kept(words: &[Option<&str>]) -> Vec<ChainLink> {
        words.iter().copied().map(link).collect()
    }

    /// An active delegation is not revoked; a revoked one, and one that is
    /// gone, are.
    #[test]
    fn only_an_active_delegation_reads_as_not_revoked() {
        assert!(!into_revoked(kept(&[Some("active")])).unwrap());
        assert!(into_revoked(kept(&[Some("revoked")])).unwrap());
        assert!(into_revoked(kept(&[None])).unwrap());
    }

    /// An empty chain or a chain with a missing or revoked link reads as
    /// revoked; a chain containing only active links does not.
    #[test]
    fn a_revoked_or_missing_link_above_revokes_the_chain() {
        assert!(into_revoked(kept(&[Some("active"), Some("revoked")])).unwrap());
        assert!(into_revoked(kept(&[Some("active"), None])).unwrap());
        assert!(into_revoked(Vec::new()).unwrap());
        assert!(!into_revoked(kept(&[Some("active"), Some("active")])).unwrap());
    }

    /// A minted delegation reads as revoked when its key is missing or
    /// revoked, while active and rotated keys leave it unrevoked.
    #[test]
    fn a_token_minted_with_a_revoked_or_missing_key_reads_as_revoked() {
        assert!(into_revoked(vec![minted(Some("revoked"))]).unwrap());
        assert!(into_revoked(vec![minted(None)]).unwrap());
        assert!(!into_revoked(vec![minted(Some("active"))]).unwrap());
        assert!(!into_revoked(vec![minted(Some("rotated"))]).unwrap());
    }

    /// Unknown delegation and credential statuses return corruption errors.
    #[test]
    fn an_unknown_status_is_refused() {
        assert!(matches!(
            into_revoked(kept(&[Some("paused")])),
            Err(DomainError::Infrastructure(_))
        ));
        assert!(matches!(
            into_revoked(vec![minted(Some("paused"))]),
            Err(DomainError::Infrastructure(_))
        ));
    }
}
