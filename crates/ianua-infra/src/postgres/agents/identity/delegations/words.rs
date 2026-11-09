//! The words a delegation's choices are stored as: whether it still
//! grants anything, and where it sits in its chain.

use ianua_domain::domains::agents::authority::delegation::{DelegationStatus, Lineage};

use crate::postgres::foundation::stored::stored_words;

stored_words! {
    DelegationStatus as "delegation status" {
        Active => "active",
        Revoked => "revoked",
    }
}

/// Where a delegation sits in its chain, as its column holds it; the
/// parent or the sources are kept beside it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum LineageKind {
    /// At the top of its chain.
    Root,
    /// Under a parent.
    Under,
    /// Minted for a task token from other delegations.
    Minted,
}

stored_words! {
    LineageKind as "delegation lineage" {
        Root => "root",
        Under => "under",
        Minted => "minted",
    }
}

impl From<&Lineage> for LineageKind {
    fn from(lineage: &Lineage) -> Self {
        match lineage {
            Lineage::Root => Self::Root,
            Lineage::Under(_) => Self::Under,
            Lineage::Minted { .. } => Self::Minted,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::postgres::foundation::stored::StoredWord;

    /// Every status reads back from its word, so a revoked delegation is
    /// never read as one that grants.
    #[test]
    fn every_status_reads_back_from_its_word() {
        for status in [DelegationStatus::Active, DelegationStatus::Revoked] {
            assert_eq!(DelegationStatus::from_word(status.word()), Some(status));
        }
    }

    /// Every lineage reads back from its word.
    #[test]
    fn every_lineage_reads_back_from_its_word() {
        for kind in [LineageKind::Root, LineageKind::Under, LineageKind::Minted] {
            assert_eq!(LineageKind::from_word(kind.word()), Some(kind));
        }
    }
}
