//! The words a sighting's choices are stored as. Where it was seen is
//! stored with the domain's own names for it.

use ianua_domain::domains::agents::identity::sighting::SightingState;

use crate::postgres::foundation::stored::stored_words;

/// Whether a person has dealt with a sighting, as its column holds it; the
/// agent it became and when it was decided are kept beside it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SightingStateKind {
    /// Nobody has looked at it yet.
    Unreviewed,
    /// Registered as an agent.
    Registered,
    /// Judged no agent at all.
    Dismissed,
}

stored_words! {
    SightingStateKind as "sighting state" {
        Unreviewed => "unreviewed",
        Registered => "registered",
        Dismissed => "dismissed",
    }
}

impl From<SightingState> for SightingStateKind {
    fn from(state: SightingState) -> Self {
        match state {
            SightingState::Unreviewed => Self::Unreviewed,
            SightingState::Registered { .. } => Self::Registered,
            SightingState::Dismissed { .. } => Self::Dismissed,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::postgres::foundation::stored::StoredWord;

    /// Every state reads back from its word.
    #[test]
    fn every_state_reads_back_from_its_word() {
        for kind in [
            SightingStateKind::Unreviewed,
            SightingStateKind::Registered,
            SightingStateKind::Dismissed,
        ] {
            assert_eq!(SightingStateKind::from_word(kind.word()), Some(kind));
        }
    }
}
