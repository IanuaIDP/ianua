//! The words a delegation request's choices are stored as.

use ianua_domain::domains::agents::authority::delegation_request::RequestState;

use crate::postgres::foundation::stored::stored_words;

/// Where a request stands, as its column holds it; the delegation it
/// became and when it was answered are kept beside it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RequestStateKind {
    /// Waiting for the person asked.
    Pending,
    /// Granted as a delegation.
    Approved,
    /// Refused.
    Denied,
}

stored_words! {
    RequestStateKind as "delegation request state" {
        Pending => "pending",
        Approved => "approved",
        Denied => "denied",
    }
}

impl From<RequestState> for RequestStateKind {
    fn from(state: RequestState) -> Self {
        match state {
            RequestState::Pending => Self::Pending,
            RequestState::Approved { .. } => Self::Approved,
            RequestState::Denied { .. } => Self::Denied,
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
            RequestStateKind::Pending,
            RequestStateKind::Approved,
            RequestStateKind::Denied,
        ] {
            assert_eq!(RequestStateKind::from_word(kind.word()), Some(kind));
        }
    }
}
