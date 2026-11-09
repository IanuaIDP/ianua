//! The words a pending connection's stage is stored as.
//!
//! An answered connection carries the service's credential and the digest
//! of the platform's one-time code, which have columns of their own, so its
//! cases are stored apart, as a [`StageKind`].

use ianua_domain::domains::workflows::account::connection::ConnectionStage;

use crate::postgres::foundation::stored::stored_words;

/// Which case of [`ConnectionStage`] a connection is in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum StageKind {
    /// Waiting for the service to send the browser back.
    AwaitingService,
    /// The service answered; waiting for the person to finish.
    Answered,
    /// Finished or refused.
    Spent,
}

impl StageKind {
    /// The case `stage` is.
    pub(super) fn of(stage: &ConnectionStage) -> Self {
        match stage {
            ConnectionStage::AwaitingService => Self::AwaitingService,
            ConnectionStage::Answered { .. } => Self::Answered,
            ConnectionStage::Spent => Self::Spent,
        }
    }
}

stored_words! {
    StageKind as "connection stage" {
        AwaitingService => "awaiting_service",
        Answered => "answered",
        Spent => "spent",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::postgres::foundation::stored::StoredWord;

    /// Every stage reads back from the word it is written as.
    #[test]
    fn every_stage_reads_back_from_its_word() {
        for kind in [
            StageKind::AwaitingService,
            StageKind::Answered,
            StageKind::Spent,
        ] {
            assert_eq!(StageKind::from_word(kind.word()), Some(kind));
        }
    }
}
