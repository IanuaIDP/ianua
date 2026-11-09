//! The words a cloud connection's standing is stored as.
//!
//! The domain's [`ConnectionState`] carries the credential and what the
//! cloud answered, which have columns of their own, so its case is stored
//! apart, as a [`Standing`]. The cloud itself is stored with the words the
//! tenant store keeps for it.

use ianua_domain::domains::organization::cloud::account::ConnectionState;

use crate::postgres::foundation::stored::stored_words;

/// Which case of [`ConnectionState`] a connection stands in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Standing {
    /// It waits for a credential.
    AwaitingCredential,
    /// It holds a credential not yet proved.
    AwaitingVerification,
    /// Its credential opened the account it names.
    Verified,
    /// The cloud refused its credential.
    Failed,
}

impl Standing {
    /// The case `state` is.
    pub(super) fn of(state: &ConnectionState) -> Self {
        match state {
            ConnectionState::AwaitingCredential => Self::AwaitingCredential,
            ConnectionState::AwaitingVerification { .. } => Self::AwaitingVerification,
            ConnectionState::Verified { .. } => Self::Verified,
            ConnectionState::Failed { .. } => Self::Failed,
        }
    }
}

stored_words! {
    Standing as "cloud connection state" {
        AwaitingCredential => "awaiting_credential",
        AwaitingVerification => "awaiting_verification",
        Verified => "verified",
        Failed => "failed",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::postgres::foundation::stored::StoredWord;

    /// Every standing reads back from the word it is written as, so a
    /// failed connection is never read as a verified one.
    #[test]
    fn every_standing_reads_back_from_its_word() {
        for standing in [
            Standing::AwaitingCredential,
            Standing::AwaitingVerification,
            Standing::Verified,
            Standing::Failed,
        ] {
            assert_eq!(Standing::from_word(standing.word()), Some(standing));
        }
    }
}
