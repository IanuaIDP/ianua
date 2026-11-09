//! An ACME challenge as its row holds it, read back through the
//! challenge's own checks.

use ianua_domain::domains::tenant::custom_domains::acme_challenge::{
    AcmeChallenge, AcmeChallengeRow, ChallengeToken, KeyAuthorization,
};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::DomainName;
use time::OffsetDateTime;

use crate::postgres::foundation::stored::Stored;

const CHALLENGE: Stored = Stored("ACME challenge");

/// A challenge as it is read. The store's checked queries fill it.
pub(super) struct ChallengeRecord {
    pub(super) token: String,
    pub(super) key_authorization: String,
    pub(super) domain: String,
    pub(super) expires_at: OffsetDateTime,
}

impl ChallengeRecord {
    /// The challenge the record holds, each value read back through its own
    /// rules.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a value no longer passes
    /// its rules.
    pub(super) fn into_challenge(self) -> Result<AcmeChallenge, DomainError> {
        AcmeChallenge::reconstitute(AcmeChallengeRow {
            token: CHALLENGE.value("token", ChallengeToken::new(self.token))?,
            key_authorization: CHALLENGE.value(
                "key authorization",
                KeyAuthorization::new(self.key_authorization),
            )?,
            domain: CHALLENGE.value("domain", DomainName::new(self.domain))?,
            expires_at: self.expires_at,
        })
    }
}
