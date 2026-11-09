//! An attestation challenge as its row holds it: read back into the
//! domain's challenge, and written out from it.

use ianua_domain::domains::agents::identity::challenge::{
    AttestationChallenge, AttestationChallengeRow, AttestationNonce,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{AgentId, Usage};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::foundation::stored::Stored;

const CHALLENGE: Stored = Stored("attestation challenge");

/// A challenge as it is read. The store's checked queries fill it.
pub(super) struct ChallengeRecord {
    pub(super) nonce: String,
    pub(super) agent_id: Uuid,
    pub(super) issued_at: OffsetDateTime,
    pub(super) expires_at: OffsetDateTime,
    pub(super) used_at: Option<OffsetDateTime>,
}

impl ChallengeRecord {
    /// The challenge the record holds, rebuilt through the domain's checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the nonce no longer passes
    /// its rules, or the row breaks a rule the challenge keeps.
    pub(super) fn into_challenge(
        self,
    ) -> Result<AttestationChallenge<ResolvedTenant>, DomainError> {
        AttestationChallenge::reconstitute(AttestationChallengeRow {
            nonce: CHALLENGE.value("nonce", AttestationNonce::new(self.nonce))?,
            agent_id: AgentId::from_uuid(self.agent_id),
            issued_at: self.issued_at,
            expires_at: self.expires_at,
            usage: Usage::from_stored(self.used_at),
        })
    }
}

/// A challenge's columns, as they are written.
pub(super) struct ChallengeColumns<'a> {
    pub(super) nonce: &'a str,
    pub(super) agent_id: &'a Uuid,
    pub(super) issued_at: OffsetDateTime,
    pub(super) expires_at: OffsetDateTime,
    pub(super) used_at: Option<OffsetDateTime>,
}

impl<'a> ChallengeColumns<'a> {
    /// The columns `challenge` is written to.
    pub(super) fn of(challenge: &'a AttestationChallenge<ResolvedTenant>) -> Self {
        Self {
            nonce: challenge.nonce().as_str(),
            agent_id: challenge.agent_id().as_uuid(),
            issued_at: challenge.issued_at(),
            expires_at: challenge.expires_at(),
            used_at: challenge.usage().used_at(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::rows::at;

    /// Rebuilding a stored challenge with a short nonce returns a corruption
    /// error.
    #[test]
    fn a_row_with_a_nonce_too_short_to_trust_is_refused() {
        let record = ChallengeRecord {
            nonce: "short".to_owned(),
            agent_id: Uuid::nil(),
            issued_at: at(0),
            expires_at: at(60),
            used_at: Some(at(10)),
        };

        let read = record.into_challenge();

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
