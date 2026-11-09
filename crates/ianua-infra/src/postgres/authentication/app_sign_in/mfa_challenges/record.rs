//! A second-factor challenge as its row holds it: read back into the
//! challenge, and written out from it.

use ianua_domain::domains::authentication::sessions::mfa_challenge::{
    MfaChallenge, MfaChallengeRow,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{SessionId, TokenHash, Usage};
use time::OffsetDateTime;
use uuid::Uuid;

/// A challenge as it is read. The store's checked queries fill it.
pub(super) struct ChallengeRecord {
    pub(super) token_hash: String,
    pub(super) session_id: Uuid,
    pub(super) expires_at: OffsetDateTime,
    pub(super) failed_attempts: i16,
    pub(super) consumed_at: Option<OffsetDateTime>,
}

impl ChallengeRecord {
    /// The challenge the record holds, rebuilt through the domain's checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the count does not fit, or
    /// the row breaks a rule the challenge keeps.
    pub(super) fn into_challenge(self) -> Result<MfaChallenge<ResolvedTenant>, DomainError> {
        MfaChallenge::reconstitute(MfaChallengeRow {
            token_hash: TokenHash::from_stored(self.token_hash),
            session_id: SessionId::from_uuid(self.session_id),
            expires_at: self.expires_at,
            failed_attempts: u8::try_from(self.failed_attempts).map_err(DomainError::infra)?,
            usage: Usage::from_stored(self.consumed_at),
        })
    }
}

/// A challenge's columns, as they are written.
pub(super) struct ChallengeColumns<'a> {
    pub(super) token_hash: &'a str,
    pub(super) session_id: &'a Uuid,
    pub(super) expires_at: OffsetDateTime,
    pub(super) failed_attempts: i16,
    pub(super) consumed_at: Option<OffsetDateTime>,
}

impl<'a> ChallengeColumns<'a> {
    /// The columns `challenge` is written to.
    pub(super) fn of(challenge: &'a MfaChallenge<ResolvedTenant>) -> Self {
        Self {
            token_hash: challenge.token_hash().as_str(),
            session_id: challenge.session_id().as_uuid(),
            expires_at: challenge.expires_at(),
            failed_attempts: i16::from(challenge.failed_attempts()),
            consumed_at: challenge.consumed_at(),
        }
    }
}
