//! A sent second-factor code as its row holds it: read back into the code,
//! and written out from it.
//!
//! The words of a factor's kind are the ones enrollments are stored with.

use ianua_domain::domains::authentication::mfa::one_time_code::{OneTimeCode, OneTimeCodeRow};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{PrincipalId, TokenHash, Usage, UserId};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::foundation::stored::{Stored, StoredWord as _};

const SENT_CODE: Stored = Stored("sent second-factor code");

/// A sent code as it is read. The store's checked queries fill it.
pub(super) struct SentCodeRecord {
    pub(super) user_id: Uuid,
    pub(super) enrolled_at: OffsetDateTime,
    pub(super) method: String,
    pub(super) code_hash: String,
    pub(super) issued_at: OffsetDateTime,
    pub(super) expires_at: OffsetDateTime,
    pub(super) wrong_tries: i16,
    pub(super) spent_at: Option<OffsetDateTime>,
}

impl SentCodeRecord {
    /// The code the record holds, rebuilt through the domain's checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the kind is unknown, the
    /// tries do not fit, or the row breaks a rule the code keeps.
    pub(super) fn into_code(self) -> Result<OneTimeCode<ResolvedTenant>, DomainError> {
        OneTimeCode::reconstitute(OneTimeCodeRow {
            subject_id: PrincipalId::from(UserId::from_uuid(self.user_id)),
            enrolled_at: self.enrolled_at,
            method: SENT_CODE.choice(&self.method)?,
            code_hash: TokenHash::from_stored(self.code_hash),
            issued_at: self.issued_at,
            expires_at: self.expires_at,
            wrong_tries: u8::try_from(self.wrong_tries).map_err(DomainError::infra)?,
            usage: Usage::from_stored(self.spent_at),
        })
    }
}

/// A sent code's columns, as they are written.
pub(super) struct SentCodeColumns<'a> {
    pub(super) user_id: Uuid,
    pub(super) enrolled_at: OffsetDateTime,
    pub(super) method: &'static str,
    pub(super) code_hash: &'a str,
    pub(super) issued_at: OffsetDateTime,
    pub(super) expires_at: OffsetDateTime,
    pub(super) wrong_tries: i16,
    pub(super) spent_at: Option<OffsetDateTime>,
}

impl<'a> SentCodeColumns<'a> {
    /// The columns `code` is written to, as its holder's.
    pub(super) fn of(code: &'a OneTimeCode<ResolvedTenant>) -> Self {
        Self {
            user_id: *code.subject_id().as_uuid(),
            enrolled_at: code.enrolled_at(),
            method: code.method().word(),
            code_hash: code.code_hash().as_str(),
            issued_at: code.issued_at(),
            expires_at: code.expires_at(),
            wrong_tries: i16::from(code.wrong_tries()),
            spent_at: code.spent_at(),
        }
    }
}
