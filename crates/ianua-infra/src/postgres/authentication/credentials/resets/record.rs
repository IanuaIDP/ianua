//! A password reset as its row holds it: read back into the request, and
//! written out from it.

use ianua_domain::domains::authentication::recovery::reset::{
    PasswordResetRequest, PasswordResetRow, ResetState,
};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{Email, PasswordResetId, TokenHash, UserId};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::foundation::stored::{Stored, StoredWord as _};

const RESET: Stored = Stored("password reset");

/// A reset request as it is read. The store's checked queries fill it.
pub(super) struct ResetRecord {
    pub(super) id: Uuid,
    pub(super) user_id: Uuid,
    pub(super) email: String,
    pub(super) initiator: String,
    pub(super) status: String,
    pub(super) completed_at: Option<OffsetDateTime>,
    pub(super) token_hash: String,
    pub(super) created_at: OffsetDateTime,
    pub(super) expires_at: OffsetDateTime,
}

impl ResetRecord {
    /// The request the record holds, rebuilt through the domain's checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a word is unknown, the
    /// address no longer passes its rules, or the row breaks a rule the
    /// request keeps.
    pub(super) fn into_request(self) -> Result<PasswordResetRequest, DomainError> {
        PasswordResetRequest::reconstitute(PasswordResetRow {
            id: PasswordResetId::from_uuid(self.id),
            user_id: UserId::from_uuid(self.user_id),
            email: RESET.value("email", Email::new(self.email))?,
            initiator: RESET.choice(&self.initiator)?,
            state: ResetState::from_stored(RESET.choice(&self.status)?, self.completed_at)?,
            token_hash: TokenHash::from_stored(self.token_hash),
            created_at: self.created_at,
            expires_at: self.expires_at,
        })
    }
}

/// A reset request's columns, as they are written.
pub(super) struct ResetColumns<'a> {
    pub(super) id: &'a Uuid,
    pub(super) user_id: &'a Uuid,
    pub(super) email: &'a str,
    pub(super) initiator: &'static str,
    pub(super) status: &'static str,
    pub(super) completed_at: Option<OffsetDateTime>,
    pub(super) token_hash: &'a str,
    pub(super) created_at: OffsetDateTime,
    pub(super) expires_at: OffsetDateTime,
}

impl<'a> ResetColumns<'a> {
    /// The columns `request` is written to.
    pub(super) fn of(request: &'a PasswordResetRequest) -> Self {
        let state = request.reset_state();
        Self {
            id: request.id().as_uuid(),
            user_id: request.user_id().as_uuid(),
            email: request.email().as_str(),
            initiator: request.initiator().word(),
            status: state.status().word(),
            completed_at: state.completed_at(),
            token_hash: request.token_hash().as_str(),
            created_at: request.created_at(),
            expires_at: request.expires_at(),
        }
    }
}
