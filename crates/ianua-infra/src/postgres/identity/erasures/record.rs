//! An erasure request as its row holds it: read back into the aggregate,
//! and written out from it.

use ianua_domain::domains::identity::privacy::erasure::{
    ErasureRequest, ErasureRequestRow, ErasureState,
};
use ianua_domain::domains::identity::privacy::erasure_status::ErasureStatus;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{Email, ErasureRequestId, Text, TokenHash, UserId};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::foundation::stored::{Stored, StoredWord as _};

const ERASURE: Stored = Stored("erasure request");

/// An erasure request as it is read. The store's checked queries fill it.
pub(super) struct ErasureRecord {
    pub(super) id: Uuid,
    pub(super) user_id: Uuid,
    pub(super) reason: Option<String>,
    pub(super) status: String,
    pub(super) completed_at: Option<OffsetDateTime>,
    pub(super) requested_at: OffsetDateTime,
    pub(super) scheduled_at: OffsetDateTime,
    pub(super) cancel_token_hash: String,
    pub(super) sent_to: String,
}

impl ErasureRecord {
    /// The request the record holds, rebuilt through the domain's checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a value no longer passes
    /// its rules, a word is unknown, or the row breaks a rule the request
    /// keeps.
    pub(super) fn into_request(self) -> Result<ErasureRequest<ResolvedTenant>, DomainError> {
        let status: ErasureStatus = ERASURE.choice(&self.status)?;
        ErasureRequest::reconstitute(ErasureRequestRow {
            id: ErasureRequestId::from_uuid(self.id),
            user_id: UserId::from_uuid(self.user_id),
            reason: self
                .reason
                .map(|reason| ERASURE.value("reason", Text::new("reason", reason)))
                .transpose()?,
            state: ErasureState::from_stored(status, self.completed_at)?,
            requested_at: self.requested_at,
            scheduled_at: self.scheduled_at,
            cancel_token_hash: TokenHash::from_stored(self.cancel_token_hash),
            sent_to: ERASURE.value("sent to", Email::new(self.sent_to))?,
        })
    }
}

/// An erasure request's columns, as they are written.
pub(super) struct ErasureColumns<'a> {
    pub(super) id: &'a Uuid,
    pub(super) user_id: &'a Uuid,
    pub(super) reason: Option<&'a str>,
    pub(super) status: &'static str,
    pub(super) completed_at: Option<OffsetDateTime>,
    pub(super) requested_at: OffsetDateTime,
    pub(super) scheduled_at: OffsetDateTime,
    pub(super) cancel_token_hash: &'a str,
    pub(super) sent_to: &'a str,
}

impl<'a> ErasureColumns<'a> {
    /// The columns `request` is written to.
    pub(super) fn of(request: &'a ErasureRequest<ResolvedTenant>) -> Self {
        Self {
            id: request.id().as_uuid(),
            user_id: request.user_id().as_uuid(),
            reason: request.reason().map(Text::as_str),
            status: request.status().word(),
            completed_at: request.completed_at(),
            requested_at: request.requested_at(),
            scheduled_at: request.scheduled_at(),
            cancel_token_hash: request.cancel_token_hash().as_str(),
            sent_to: request.sent_to().as_str(),
        }
    }
}
