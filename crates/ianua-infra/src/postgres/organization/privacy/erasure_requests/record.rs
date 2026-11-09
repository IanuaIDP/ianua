//! A member's erasure request as its row holds it: read back into the
//! aggregate, and written out from it.

use ianua_domain::domains::identity::privacy::erasure::ErasureState;
use ianua_domain::domains::organization::members::privacy::erasure::{
    OrgErasureRequest, OrgErasureRequestRow,
};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{Email, ErasureRequestId, OrgUserId, OrganizationId, Text, TokenHash};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::foundation::stored::{Stored, StoredWord as _};

const ERASURE: Stored = Stored("organization erasure request");

/// An erasure request as it is read. The store's checked queries fill it.
pub(super) struct ErasureRecord {
    pub(super) id: Uuid,
    pub(super) organization_id: Uuid,
    pub(super) org_user_id: Uuid,
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
    /// its rules, the status is unknown or contradicts the completion time,
    /// or the row breaks a rule the request keeps.
    pub(super) fn into_request(self) -> Result<OrgErasureRequest, DomainError> {
        let reason = self
            .reason
            .map(|reason| ERASURE.value("reason", Text::new("reason", reason)))
            .transpose()?;
        OrgErasureRequest::reconstitute(OrgErasureRequestRow {
            id: ErasureRequestId::from_uuid(self.id),
            organization_id: OrganizationId::from_uuid(self.organization_id),
            org_user_id: OrgUserId::from_uuid(self.org_user_id),
            reason,
            state: ErasureState::from_stored(ERASURE.choice(&self.status)?, self.completed_at)?,
            requested_at: self.requested_at,
            scheduled_at: self.scheduled_at,
            cancel_token_hash: TokenHash::from_stored(self.cancel_token_hash),
            sent_to: ERASURE.value("address", Email::new(self.sent_to))?,
        })
    }
}

/// An erasure request's columns, as they are written.
pub(super) struct ErasureColumns<'a> {
    pub(super) id: &'a Uuid,
    pub(super) organization_id: &'a Uuid,
    pub(super) org_user_id: &'a Uuid,
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
    pub(super) fn of(request: &'a OrgErasureRequest) -> Self {
        Self {
            id: request.id().as_uuid(),
            organization_id: request.organization_id().as_uuid(),
            org_user_id: request.org_user_id().as_uuid(),
            reason: request.reason().map(Text::as_str),
            status: request.status().word(),
            completed_at: request.state().completed_at(),
            requested_at: request.requested_at(),
            scheduled_at: request.scheduled_at(),
            cancel_token_hash: request.cancel_token_hash().as_str(),
            sent_to: request.sent_to().as_str(),
        }
    }
}
