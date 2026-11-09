//! A logout request this platform sent, as its row holds it: read back
//! into the domain's request, and written out from it.

use ianua_domain::domains::federation::saml::logout::{SentLogoutRequest, SentLogoutRequestRow};
use ianua_domain::domains::federation::saml::name_id::SamlNameIdValue;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{HttpsUrl, SamlEntityId, SamlNameIdFormat, SamlRequestId, SessionIndex};
use time::OffsetDateTime;

use crate::postgres::foundation::stored::Stored;

const REQUEST: Stored = Stored("sent logout request");

/// A sent request as it is read. The store's checked queries fill it.
pub(super) struct LogoutRecord {
    pub(super) id: String,
    pub(super) peer: String,
    pub(super) destination: String,
    pub(super) name_id_format: String,
    pub(super) name_id: String,
    pub(super) session_index: String,
    pub(super) sent_at: OffsetDateTime,
    pub(super) expires_at: OffsetDateTime,
}

impl LogoutRecord {
    /// The request the record holds, rebuilt through the domain's checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a value no longer passes
    /// its rules, or the request waits longer than a logout request does.
    pub(super) fn into_request(self) -> Result<SentLogoutRequest, DomainError> {
        SentLogoutRequest::reconstitute(SentLogoutRequestRow {
            id: REQUEST.value("id", SamlRequestId::new(self.id))?,
            peer: REQUEST.value("peer", SamlEntityId::new(self.peer))?,
            destination: REQUEST.value("destination", HttpsUrl::new(self.destination))?,
            name_id_format: REQUEST
                .value("name id format", SamlNameIdFormat::new(self.name_id_format))?,
            name_id: REQUEST.value("name id", SamlNameIdValue::new(self.name_id))?,
            session_index: REQUEST.value("session index", SessionIndex::new(self.session_index))?,
            sent_at: self.sent_at,
            expires_at: self.expires_at,
        })
    }
}

/// A sent request's columns, as they are written.
pub(super) struct LogoutColumns<'a> {
    pub(super) id: &'a str,
    pub(super) peer: &'a str,
    pub(super) destination: &'a str,
    pub(super) name_id_format: &'a str,
    pub(super) name_id: &'a str,
    pub(super) session_index: &'a str,
    pub(super) sent_at: OffsetDateTime,
    pub(super) expires_at: OffsetDateTime,
}

impl<'a> LogoutColumns<'a> {
    /// The columns `request` is written to.
    pub(super) fn of(request: &'a SentLogoutRequest) -> Self {
        Self {
            id: request.id().as_str(),
            peer: request.peer().as_str(),
            destination: request.destination().as_str(),
            name_id_format: request.name_id_format().as_str(),
            name_id: request.name_id().as_str(),
            session_index: request.session_index().as_str(),
            sent_at: request.sent_at(),
            expires_at: request.expires_at(),
        }
    }
}
