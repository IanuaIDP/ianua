//! A pass carrying a session to another host as its row holds it: read
//! back into the handoff, and written out from it.

use ianua_domain::domains::authentication::sessions::handoff::{SessionHandoff, SessionHandoffRow};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{DomainName, ServiceId, SessionId, TokenHash, Usage};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::foundation::stored::Stored;

const HANDOFF: Stored = Stored("session handoff");

/// A handoff as it is read. The store's checked queries fill it.
pub(super) struct HandoffRecord {
    pub(super) token_hash: String,
    pub(super) browser_hash: String,
    pub(super) session_id: Uuid,
    pub(super) service_id: Uuid,
    pub(super) host: String,
    pub(super) expires_at: OffsetDateTime,
    pub(super) consumed_at: Option<OffsetDateTime>,
}

impl HandoffRecord {
    /// The handoff the record holds, rebuilt through the domain's checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the host is not a name, or
    /// the row breaks a rule the handoff keeps.
    pub(super) fn into_handoff(self) -> Result<SessionHandoff<ResolvedTenant>, DomainError> {
        SessionHandoff::reconstitute(SessionHandoffRow {
            token_hash: TokenHash::from_stored(self.token_hash),
            browser_hash: TokenHash::from_stored(self.browser_hash),
            session_id: SessionId::from_uuid(self.session_id),
            service_id: ServiceId::from_uuid(self.service_id),
            host: HANDOFF.value("host", DomainName::new(self.host))?,
            expires_at: self.expires_at,
            usage: Usage::from_stored(self.consumed_at),
        })
    }
}

/// A handoff's columns, as they are written.
pub(super) struct HandoffColumns<'a> {
    pub(super) token_hash: &'a str,
    pub(super) browser_hash: &'a str,
    pub(super) session_id: &'a Uuid,
    pub(super) service_id: &'a Uuid,
    pub(super) host: &'a str,
    pub(super) expires_at: OffsetDateTime,
    pub(super) consumed_at: Option<OffsetDateTime>,
}

impl<'a> HandoffColumns<'a> {
    /// The columns `handoff` is written to.
    pub(super) fn of(handoff: &'a SessionHandoff<ResolvedTenant>) -> Self {
        Self {
            token_hash: handoff.token_hash().as_str(),
            browser_hash: handoff.browser_hash().as_str(),
            session_id: handoff.session_id().as_uuid(),
            service_id: handoff.service_id().as_uuid(),
            host: handoff.host().as_str(),
            expires_at: handoff.expires_at(),
            consumed_at: handoff.consumed_at(),
        }
    }
}
