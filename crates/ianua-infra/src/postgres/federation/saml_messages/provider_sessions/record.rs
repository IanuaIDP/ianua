//! The provider session behind a session here, as its row holds it: the
//! port's own value, each part rebuilt through its own constructor.

use ianua_app::ports::federation::ProviderSession;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{ConnectionId, FederatedSubject, SessionId, SessionIndex};
use uuid::Uuid;

use crate::postgres::foundation::stored::Stored;

const SESSION: Stored = Stored("provider session");

/// A provider session as it is read. The store's checked queries fill it.
pub(super) struct SessionRecord {
    pub(super) session_id: Uuid,
    pub(super) connection_id: Uuid,
    pub(super) subject: String,
    pub(super) session_index: String,
}

impl SessionRecord {
    /// The provider session the record holds.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the subject or the
    /// session index no longer passes its rules.
    pub(super) fn into_session(self) -> Result<ProviderSession, DomainError> {
        Ok(ProviderSession {
            session_id: SessionId::from_uuid(self.session_id),
            connection_id: ConnectionId::from_uuid(self.connection_id),
            subject: SESSION.value("subject", FederatedSubject::new(self.subject))?,
            session_index: SESSION.value("session index", SessionIndex::new(self.session_index))?,
        })
    }
}
