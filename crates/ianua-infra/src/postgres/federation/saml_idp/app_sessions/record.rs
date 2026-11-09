//! A SAML app a session signed in to, as its row holds it: the port's own
//! value, each part rebuilt through its own constructor.

use ianua_app::ports::federation::SamlAppSession;
use ianua_domain::domains::federation::saml::name_id::SamlNameIdValue;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{SamlServiceProviderId, SessionId, SessionIndex};
use uuid::Uuid;

use crate::postgres::foundation::stored::Stored;

const APP_SESSION: Stored = Stored("SAML app session");

/// An app session as it is read. The store's checked queries fill it.
pub(super) struct AppSessionRecord {
    pub(super) session_id: Uuid,
    pub(super) provider_id: Uuid,
    pub(super) name_id: String,
    pub(super) session_index: String,
}

impl AppSessionRecord {
    /// The app session the record holds.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the name or the session
    /// index no longer passes its rules.
    pub(super) fn into_app_session(self) -> Result<SamlAppSession, DomainError> {
        Ok(SamlAppSession {
            session_id: SessionId::from_uuid(self.session_id),
            provider_id: SamlServiceProviderId::from_uuid(self.provider_id),
            name_id: APP_SESSION.value("name id", SamlNameIdValue::new(self.name_id))?,
            session_index: APP_SESSION
                .value("session index", SessionIndex::new(self.session_index))?,
        })
    }
}
