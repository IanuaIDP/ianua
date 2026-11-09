//! A consent as its row holds it: read back into the aggregate.

use ianua_domain::domains::oauth::clients::consent::{OAuthConsent, OAuthConsentRow};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{OAuthClientId, UserId};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::foundation::stored::Stored;
use crate::postgres::oauth::scopes::scopes_from;

const CONSENT: Stored = Stored("OAuth consent");

/// A consent as it is read. The store's checked queries fill it.
pub(super) struct ConsentRecord {
    pub(super) user_id: Uuid,
    pub(super) client_id: Uuid,
    pub(super) scopes: Vec<String>,
    pub(super) granted_at: OffsetDateTime,
}

impl ConsentRecord {
    /// The consent the record holds, rebuilt through the domain's checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a scope no longer passes
    /// its rules.
    pub(super) fn into_consent(self) -> Result<OAuthConsent<ResolvedTenant>, DomainError> {
        OAuthConsent::reconstitute(OAuthConsentRow {
            user_id: UserId::from_uuid(self.user_id),
            client_id: OAuthClientId::from_uuid(self.client_id),
            scopes: scopes_from(CONSENT, self.scopes)?,
            granted_at: self.granted_at,
        })
    }
}
