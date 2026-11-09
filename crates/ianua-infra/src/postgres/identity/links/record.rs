//! A mailed link as its row holds it: read back into the token, and
//! written out from it.

use ianua_domain::domains::identity::tokens::purpose::TenantLinkPurpose;
use ianua_domain::domains::identity::tokens::secure::{SecureToken, SecureTokenRow};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{Email, TokenHash, Usage, UserId};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::foundation::stored::Stored;

const LINK: Stored = Stored("mailed link");

/// A link as it is read. The store's checked queries fill it.
pub(super) struct LinkRecord {
    pub(super) token_hash: String,
    pub(super) user_id: Uuid,
    pub(super) sent_to: String,
    pub(super) created_at: OffsetDateTime,
    pub(super) expires_at: OffsetDateTime,
    pub(super) used_at: Option<OffsetDateTime>,
}

impl LinkRecord {
    /// The link the record holds, rebuilt through the domain's checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the address no longer
    /// passes its rules, or the row breaks a rule the link keeps.
    pub(super) fn into_link<P: TenantLinkPurpose>(
        self,
    ) -> Result<SecureToken<ResolvedTenant, P>, DomainError> {
        SecureToken::reconstitute(SecureTokenRow {
            token_hash: TokenHash::from_stored(self.token_hash),
            user_id: UserId::from_uuid(self.user_id),
            sent_to: LINK.value("sent to", Email::new(self.sent_to))?,
            created_at: self.created_at,
            expires_at: self.expires_at,
            usage: Usage::from_stored(self.used_at),
        })
    }
}

/// A link's columns, as they are written.
pub(super) struct LinkColumns<'a> {
    pub(super) purpose: &'static str,
    pub(super) token_hash: &'a str,
    pub(super) user_id: &'a Uuid,
    pub(super) sent_to: &'a str,
    pub(super) created_at: OffsetDateTime,
    pub(super) expires_at: OffsetDateTime,
    pub(super) used_at: Option<OffsetDateTime>,
}

impl<'a> LinkColumns<'a> {
    /// The columns `link` is written to, filed under its purpose's name.
    pub(super) fn of<P: TenantLinkPurpose>(link: &'a SecureToken<ResolvedTenant, P>) -> Self {
        Self {
            purpose: P::NAME,
            token_hash: link.token_hash().as_str(),
            user_id: link.user_id().as_uuid(),
            sent_to: link.sent_to().as_str(),
            created_at: link.created_at(),
            expires_at: link.expires_at(),
            used_at: link.consumed_at(),
        }
    }
}
