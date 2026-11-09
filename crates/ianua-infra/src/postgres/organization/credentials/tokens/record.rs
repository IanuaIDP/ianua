//! A mailed link as its row holds it: read back into the token, and
//! written out from it.

use ianua_domain::domains::identity::tokens::purpose::TokenPurpose;
use ianua_domain::domains::organization::access::token::{OrgToken, OrgTokenRow};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{Email, OrgUserId, TokenHash, Usage};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::foundation::stored::Stored;

const TOKEN: Stored = Stored("organization token");

/// A mailed link as it is read. The store's checked queries fill it.
pub(super) struct TokenRecord {
    pub(super) token_hash: String,
    pub(super) org_user_id: Uuid,
    pub(super) sent_to: String,
    pub(super) created_at: OffsetDateTime,
    pub(super) expires_at: OffsetDateTime,
    pub(super) consumed_at: Option<OffsetDateTime>,
}

impl TokenRecord {
    /// The token the record holds, rebuilt through the domain's checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the address no longer
    /// passes its rules, or the row breaks a rule the token keeps.
    pub(super) fn into_token<Purpose: TokenPurpose>(
        self,
    ) -> Result<OrgToken<Purpose>, DomainError> {
        OrgToken::reconstitute(OrgTokenRow {
            token_hash: TokenHash::from_stored(self.token_hash),
            org_user_id: OrgUserId::from_uuid(self.org_user_id),
            sent_to: TOKEN.value("address", Email::new(self.sent_to))?,
            created_at: self.created_at,
            expires_at: self.expires_at,
            usage: Usage::from_stored(self.consumed_at),
        })
    }
}

/// A mailed link's columns, as they are written.
pub(super) struct TokenColumns<'a> {
    pub(super) token_hash: &'a str,
    pub(super) org_user_id: &'a Uuid,
    pub(super) sent_to: &'a str,
    pub(super) created_at: OffsetDateTime,
    pub(super) expires_at: OffsetDateTime,
    pub(super) consumed_at: Option<OffsetDateTime>,
}

impl<'a> TokenColumns<'a> {
    /// The columns `token` is written to.
    pub(super) fn of<Purpose: TokenPurpose>(token: &'a OrgToken<Purpose>) -> Self {
        Self {
            token_hash: token.token_hash().as_str(),
            org_user_id: token.org_user_id().as_uuid(),
            sent_to: token.sent_to().as_str(),
            created_at: token.created_at(),
            expires_at: token.expires_at(),
            consumed_at: token.consumed_at(),
        }
    }
}
