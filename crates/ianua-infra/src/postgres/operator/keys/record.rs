//! An operator API key as its row holds it: read back into the aggregate,
//! and written out from it.

use ianua_domain::domains::operator::api_key::{OperatorApiKey, OperatorApiKeyRow};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{Expiry, KeyPrefix, OperatorId, Revocation, TokenHash};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::foundation::stored::Stored;

const OPERATOR_KEY: Stored = Stored("operator API key");

/// A key as it is read. The store's checked queries fill it.
pub(super) struct KeyRecord {
    pub(super) key_prefix: String,
    pub(super) operator_id: Uuid,
    pub(super) key_hash: String,
    pub(super) expires_at: Option<OffsetDateTime>,
    pub(super) revoked_at: Option<OffsetDateTime>,
    pub(super) created_at: OffsetDateTime,
}

impl KeyRecord {
    /// The key the record holds, rebuilt through the domain's checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the prefix no longer
    /// passes its rules or the row breaks a rule the key keeps.
    pub(super) fn into_key(self) -> Result<OperatorApiKey, DomainError> {
        OperatorApiKey::reconstitute(OperatorApiKeyRow {
            operator_id: OperatorId::from_uuid(self.operator_id),
            key_prefix: OPERATOR_KEY.value("key prefix", KeyPrefix::new(self.key_prefix))?,
            key_hash: TokenHash::from_stored(self.key_hash),
            expires_at: self.expires_at.map_or(Expiry::Never, Expiry::At),
            revocation: Revocation::from_stored(self.revoked_at),
            created_at: self.created_at,
        })
    }
}

/// A key's columns, as they are written.
pub(super) struct KeyColumns<'a> {
    pub(super) key_prefix: &'a str,
    pub(super) operator_id: &'a Uuid,
    pub(super) key_hash: &'a str,
    pub(super) expires_at: Option<OffsetDateTime>,
    pub(super) revoked_at: Option<OffsetDateTime>,
    pub(super) created_at: OffsetDateTime,
}

impl<'a> KeyColumns<'a> {
    /// The columns `key` is written to.
    pub(super) fn of(key: &'a OperatorApiKey) -> Self {
        Self {
            key_prefix: key.key_prefix().as_str(),
            operator_id: key.operator_id().as_uuid(),
            key_hash: key.key_hash().as_str(),
            expires_at: key.expires_at().instant(),
            revoked_at: key.revocation().revoked_at(),
            created_at: key.created_at(),
        }
    }
}
