//! An organization API key as its row holds it: read back into the
//! aggregate, and written out from it.

use ianua_domain::domains::organization::access::api_key::{
    MintedThrough, OrgApiKey, OrgApiKeyRow,
};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{
    Expiry, KeyPrefix, Label, OrgApiKeyId, OrgUserId, OrganizationId, Scope, TokenHash,
};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::foundation::stored::{Stored, StoredWord as _};

const API_KEY: Stored = Stored("organization API key");

/// A key as it is read. The store's checked queries fill it.
pub(super) struct ApiKeyRecord {
    pub(super) id: Uuid,
    pub(super) organization_id: Uuid,
    pub(super) name: String,
    pub(super) key_prefix: String,
    pub(super) key_hash: String,
    pub(super) scopes: Vec<String>,
    pub(super) created_by: Uuid,
    pub(super) parent_key_id: Option<Uuid>,
    pub(super) expires_at: Option<OffsetDateTime>,
    pub(super) last_used_at: Option<OffsetDateTime>,
    pub(super) status: String,
    pub(super) created_at: OffsetDateTime,
}

impl ApiKeyRecord {
    /// The key the record holds, rebuilt through the domain's checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a value no longer passes
    /// its rules, the status is unknown, or the row breaks a rule the key
    /// keeps.
    pub(super) fn into_api_key(self) -> Result<OrgApiKey, DomainError> {
        let scopes = self
            .scopes
            .into_iter()
            .map(|scope| API_KEY.value("scope", Scope::new(scope)))
            .collect::<Result<Vec<_>, _>>()?;
        OrgApiKey::reconstitute(OrgApiKeyRow {
            id: OrgApiKeyId::from_uuid(self.id),
            organization_id: OrganizationId::from_uuid(self.organization_id),
            name: API_KEY.value("name", Label::new("api_key_name", self.name))?,
            key_prefix: API_KEY.value("key prefix", KeyPrefix::new(self.key_prefix))?,
            key_hash: TokenHash::from_stored(self.key_hash),
            scopes,
            created_by: OrgUserId::from_uuid(self.created_by),
            minted_through: self.parent_key_id.map_or(MintedThrough::Session, |parent| {
                MintedThrough::Key(OrgApiKeyId::from_uuid(parent))
            }),
            expires_at: self.expires_at.map_or(Expiry::Never, Expiry::At),
            last_used_at: self.last_used_at,
            status: API_KEY.choice(&self.status)?,
            created_at: self.created_at,
        })
    }
}

/// A key's columns, as they are written.
pub(super) struct ApiKeyColumns<'a> {
    pub(super) id: &'a Uuid,
    pub(super) organization_id: &'a Uuid,
    pub(super) name: &'a str,
    pub(super) key_prefix: &'a str,
    pub(super) key_hash: &'a str,
    pub(super) scopes: Vec<String>,
    pub(super) created_by: &'a Uuid,
    pub(super) parent_key_id: Option<Uuid>,
    pub(super) expires_at: Option<OffsetDateTime>,
    pub(super) last_used_at: Option<OffsetDateTime>,
    pub(super) status: &'static str,
    pub(super) created_at: OffsetDateTime,
}

impl<'a> ApiKeyColumns<'a> {
    /// The columns `key` is written to.
    pub(super) fn of(key: &'a OrgApiKey) -> Self {
        Self {
            id: key.id().as_uuid(),
            organization_id: key.organization_id().as_uuid(),
            name: key.name().as_str(),
            key_prefix: key.key_prefix().as_str(),
            key_hash: key.key_hash().as_str(),
            scopes: key
                .scopes()
                .iter()
                .map(|scope| scope.as_str().to_owned())
                .collect(),
            created_by: key.created_by().as_uuid(),
            parent_key_id: parent_of(key.minted_through()),
            expires_at: key.expires_at().instant(),
            last_used_at: key.last_used_at(),
            status: key.status().word(),
            created_at: key.created_at(),
        }
    }
}

/// The key a key was minted through, as its column holds it: none for one
/// minted through its creator's session.
fn parent_of(minted_through: MintedThrough) -> Option<Uuid> {
    match minted_through {
        MintedThrough::Session => None,
        MintedThrough::Key(parent) => Some(*parent.as_uuid()),
    }
}
