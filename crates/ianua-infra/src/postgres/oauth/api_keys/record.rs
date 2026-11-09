//! A tenant API key as its row holds it: read back into the aggregate, and
//! written out from it.

use ianua_domain::domains::oauth::clients::api_key::{ApiKey, ApiKeyRow, KeyStanding};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{
    ActorRef, ApiKeyId, CountryCode, Expiry, IpAddress, KeyPrefix, Label, TenantId, TokenHash,
};
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::foundation::envelope::Kept;
use crate::postgres::foundation::stored::Stored;
use crate::postgres::oauth::scopes::{scopes_column, scopes_from};

const API_KEY: Stored = Stored("API key");

const CREATED_BY: Kept = Kept {
    entity: API_KEY.0,
    column: "created_by",
    shape: 1,
};

/// A key as it is read. The store's checked queries fill it.
pub(super) struct ApiKeyRecord {
    pub(super) id: Uuid,
    pub(super) name: String,
    pub(super) key_prefix: String,
    pub(super) key_hash: String,
    pub(super) scopes: Vec<String>,
    pub(super) created_by: Value,
    pub(super) expires_at: Option<OffsetDateTime>,
    pub(super) last_used_at: Option<OffsetDateTime>,
    pub(super) last_used_ip: Option<String>,
    pub(super) created_at: OffsetDateTime,
    pub(super) paused_at: Option<OffsetDateTime>,
    pub(super) seen_countries: Vec<String>,
}

impl ApiKeyRecord {
    /// The key the record holds, rebuilt through the domain's checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a value no longer passes
    /// its rules, or the row breaks a rule the key keeps.
    pub(super) fn into_api_key(self) -> Result<ApiKey<ResolvedTenant>, DomainError> {
        let last_used_ip = self
            .last_used_ip
            .map(|ip| API_KEY.value("last used address", IpAddress::new(ip)))
            .transpose()?;
        ApiKey::reconstitute(ApiKeyRow {
            id: ApiKeyId::from_uuid(self.id),
            name: API_KEY.value("name", Label::new("api_key_name", self.name))?,
            key_prefix: API_KEY.value("key prefix", KeyPrefix::new(self.key_prefix))?,
            key_hash: TokenHash::from_stored(self.key_hash),
            scopes: scopes_from(API_KEY, self.scopes)?,
            created_by: CREATED_BY.open::<ActorRef>(self.created_by)?,
            expires_at: self.expires_at.map_or(Expiry::Never, Expiry::At),
            last_used_at: self.last_used_at,
            last_used_ip,
            created_at: self.created_at,
            standing: self
                .paused_at
                .map_or(KeyStanding::Working, KeyStanding::Paused),
            seen_countries: self
                .seen_countries
                .into_iter()
                .map(|country| API_KEY.value("seen country", CountryCode::new(country)))
                .collect::<Result<_, _>>()?,
        })
    }
}

/// A key the expiry sweep deleted, as the query answers it.
pub(super) struct ExpiredKeyRecord {
    pub(super) tenant_id: Uuid,
    pub(super) id: Uuid,
    pub(super) name: String,
}

impl ExpiredKeyRecord {
    /// The tenant, id and name of the deleted key.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the stored name is no
    /// label.
    pub(super) fn into_expired(self) -> Result<(TenantId, ApiKeyId, Label), DomainError> {
        Ok((
            TenantId::from_uuid(self.tenant_id),
            ApiKeyId::from_uuid(self.id),
            API_KEY.value("name", Label::new("api_key_name", self.name))?,
        ))
    }
}

/// A key's columns, as they are written.
pub(super) struct ApiKeyColumns<'a> {
    pub(super) id: &'a Uuid,
    pub(super) name: &'a str,
    pub(super) key_prefix: &'a str,
    pub(super) key_hash: &'a str,
    pub(super) scopes: Vec<String>,
    pub(super) created_by: Value,
    pub(super) expires_at: Option<OffsetDateTime>,
    pub(super) last_used_at: Option<OffsetDateTime>,
    pub(super) last_used_ip: Option<&'a str>,
    pub(super) created_at: OffsetDateTime,
    pub(super) paused_at: Option<OffsetDateTime>,
    pub(super) seen_countries: Vec<String>,
}

impl<'a> ApiKeyColumns<'a> {
    /// The columns `key` is written to.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when who made it cannot be
    /// written out as JSON.
    pub(super) fn of(key: &'a ApiKey<ResolvedTenant>) -> Result<Self, DomainError> {
        Ok(Self {
            id: key.id().as_uuid(),
            name: key.name().as_str(),
            key_prefix: key.key_prefix().as_str(),
            key_hash: key.key_hash().as_str(),
            scopes: scopes_column(key.scopes()),
            created_by: CREATED_BY.seal(key.created_by())?,
            expires_at: key.expires_at().instant(),
            last_used_at: key.last_used_at(),
            last_used_ip: key.last_used_ip().map(IpAddress::as_str),
            created_at: key.created_at(),
            paused_at: paused_column(key.standing()),
            seen_countries: seen_countries_column(key),
        })
    }
}

/// The countries `key` signed in from, as the column holds them.
pub(super) fn seen_countries_column(key: &ApiKey<ResolvedTenant>) -> Vec<String> {
    countries_column(key.seen_countries())
}

/// `countries` as the `seen_countries` column holds them, in order: the
/// countries a use read, for the write to land only while they still
/// stand.
pub(super) fn countries_column(countries: &[CountryCode]) -> Vec<String> {
    countries
        .iter()
        .map(|country| country.as_str().to_owned())
        .collect()
}

/// The moment a key was paused, as its column holds it: empty while it
/// works.
pub(super) fn paused_column(standing: KeyStanding) -> Option<OffsetDateTime> {
    match standing {
        KeyStanding::Working => None,
        KeyStanding::Paused(at) => Some(at),
    }
}

#[cfg(test)]
mod tests {
    //! The shape each JSON column is stored in today. A row written now is
    //! read for years, so when one of these fails, the domain changed how
    //! it writes the value: raise the column's shape and add the step that
    //! reads the old one, rather than changing the shape pinned here.

    use ianua_domain::types::{OrgUserId, UserId};
    use serde_json::json;

    use super::*;

    /// Who made a key is written in the shape pinned here, a tenant user
    /// and an organization member told apart, and reads back the same.
    #[test]
    fn who_made_a_key_is_stored_in_its_pinned_shape() {
        let ann = ActorRef::User(UserId::from_uuid(Uuid::from_u128(7)));
        let sam = ActorRef::OrgUser(OrgUserId::from_uuid(Uuid::from_u128(8)));
        let stored = json!({"v": 1, "value": {"User": "00000000-0000-0000-0000-000000000007"}});

        assert_eq!(CREATED_BY.seal(&ann).unwrap(), stored);
        assert_eq!(
            CREATED_BY.seal(&sam).unwrap(),
            json!({"v": 1, "value": {"OrgUser": "00000000-0000-0000-0000-000000000008"}})
        );
        let read: ActorRef = CREATED_BY.open(stored.clone()).unwrap();
        assert_eq!(CREATED_BY.seal(&read).unwrap(), stored);
    }
}
