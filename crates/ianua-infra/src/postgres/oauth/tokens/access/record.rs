//! An access token as its row holds it: read back into the aggregate, and
//! written out from it.

use ianua_domain::domains::oauth::grants::access_token::{
    AccessAudience, AccessToken, AccessTokenRow, ActingParty, TokenSubject,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{OAuthClientId, Revocation, StreamRouteId, TokenHash, UserId};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::foundation::envelope::Kept;
use crate::postgres::foundation::stored::Stored;
use crate::postgres::oauth::scopes::{scopes_column, scopes_from};
use crate::postgres::oauth::tokens::binding::{binding_columns, binding_from};

const ACCESS_TOKEN: Stored = Stored("access token");

const DELEGATION: Kept = Kept {
    entity: ACCESS_TOKEN.0,
    column: "delegation",
    shape: 1,
};

/// One party acting for a token's subject, as it is stored.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum StoredParty {
    Person(Uuid),
    Client(Uuid),
}

impl From<&ActingParty> for StoredParty {
    fn from(party: &ActingParty) -> Self {
        match party {
            ActingParty::Person(person) => Self::Person(*person.as_uuid()),
            ActingParty::Client(client) => Self::Client(*client.as_uuid()),
        }
    }
}

impl From<StoredParty> for ActingParty {
    fn from(stored: StoredParty) -> Self {
        match stored {
            StoredParty::Person(person) => Self::Person(UserId::from_uuid(person)),
            StoredParty::Client(client) => Self::Client(OAuthClientId::from_uuid(client)),
        }
    }
}

/// An access token as it is read. The store's checked queries fill it.
pub(super) struct AccessTokenRecord {
    pub(super) token_hash: String,
    pub(super) client_id: Uuid,
    pub(super) user_id: Option<Uuid>,
    pub(super) scopes: Vec<String>,
    pub(super) audience_client_id: Option<Uuid>,
    pub(super) audience_stream_route_id: Option<Uuid>,
    pub(super) delegation: Value,
    pub(super) binding: String,
    pub(super) binding_thumbprint: Option<String>,
    pub(super) created_at: OffsetDateTime,
    pub(super) expires_at: OffsetDateTime,
    pub(super) revoked_at: Option<OffsetDateTime>,
}

impl AccessTokenRecord {
    /// The token the record holds, rebuilt through the domain's checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a value no longer passes
    /// its rules, or the row breaks a rule the token keeps.
    pub(super) fn into_token(self) -> Result<AccessToken<ResolvedTenant>, DomainError> {
        let delegation = DELEGATION
            .open::<Vec<StoredParty>>(self.delegation)?
            .into_iter()
            .map(ActingParty::from)
            .collect();
        AccessToken::reconstitute(AccessTokenRow {
            token_hash: TokenHash::from_stored(self.token_hash),
            client_id: OAuthClientId::from_uuid(self.client_id),
            subject: TokenSubject::from_stored(self.user_id.map(UserId::from_uuid)),
            scopes: scopes_from(ACCESS_TOKEN, self.scopes)?,
            audience: audience_from(self.audience_client_id, self.audience_stream_route_id)?,
            delegation,
            binding: binding_from(ACCESS_TOKEN, &self.binding, self.binding_thumbprint)?,
            created_at: self.created_at,
            expires_at: self.expires_at,
            revocation: Revocation::from_stored(self.revoked_at),
        })
    }
}

/// Whom a token is meant for, as its two audience columns hold it.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when both are set: a token is
/// meant for one audience.
fn audience_from(
    client: Option<Uuid>,
    stream_route: Option<Uuid>,
) -> Result<AccessAudience, DomainError> {
    match (client, stream_route) {
        (None, None) => Ok(AccessAudience::Holder),
        (Some(client), None) => Ok(AccessAudience::Client(OAuthClientId::from_uuid(client))),
        (None, Some(route)) => Ok(AccessAudience::StreamRoute(StreamRouteId::from_uuid(route))),
        (Some(_), Some(_)) => Err(DomainError::corrupt_row(
            ACCESS_TOKEN.0,
            "meant for both a client and a stream route",
        )),
    }
}

/// An access token's columns, as they are written.
pub(super) struct AccessTokenColumns<'a> {
    pub(super) token_hash: &'a str,
    pub(super) client_id: &'a Uuid,
    pub(super) user_id: Option<Uuid>,
    pub(super) scopes: Vec<String>,
    pub(super) audience_client_id: Option<Uuid>,
    pub(super) audience_stream_route_id: Option<Uuid>,
    pub(super) delegation: Value,
    pub(super) binding: &'static str,
    pub(super) binding_thumbprint: Option<&'a str>,
    pub(super) created_at: OffsetDateTime,
    pub(super) expires_at: OffsetDateTime,
    pub(super) revoked_at: Option<OffsetDateTime>,
}

impl<'a> AccessTokenColumns<'a> {
    /// The columns `token` is written to.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when its delegation cannot be
    /// written out as JSON.
    pub(super) fn of(token: &'a AccessToken<ResolvedTenant>) -> Result<Self, DomainError> {
        let (binding, binding_thumbprint) = binding_columns(token.binding());
        let delegation: Vec<StoredParty> =
            token.delegation().iter().map(StoredParty::from).collect();
        Ok(Self {
            token_hash: token.token_hash().as_str(),
            client_id: token.client_id().as_uuid(),
            user_id: token.subject().person().map(|person| *person.as_uuid()),
            scopes: scopes_column(token.scopes()),
            audience_client_id: match token.audience() {
                AccessAudience::Client(client) => Some(*client.as_uuid()),
                AccessAudience::Holder | AccessAudience::StreamRoute(_) => None,
            },
            audience_stream_route_id: match token.audience() {
                AccessAudience::StreamRoute(route) => Some(*route.as_uuid()),
                AccessAudience::Holder | AccessAudience::Client(_) => None,
            },
            delegation: DELEGATION.seal(&delegation)?,
            binding,
            binding_thumbprint,
            created_at: token.created_at(),
            expires_at: token.expires_at(),
            revoked_at: token.revoked_at(),
        })
    }
}

#[cfg(test)]
mod tests {
    //! The shape each JSON column is stored in today. A row written now is
    //! read for years, so when one of these fails, the domain changed how
    //! it writes the value: raise the column's shape and add the step that
    //! reads the old one, rather than changing the shape pinned here.

    use serde_json::json;

    use super::*;

    /// Who acts for a token's subject is written outermost first, in the
    /// shape pinned here, and reads back the same.
    #[test]
    fn the_delegation_is_stored_in_its_pinned_shape() {
        let delegation = vec![
            StoredParty::from(&ActingParty::Client(OAuthClientId::from_uuid(
                Uuid::from_u128(1),
            ))),
            StoredParty::from(&ActingParty::Person(UserId::from_uuid(Uuid::from_u128(2)))),
        ];
        let stored = json!({"v": 1, "value": [
            {"client": "00000000-0000-0000-0000-000000000001"},
            {"person": "00000000-0000-0000-0000-000000000002"}
        ]});

        assert_eq!(DELEGATION.seal(&delegation).unwrap(), stored);
        let read: Vec<ActingParty> = DELEGATION
            .open::<Vec<StoredParty>>(stored)
            .unwrap()
            .into_iter()
            .map(ActingParty::from)
            .collect();
        assert_eq!(
            read,
            [
                ActingParty::Client(OAuthClientId::from_uuid(Uuid::from_u128(1))),
                ActingParty::Person(UserId::from_uuid(Uuid::from_u128(2)))
            ]
        );
    }
}
