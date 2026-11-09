//! A refresh token as its row holds it: read back into the aggregate, and
//! written out from it.

use ianua_domain::domains::oauth::grants::refresh_token::{
    GrantedIn, OAuthRefreshToken, OAuthRefreshTokenRow, RefreshState,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{OAuthClientId, RefreshFamilyId, SessionId, TokenHash, UserId};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::foundation::stored::Stored;
use crate::postgres::oauth::scopes::{scopes_column, scopes_from};
use crate::postgres::oauth::tokens::binding::{binding_columns, binding_from};

const REFRESH_TOKEN: Stored = Stored("refresh token");

/// A refresh token as it is read. The store's checked queries fill it.
pub(super) struct RefreshTokenRecord {
    pub(super) token_hash: String,
    pub(super) family_id: Uuid,
    pub(super) client_id: Uuid,
    pub(super) user_id: Uuid,
    pub(super) scopes: Vec<String>,
    pub(super) session_id: Option<Uuid>,
    pub(super) binding: String,
    pub(super) binding_thumbprint: Option<String>,
    pub(super) issued_at: OffsetDateTime,
    pub(super) expires_at: OffsetDateTime,
    pub(super) family_expires_at: OffsetDateTime,
    pub(super) state: String,
    pub(super) ended_at: Option<OffsetDateTime>,
}

impl RefreshTokenRecord {
    /// The token the record holds, rebuilt through the domain's checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a value no longer passes
    /// its rules, its state does not read, or the row breaks a rule the
    /// token keeps.
    pub(super) fn into_token(self) -> Result<OAuthRefreshToken<ResolvedTenant>, DomainError> {
        OAuthRefreshToken::reconstitute(OAuthRefreshTokenRow {
            token_hash: TokenHash::from_stored(self.token_hash),
            family: RefreshFamilyId::from_uuid(self.family_id),
            client_id: OAuthClientId::from_uuid(self.client_id),
            user_id: UserId::from_uuid(self.user_id),
            scopes: scopes_from(REFRESH_TOKEN, self.scopes)?,
            granted_in: GrantedIn::from_stored(self.session_id.map(SessionId::from_uuid)),
            binding: binding_from(REFRESH_TOKEN, &self.binding, self.binding_thumbprint)?,
            issued_at: self.issued_at,
            expires_at: self.expires_at,
            family_expires_at: self.family_expires_at,
            state: state_from(&self.state, self.ended_at)?,
        })
    }
}

/// Where a token stands, from its stored word and when it ended.
fn state_from(word: &str, ended_at: Option<OffsetDateTime>) -> Result<RefreshState, DomainError> {
    match (word, ended_at) {
        ("active", None) => Ok(RefreshState::Active),
        ("rotated", Some(at)) => Ok(RefreshState::Rotated { at }),
        ("revoked", Some(at)) => Ok(RefreshState::Revoked { at }),
        _ => Err(DomainError::corrupt_row(
            REFRESH_TOKEN.0,
            "a state this version cannot read",
        )),
    }
}

/// The word `state` is stored as, and when it ended.
fn state_columns(state: RefreshState) -> (&'static str, Option<OffsetDateTime>) {
    match state {
        RefreshState::Active => ("active", None),
        RefreshState::Rotated { at } => ("rotated", Some(at)),
        RefreshState::Revoked { at } => ("revoked", Some(at)),
    }
}

/// A refresh token's columns, as they are written.
pub(super) struct RefreshTokenColumns<'a> {
    pub(super) token_hash: &'a str,
    pub(super) family_id: &'a Uuid,
    pub(super) client_id: &'a Uuid,
    pub(super) user_id: &'a Uuid,
    pub(super) scopes: Vec<String>,
    pub(super) session_id: Option<Uuid>,
    pub(super) binding: &'static str,
    pub(super) binding_thumbprint: Option<&'a str>,
    pub(super) issued_at: OffsetDateTime,
    pub(super) expires_at: OffsetDateTime,
    pub(super) family_expires_at: OffsetDateTime,
    pub(super) state: &'static str,
    pub(super) ended_at: Option<OffsetDateTime>,
}

impl<'a> RefreshTokenColumns<'a> {
    /// The columns a token is written to, from the row it keeps,
    /// [`OAuthRefreshToken::to_row`].
    pub(super) fn of(row: &'a OAuthRefreshTokenRow) -> Self {
        let (binding, binding_thumbprint) = binding_columns(&row.binding);
        let (state, ended_at) = state_columns(row.state);
        Self {
            token_hash: row.token_hash.as_str(),
            family_id: row.family.as_uuid(),
            client_id: row.client_id.as_uuid(),
            user_id: row.user_id.as_uuid(),
            scopes: scopes_column(&row.scopes),
            session_id: row.granted_in.session().map(|session| *session.as_uuid()),
            binding,
            binding_thumbprint,
            issued_at: row.issued_at,
            expires_at: row.expires_at,
            family_expires_at: row.family_expires_at,
            state,
            ended_at,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::rows::at;

    /// Every state reads back from the word and time it is written as.
    #[test]
    fn every_state_reads_back_from_its_columns() {
        for state in [
            RefreshState::Active,
            RefreshState::Rotated { at: at(1) },
            RefreshState::Revoked { at: at(2) },
        ] {
            let (word, ended_at) = state_columns(state);

            assert_eq!(state_from(word, ended_at).unwrap(), state);
        }
    }

    /// An active refresh token with an end time and a revoked token
    /// without one both fail state reconstruction.
    #[test]
    fn a_state_that_does_not_fit_its_time_is_refused() {
        assert!(state_from("active", Some(at(1))).is_err());
        assert!(state_from("revoked", None).is_err());
    }
}
