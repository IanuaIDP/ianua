//! An initial access token as its row holds it: read back into the
//! aggregate, and written out from it.

use ianua_domain::domains::oauth::clients::registration::{
    InitialAccessToken, InitialAccessTokenRow,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{InitialAccessTokenId, Label, Revocation, TokenHash};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::foundation::stored::Stored;

const TOKEN: Stored = Stored("initial access token");

/// An initial access token as it is read. The store's checked queries fill
/// it.
pub(super) struct InitialAccessTokenRecord {
    pub(super) id: Uuid,
    pub(super) name: String,
    pub(super) token_hash: String,
    pub(super) uses_left: i32,
    pub(super) created_at: OffsetDateTime,
    pub(super) expires_at: OffsetDateTime,
    pub(super) revoked_at: Option<OffsetDateTime>,
}

impl InitialAccessTokenRecord {
    /// The token the record holds, rebuilt through the domain's checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a value no longer passes
    /// its rules, or the row breaks a rule the token keeps.
    pub(super) fn into_token(self) -> Result<InitialAccessToken<ResolvedTenant>, DomainError> {
        InitialAccessToken::reconstitute(InitialAccessTokenRow {
            id: InitialAccessTokenId::from_uuid(self.id),
            name: TOKEN.value("name", Label::new("name", self.name))?,
            token_hash: TokenHash::from_stored(self.token_hash),
            uses_left: u32::try_from(self.uses_left)
                .map_err(|_| DomainError::corrupt_row(TOKEN.0, "fewer than no uses left"))?,
            created_at: self.created_at,
            expires_at: self.expires_at,
            revocation: Revocation::from_stored(self.revoked_at),
        })
    }
}

/// An initial access token's columns, as they are written.
pub(super) struct InitialAccessTokenColumns<'a> {
    pub(super) id: &'a Uuid,
    pub(super) name: &'a str,
    pub(super) token_hash: &'a str,
    pub(super) uses_left: i32,
    pub(super) created_at: OffsetDateTime,
    pub(super) expires_at: OffsetDateTime,
    pub(super) revoked_at: Option<OffsetDateTime>,
}

impl<'a> InitialAccessTokenColumns<'a> {
    /// The columns `token` is written to.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when its uses do not fit their
    /// column, which a token the domain made never does.
    pub(super) fn of(token: &'a InitialAccessToken<ResolvedTenant>) -> Result<Self, DomainError> {
        Ok(Self {
            id: token.id().as_uuid(),
            name: token.name().as_str(),
            token_hash: token.token_hash().as_str(),
            uses_left: uses_column(token)?,
            created_at: token.created_at(),
            expires_at: token.expires_at(),
            revoked_at: token.revocation().revoked_at(),
        })
    }
}

/// The uses `token` has left, as their column holds them.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when they do not fit the column.
pub(super) fn uses_column(token: &InitialAccessToken<ResolvedTenant>) -> Result<i32, DomainError> {
    i32::try_from(token.uses_left()).map_err(DomainError::infra)
}
