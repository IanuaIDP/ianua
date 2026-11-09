//! An authorization code as its row holds it: read back into the
//! aggregate, and written out from it.

use ianua_app::ports::oauth::ConsentedSession;
use ianua_domain::domains::authentication::sessions::mfa_factor::{FactorProved, MfaFactor};
use ianua_domain::domains::oauth::grants::authorization_code::{
    AuthCodeRow, AuthorizationCode, CodeChallenge, NonceSent,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{Nonce, OAuthClientId, RedirectUri, SessionId, TokenHash, Usage, UserId};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::foundation::stored::{Stored, StoredWord as _};
use crate::postgres::oauth::scopes::{scopes_column, scopes_from};

const CODE: Stored = Stored("authorization code");

/// A distinct client/session pair read for logout delivery.
pub(super) struct ConsentedSessionRecord {
    pub(super) client_id: Uuid,
    pub(super) session_id: Uuid,
}

impl ConsentedSessionRecord {
    /// Rebuilds the typed identities used to select logout recipients.
    pub(super) fn into_pair(self) -> ConsentedSession {
        ConsentedSession {
            client: OAuthClientId::from_uuid(self.client_id),
            session: SessionId::from_uuid(self.session_id),
        }
    }
}

/// A code as it is read. The store's checked queries fill it.
pub(super) struct AuthCodeRecord {
    pub(super) code_hash: String,
    pub(super) client_id: Uuid,
    pub(super) user_id: Uuid,
    pub(super) redirect_uri: String,
    pub(super) scopes: Vec<String>,
    pub(super) code_challenge: String,
    pub(super) code_challenge_method: String,
    pub(super) nonce: Option<String>,
    pub(super) session_id: Uuid,
    pub(super) auth_method: String,
    pub(super) second_factor: Option<String>,
    pub(super) authenticated_at: OffsetDateTime,
    pub(super) created_at: OffsetDateTime,
    pub(super) expires_at: OffsetDateTime,
    pub(super) consumed_at: Option<OffsetDateTime>,
}

impl AuthCodeRecord {
    /// The code the record holds, rebuilt through the domain's checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a value no longer passes
    /// its rules, a word is unknown, or the row breaks a rule the code
    /// keeps.
    pub(super) fn into_code(self) -> Result<AuthorizationCode<ResolvedTenant>, DomainError> {
        let nonce = self
            .nonce
            .map(|nonce| CODE.value("nonce", Nonce::new(nonce)))
            .transpose()?;
        let second_factor = self
            .second_factor
            .map(|factor| CODE.choice(&factor))
            .transpose()?;
        AuthorizationCode::reconstitute(AuthCodeRow {
            code_hash: TokenHash::from_stored(self.code_hash),
            client_id: OAuthClientId::from_uuid(self.client_id),
            user_id: UserId::from_uuid(self.user_id),
            redirect_uri: CODE.value("redirect URI", RedirectUri::new(self.redirect_uri))?,
            scopes: scopes_from(CODE, self.scopes)?,
            code_challenge: CODE
                .value("code challenge", CodeChallenge::new(self.code_challenge))?,
            code_challenge_method: CODE.choice(&self.code_challenge_method)?,
            nonce: NonceSent::from_stored(nonce),
            session_id: SessionId::from_uuid(self.session_id),
            auth_method: CODE.choice(&self.auth_method)?,
            second_factor: FactorProved::from_stored(second_factor),
            authenticated_at: self.authenticated_at,
            created_at: self.created_at,
            expires_at: self.expires_at,
            usage: Usage::from_stored(self.consumed_at),
        })
    }
}

/// A code's columns, as they are written.
pub(super) struct AuthCodeColumns<'a> {
    pub(super) code_hash: &'a str,
    pub(super) client_id: &'a Uuid,
    pub(super) user_id: &'a Uuid,
    pub(super) redirect_uri: &'a str,
    pub(super) scopes: Vec<String>,
    pub(super) code_challenge: &'a str,
    pub(super) code_challenge_method: &'static str,
    pub(super) nonce: Option<&'a str>,
    pub(super) session_id: &'a Uuid,
    pub(super) auth_method: &'static str,
    pub(super) second_factor: Option<&'static str>,
    pub(super) authenticated_at: OffsetDateTime,
    pub(super) created_at: OffsetDateTime,
    pub(super) expires_at: OffsetDateTime,
    pub(super) consumed_at: Option<OffsetDateTime>,
}

impl<'a> AuthCodeColumns<'a> {
    /// The columns `code` is written to.
    pub(super) fn of(code: &'a AuthorizationCode<ResolvedTenant>) -> Self {
        Self {
            code_hash: code.code_hash().as_str(),
            client_id: code.client_id().as_uuid(),
            user_id: code.user_id().as_uuid(),
            redirect_uri: code.redirect_uri().as_str(),
            scopes: scopes_column(code.scopes()),
            code_challenge: code.code_challenge().as_str(),
            code_challenge_method: code.code_challenge_method().word(),
            nonce: code.nonce().sent().map(Nonce::as_str),
            session_id: code.session_id().as_uuid(),
            auth_method: code.auth_method().word(),
            second_factor: code.second_factor().stored().map(MfaFactor::word),
            authenticated_at: code.authenticated_at(),
            created_at: code.created_at(),
            expires_at: code.expires_at(),
            consumed_at: code.consumed_at(),
        }
    }
}
