//! A sign-in code as its row holds it: read back into the code, and written
//! out from it.

use ianua_domain::domains::authentication::sessions::sign_in_code::{SignInCode, SignInCodeRow};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{SessionId, TokenHash, Usage};
use time::OffsetDateTime;
use uuid::Uuid;

/// A sign-in code as it is read. The store's checked queries fill it.
pub(super) struct CodeRecord {
    pub(super) token_hash: String,
    pub(super) dashboard_hash: String,
    pub(super) session_id: Uuid,
    pub(super) expires_at: OffsetDateTime,
    pub(super) consumed_at: Option<OffsetDateTime>,
}

impl CodeRecord {
    /// The code the record holds, rebuilt through the domain's checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the row breaks a rule the
    /// code keeps.
    pub(super) fn into_code(self) -> Result<SignInCode<ResolvedTenant>, DomainError> {
        SignInCode::reconstitute(SignInCodeRow {
            token_hash: TokenHash::from_stored(self.token_hash),
            dashboard_hash: TokenHash::from_stored(self.dashboard_hash),
            session_id: SessionId::from_uuid(self.session_id),
            expires_at: self.expires_at,
            usage: Usage::from_stored(self.consumed_at),
        })
    }
}

/// A sign-in code's columns, as they are written.
pub(super) struct CodeColumns<'a> {
    pub(super) token_hash: &'a str,
    pub(super) dashboard_hash: &'a str,
    pub(super) session_id: &'a Uuid,
    pub(super) expires_at: OffsetDateTime,
    pub(super) consumed_at: Option<OffsetDateTime>,
}

impl<'a> CodeColumns<'a> {
    /// The columns `code` is written to.
    pub(super) fn of(code: &'a SignInCode<ResolvedTenant>) -> Self {
        Self {
            token_hash: code.token_hash().as_str(),
            dashboard_hash: code.dashboard_hash().as_str(),
            session_id: code.session_id().as_uuid(),
            expires_at: code.expires_at(),
            consumed_at: code.consumed_at(),
        }
    }
}
