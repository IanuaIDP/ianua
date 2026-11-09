//! A pending email change as its row holds it, in either database: read
//! back into the change, and written out from it. Only the hashes of the
//! mailed links are kept.

use ianua_domain::domains::identity::account::email_change::{
    ChangeState, EmailChangeRow, PendingEmailChange,
};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{Email, PrincipalId, TokenHash};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::foundation::stored::Stored;

const CHANGE: Stored = Stored("email change");

/// The word a change still waiting for its link is stored with.
const WAITING: &str = "waiting";

/// The word a confirmed change is stored with.
const CONFIRMED: &str = "confirmed";

/// The word a cancelled change is stored with.
const CANCELLED: &str = "cancelled";

/// A change as it is read. The store's checked queries fill it.
pub(super) struct ChangeRecord {
    pub(super) principal_id: Uuid,
    pub(super) from_email: String,
    pub(super) new_email: String,
    pub(super) token_hash: String,
    pub(super) cancel_token_hash: String,
    pub(super) state: String,
    pub(super) settled_at: Option<OffsetDateTime>,
    pub(super) created_at: OffsetDateTime,
    pub(super) expires_at: OffsetDateTime,
}

impl ChangeRecord {
    /// The change the record holds, rebuilt through the domain's checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when an address no longer
    /// passes its rules, the state does not fit its time, or the row breaks
    /// a rule the change keeps.
    pub(super) fn into_change(self) -> Result<PendingEmailChange, DomainError> {
        PendingEmailChange::reconstitute(EmailChangeRow {
            principal_id: PrincipalId::from_uuid(self.principal_id),
            from_email: CHANGE.value("old address", Email::new(self.from_email))?,
            new_email: CHANGE.value("new address", Email::new(self.new_email))?,
            token_hash: TokenHash::from_stored(self.token_hash),
            cancel_token_hash: TokenHash::from_stored(self.cancel_token_hash),
            created_at: self.created_at,
            expires_at: self.expires_at,
            state: state_from(&self.state, self.settled_at)?,
        })
    }
}

/// Where a stored change stands, from its two columns.
fn state_from(state: &str, settled_at: Option<OffsetDateTime>) -> Result<ChangeState, DomainError> {
    match (state, settled_at) {
        (WAITING, None) => Ok(ChangeState::Waiting),
        (CONFIRMED, Some(at)) => Ok(ChangeState::Confirmed { at }),
        (CANCELLED, Some(at)) => Ok(ChangeState::Cancelled { at }),
        _ => Err(DomainError::corrupt_row(
            CHANGE.0,
            "a state that does not fit when it was settled",
        )),
    }
}

/// A change's columns, as they are written.
pub(super) struct ChangeColumns<'a> {
    pub(super) principal_id: &'a Uuid,
    pub(super) from_email: &'a str,
    pub(super) new_email: &'a str,
    pub(super) token_hash: &'a str,
    pub(super) cancel_token_hash: &'a str,
    pub(super) state: &'static str,
    pub(super) settled_at: Option<OffsetDateTime>,
    pub(super) created_at: OffsetDateTime,
    pub(super) expires_at: OffsetDateTime,
}

impl<'a> ChangeColumns<'a> {
    /// The columns `change` is written to.
    pub(super) fn of(change: &'a PendingEmailChange) -> Self {
        let stage = change.stage();
        let state = match stage {
            ChangeState::Waiting => WAITING,
            ChangeState::Confirmed { .. } => CONFIRMED,
            ChangeState::Cancelled { .. } => CANCELLED,
        };
        Self {
            principal_id: change.principal_id().as_uuid(),
            from_email: change.from_email().as_str(),
            new_email: change.new_email().as_str(),
            token_hash: change.token_hash().as_str(),
            cancel_token_hash: change.cancel_token_hash().as_str(),
            state,
            settled_at: stage.settled_at(),
            created_at: change.created_at(),
            expires_at: change.expires_at(),
        }
    }
}
