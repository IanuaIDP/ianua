//! An operator as its row holds it: read back into the aggregate, and
//! written out from it.

use ianua_domain::domains::operator::identity::{Operator, OperatorRow};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{Email, OperatorId, PasswordHash};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::foundation::stored::{Stored, StoredWord as _};

const OPERATOR: Stored = Stored("operator");

/// An operator as it is read. The store's checked queries fill it.
pub(super) struct OperatorRecord {
    pub(super) id: Uuid,
    pub(super) email: String,
    pub(super) password_hash: String,
    pub(super) status: String,
    pub(super) created_at: OffsetDateTime,
}

impl OperatorRecord {
    /// The operator the record holds, rebuilt through the domain's checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the address no longer
    /// passes its rules or the status is unknown.
    pub(super) fn into_operator(self) -> Result<Operator, DomainError> {
        Operator::reconstitute(OperatorRow {
            id: OperatorId::from_uuid(self.id),
            email: OPERATOR.value("email", Email::new(self.email))?,
            password_hash: PasswordHash::from_stored(self.password_hash),
            status: OPERATOR.choice(&self.status)?,
            created_at: self.created_at,
        })
    }
}

/// An operator's columns, as they are written.
pub(super) struct OperatorColumns<'a> {
    pub(super) id: &'a Uuid,
    pub(super) email: &'a str,
    pub(super) password_hash: &'a str,
    pub(super) status: &'static str,
    pub(super) created_at: OffsetDateTime,
}

impl<'a> OperatorColumns<'a> {
    /// The columns `operator` is written to.
    pub(super) fn of(operator: &'a Operator) -> Self {
        Self {
            id: operator.id().as_uuid(),
            email: operator.email().as_str(),
            password_hash: operator.password_hash().as_str(),
            status: operator.status().word(),
            created_at: operator.created_at(),
        }
    }
}
