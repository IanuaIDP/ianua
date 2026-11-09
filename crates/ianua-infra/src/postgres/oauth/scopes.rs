//! The scopes a client, a code, a consent, a token or a key carries, as a
//! `text[]` column.

use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::Scope;

use crate::postgres::foundation::stored::Stored;

/// The column `scopes` are written to.
pub(crate) fn scopes_column(scopes: &[Scope]) -> Vec<String> {
    scopes
        .iter()
        .map(|scope| scope.as_str().to_owned())
        .collect()
}

/// The scopes a stored column of `entity` holds.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when a stored scope is not one.
pub(crate) fn scopes_from(entity: Stored, stored: Vec<String>) -> Result<Vec<Scope>, DomainError> {
    stored
        .into_iter()
        .map(|scope| entity.value("scope", Scope::new(scope)))
        .collect()
}
