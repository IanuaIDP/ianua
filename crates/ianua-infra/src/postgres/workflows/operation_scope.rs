//! The operations an account may be used for, as an `operations text[]`
//! column holds them: `NULL` for every one, otherwise the ones named. An
//! account and a connection begun for one keep them the same way.

use ianua_domain::domains::workflows::account::{OperationScope, ScopedOperations};
use ianua_domain::domains::workflows::integration::OperationKey;
use ianua_domain::shared::errors::DomainError;

use crate::postgres::foundation::stored::Stored;

/// The column `scope` is written to.
pub(super) fn written(scope: &OperationScope) -> Option<Vec<String>> {
    match scope {
        OperationScope::All => None,
        OperationScope::Only(scoped) => Some(
            scoped
                .operations()
                .iter()
                .map(|operation| operation.as_str().to_owned())
                .collect(),
        ),
    }
}

/// The scope `stored` in a row of `row` holds: every operation when none is
/// stored.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when an operation no longer passes
/// its rules, or the list breaks a rule a scope keeps.
pub(super) fn read(
    row: Stored,
    stored: Option<Vec<String>>,
) -> Result<OperationScope, DomainError> {
    let Some(stored) = stored else {
        return Ok(OperationScope::All);
    };
    let operations = stored
        .into_iter()
        .map(|operation| row.value("operation", OperationKey::new(operation)))
        .collect::<Result<Vec<_>, _>>()?;
    ScopedOperations::new(operations)
        .map(OperationScope::Only)
        .map_err(DomainError::infra)
}
