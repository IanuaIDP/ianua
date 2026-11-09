//! An operator's choices as their rows hold them, read back into the
//! domain's set of them.

use ianua_domain::domains::notifications::personal::{
    OperatorNotificationPreferences, OperatorNotificationPreferencesRow,
};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::OperatorId;

use crate::postgres::notifications::preferences::choice::{ChoiceRecord, rows_of};

/// The operator's choices `records` hold, or `None` when they never chose
/// anything.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when a word is unknown or the
/// rows break a rule the choices keep.
pub(super) fn into_operator_preferences(
    operator_id: OperatorId,
    records: Vec<ChoiceRecord>,
) -> Result<Option<OperatorNotificationPreferences>, DomainError> {
    if records.is_empty() {
        return Ok(None);
    }
    OperatorNotificationPreferences::reconstitute(OperatorNotificationPreferencesRow {
        operator_id,
        preferences: rows_of(records)?,
    })
    .map(Some)
}
