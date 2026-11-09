//! A tenant user's choices as their rows hold them, read back into the
//! domain's preferences.

use ianua_domain::domains::notifications::preference::NotificationPreference;
use ianua_domain::shared::errors::DomainError;

use crate::postgres::notifications::preferences::choice::{ChoiceRecord, rows_of};

/// The preferences `records` hold, each rebuilt through the domain's
/// checks.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when a word is unknown.
pub(super) fn into_preferences(
    records: Vec<ChoiceRecord>,
) -> Result<Vec<NotificationPreference>, DomainError> {
    rows_of(records)?
        .into_iter()
        .map(NotificationPreference::reconstitute)
        .collect()
}
