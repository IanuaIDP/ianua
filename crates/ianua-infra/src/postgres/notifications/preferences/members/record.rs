//! An organization member's choices as their rows hold them, read back
//! into the domain's set of them.

use ianua_domain::domains::notifications::personal::{
    MemberNotificationPreferences, MemberNotificationPreferencesRow,
};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{OrgUserId, OrganizationId};

use crate::postgres::notifications::preferences::choice::{ChoiceRecord, rows_of};

/// The member's choices `records` hold, or `None` when they never chose
/// anything.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when a word is unknown or the
/// rows break a rule the choices keep.
pub(super) fn into_member_preferences(
    organization_id: OrganizationId,
    org_user_id: OrgUserId,
    records: Vec<ChoiceRecord>,
) -> Result<Option<MemberNotificationPreferences>, DomainError> {
    if records.is_empty() {
        return Ok(None);
    }
    MemberNotificationPreferences::reconstitute(MemberNotificationPreferencesRow {
        organization_id,
        org_user_id,
        preferences: rows_of(records)?,
    })
    .map(Some)
}
