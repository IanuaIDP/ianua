//! The rules a break-glass grant keeps when it is made, checked again on a
//! stored row.

use crate::domains::authorization::break_glass::{
    BreakGlassGrantRow, GrantApproval, MAX_BREAK_GLASS_LENGTH, grantee_of,
};
use crate::shared::errors::DomainError;
use crate::shared::model::row_check::RowCheck;
use crate::types::Human;

/// Refuses a stored row that breaks a rule a grant keeps.
pub(super) fn ensure_consistent(row: &BreakGlassGrantRow) -> Result<(), DomainError> {
    let grantee = grantee_of(row.user_id, &row.grantee_person);
    RowCheck::of("break-glass grant")
        .holds(
            row.created_at < row.expires_at,
            "ends before it was granted",
        )
        .holds(
            row.expires_at <= row.created_at.saturating_add(MAX_BREAK_GLASS_LENGTH),
            "lasts longer than any grant may",
        )
        .holds(
            row.access.is_well_formed(),
            "grants nothing, or a permission twice",
        )
        .in_order_if(
            row.created_at,
            row.revocation.revoked_at(),
            "revoked before it was granted",
        )
        .holds(
            !approved_by_the_grantee(&row.approved_by, &grantee),
            "a self-approval recorded as a sign-off",
        )
        .finish()
}

/// Whether `approved_by` names the grantee through any of their accounts.
/// That is a self-approval written as someone's sign-off.
fn approved_by_the_grantee(approved_by: &GrantApproval, grantee: &Human) -> bool {
    approved_by
        .approver()
        .is_some_and(|approver| approver.is_same_person_as(grantee))
}
