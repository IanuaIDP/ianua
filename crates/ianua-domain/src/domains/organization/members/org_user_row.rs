//! What a stored member row must keep before
//! [`OrgUser::reconstitute`](crate::domains::organization::members::org_user::OrgUser::reconstitute)
//! rebuilds it.

use crate::domains::organization::members::org_user::OrgUserRow;
use crate::shared::errors::DomainError;
use crate::shared::model::row_check::RowCheck;

/// Refuses a stored member row that breaks a rule a member keeps.
///
/// # Errors
///
/// - [`DomainError::Infrastructure`] when the row breaks one, as
///   [`OrgUser::reconstitute`](crate::domains::organization::members::org_user::OrgUser::reconstitute)
///   lists.
pub(super) fn ensure_consistent(row: &OrgUserRow) -> Result<(), DomainError> {
    RowCheck::of("organization member")
        .holds(
            row.status.fits(row.joining),
            "a join date that does not fit its status",
        )
        .holds(
            row.vouching.fits(row.joining),
            "vouched for by a route it never joined through",
        )
        .in_order(
            row.created_at,
            row.updated_at,
            "changed before it was created",
        )
        .in_order_if(
            row.created_at,
            row.joining.joined_at(),
            "joined before it was created",
        )
        .in_order_if(
            row.created_at,
            row.credentials_changed_at.changed_at(),
            "changed its sign-in before it was created",
        )
        .finish()
}
