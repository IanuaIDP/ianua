//! What a stored user row must keep before
//! [`User::reconstitute`](crate::domains::identity::account::user::User::reconstitute) rebuilds it.

use crate::domains::identity::account::address::AddressStanding;
use crate::domains::identity::account::user::UserRow;
use crate::domains::identity::account::user_status::UserStatus;
use crate::shared::errors::DomainError;
use crate::shared::model::row_check::RowCheck;
use crate::types::Joining;

/// Refuses a stored user row that breaks a rule a user keeps.
///
/// # Errors
///
/// - [`DomainError::Infrastructure`] when the row breaks one, as
///   [`User::reconstitute`](crate::domains::identity::account::user::User::reconstitute) lists.
pub(super) fn ensure_consistent(row: &UserRow) -> Result<(), DomainError> {
    RowCheck::of("user")
        .holds(
            joined_only_once_admitted(row),
            "a join date that does not fit its status",
        )
        .holds(
            !waits_on_a_proven_address(row),
            "waiting on an address it has already proven",
        )
        .holds(
            !row.profile.records.names_as_own_manager(&row.id),
            "names the account as its own manager",
        )
        .holds(
            row.vouching.fits(row.joining),
            "vouched for by an invitation it never joined through",
        )
        .finish()?;
    ensure_in_time_order(row)
}

/// Refuses a stored user row that says it changed, signed in or joined
/// before it was created.
fn ensure_in_time_order(row: &UserRow) -> Result<(), DomainError> {
    RowCheck::of("user")
        .in_order(
            row.created_at,
            row.updated_at,
            "changed before it was created",
        )
        .in_order_if(
            row.created_at,
            row.last_login_at,
            "signed in before it was created",
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

/// Whether a stored user is still waiting on an address it already proved.
fn waits_on_a_proven_address(row: &UserRow) -> bool {
    row.status == UserStatus::PendingVerification && row.email_standing == AddressStanding::Verified
}

/// Whether a stored user's join date fits its status.
///
/// One still invited or unverified has none. One active or locked has been
/// active, so it has one. A deactivated user may have been either.
fn joined_only_once_admitted(row: &UserRow) -> bool {
    match row.status {
        UserStatus::Invited | UserStatus::PendingVerification => row.joining == Joining::NotYet,
        UserStatus::Active | UserStatus::Locked | UserStatus::Closing => {
            row.joining != Joining::NotYet
        }
        UserStatus::Deactivated => true,
    }
}
