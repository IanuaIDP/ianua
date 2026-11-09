//! Loading an organization member's or an operator's notification choices,
//! or their starting choices when they never chose anything.

use ianua_domain::domains::notifications::personal::{
    MemberNotificationPreferences, OperatorNotificationPreferences,
};
use ianua_domain::domains::operator::control::OperatorAuthority;
use ianua_domain::domains::organization::members::control::OrgControl;

use crate::error::{AppError, OrInternal};
use crate::ports::notifications::{MemberPreferenceStore, OperatorPreferenceStore};

/// The choices of the member `control` names, or every category in-app
/// when they never chose anything.
///
/// # Errors
///
/// - `AppError::Forbidden` when the member may not change their own
///   notifications, which their starting choices need.
/// - `AppError::Internal` on storage failure.
pub(super) async fn member_choices(
    store: &dyn MemberPreferenceStore,
    control: &OrgControl<'_>,
) -> Result<MemberNotificationPreferences, AppError> {
    let member = control.by();
    let stored = store
        .find(member.organization_id(), member.id())
        .await
        .or_internal()?;
    let Some(stored) = stored else {
        return MemberNotificationPreferences::for_member(control).map_err(AppError::from_domain);
    };
    Ok(stored)
}

/// The choices of the operator `authority` names, or every category in-app
/// when they never chose anything.
///
/// # Errors
///
/// `AppError::Internal` on storage failure.
pub(super) async fn operator_choices(
    store: &dyn OperatorPreferenceStore,
    authority: &OperatorAuthority,
) -> Result<OperatorNotificationPreferences, AppError> {
    Ok(store
        .find(authority.operator())
        .await
        .or_internal()?
        .unwrap_or_else(|| OperatorNotificationPreferences::for_operator(authority)))
}
