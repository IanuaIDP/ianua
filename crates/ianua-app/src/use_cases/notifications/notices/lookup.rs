//! The stored things a notice is checked against.

use ianua_domain::domains::notifications::notice::NoticeOffer;
use ianua_domain::message;
use ianua_domain::types::{EventLabel, GroupId};

use crate::error::{AppError, OrInternal, OrNotFound};
use crate::ports::authorization::GroupStore;
use crate::tenancy::ScopedTenant;

/// What a notice is asked to offer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Offering {
    /// Nothing: it only tells.
    Nothing,
    /// To ask to join this group.
    JoinGroup(GroupId),
}

/// The offer `offering` makes, the group it names read from `groups`.
///
/// # Errors
///
/// - `AppError::NotFound` when the tenant has no such group.
/// - `AppError::Internal` on storage failure.
pub(super) async fn existing_offer(
    groups: &dyn GroupStore,
    tenant: &ScopedTenant,
    offering: Offering,
) -> Result<NoticeOffer, AppError> {
    let Offering::JoinGroup(group_id) = offering else {
        return Ok(NoticeOffer::Nothing);
    };
    let group = groups
        .find_by_id(tenant, &group_id)
        .await
        .or_internal()?
        .or_not_found(message!(
            "notifications-the-offered-group-is-not-found",
            "the group offered is not found"
        ))?;
    Ok(NoticeOffer::JoinGroup(
        group_id,
        EventLabel::of(group.name().as_str()),
    ))
}
