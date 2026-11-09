//! What sitting at a place in the tenant's group tree brings, worked out
//! from every group and role the tenant has.

use ianua_domain::domains::authorization::group::GroupPlace;
use ianua_domain::domains::authorization::group_tree::{Conferred, GroupTree};

use crate::error::AppError;
use crate::ports::authorization::AccessRecords;

/// What a member at `place` holds through the tree, as `records` say.
///
/// # Errors
///
/// - `AppError::NotFound` when `place` is under a group the tenant does not
///   have.
/// - `AppError::Internal` when a group sits under one that is missing, or
///   names a role that is.
pub(in crate::use_cases::authorization) fn conferred_at(
    records: &AccessRecords,
    place: GroupPlace,
) -> Result<Conferred, AppError> {
    GroupTree::new(&records.groups)
        .conferred(place, &records.roles)
        .map_err(AppError::from_domain)
}
