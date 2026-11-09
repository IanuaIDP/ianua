//! The groups a SCIM filter picks, read back through the authorization
//! context's own mapper of the groups table, so a group reads the same
//! however it was found.

use ianua_domain::domains::authorization::group::Group;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;

use crate::postgres::authorization::groups::tree::record::{GroupRecord, groups_from};

/// The groups `records` hold.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` for the first record that does
/// not read back.
pub(super) fn picked_groups(
    records: Vec<GroupRecord>,
) -> Result<Vec<Group<ResolvedTenant>>, DomainError> {
    groups_from(records)
}
