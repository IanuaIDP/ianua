//! The access records assembled from every table they are read from.
//!
//! The roles, assignments, groups, memberships, resource types and
//! break-glass grants are read through their own stores' mappers, so a
//! record reads the same however it was found.

use ianua_app::ports::authorization::AccessRecords;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::TenantId;

use crate::postgres::authentication::sign_in::break_glass::record::BreakGlassRecord;
use crate::postgres::authorization::groups::memberships::record::{
    MembershipRecord, memberships_from,
};
use crate::postgres::authorization::groups::tree::record::{GroupRecord, groups_from};
use crate::postgres::authorization::resource_types::record::{
    ResourceTypeRecord, resource_types_from,
};
use crate::postgres::authorization::roles::assignments::record::{
    AssignmentRecord, assignments_from,
};
use crate::postgres::authorization::roles::definitions::record::{RoleRecord, roles_from};

/// Everything a read of a tenant's access records found, before it is
/// rebuilt.
#[derive(Default)]
pub(super) struct RecordsRead {
    pub(super) roles: Vec<RoleRecord>,
    pub(super) assignments: Vec<AssignmentRecord>,
    pub(super) groups: Vec<GroupRecord>,
    pub(super) memberships: Vec<MembershipRecord>,
    pub(super) catalogue: Vec<ResourceTypeRecord>,
    pub(super) break_glass: Vec<BreakGlassRecord>,
}

impl RecordsRead {
    /// The access records of `tenant_id` the rows hold, each rebuilt
    /// through the domain's checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` for the first row that does
    /// not read back.
    pub(super) fn into_records(self, tenant_id: TenantId) -> Result<AccessRecords, DomainError> {
        Ok(AccessRecords {
            roles: roles_from(self.roles)?,
            assignments: assignments_from(self.assignments)?,
            groups: groups_from(self.groups)?,
            memberships: memberships_from(self.memberships)?,
            catalogue: resource_types_from(self.catalogue)?,
            break_glass: self
                .break_glass
                .into_iter()
                .map(|grant| grant.into_grant(tenant_id))
                .collect::<Result<_, _>>()?,
        })
    }
}
