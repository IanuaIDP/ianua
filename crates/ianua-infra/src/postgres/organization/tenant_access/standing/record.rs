//! Where a member stands in a tenant, as the member and grant rows hold it:
//! read back through the aggregates, then into what the ports answer.

use ianua_app::ports::organization::MembersInTenant;
use ianua_domain::domains::organization::members::org_user::OrgUser;
use ianua_domain::domains::organization::members::tenant_grant::{
    OrgTenantGrant, OrgTenantGrantRow,
};
use ianua_domain::shared::config::DomainLimits;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{ActedBy, OrgUserId, RoleId, TenantId};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::organization::members::OrgUserRecord;

/// A grant held in the one tenant asked about, as it is read.
pub(super) struct HeldGrantRecord {
    pub(super) org_user_id: Uuid,
    pub(super) role_id: Uuid,
    pub(super) granted_by: Option<Uuid>,
    pub(super) granted_at: OffsetDateTime,
}

impl HeldGrantRecord {
    /// The grant the record holds in `tenant_id`, rebuilt through the
    /// domain's checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the row breaks a rule the
    /// grant keeps.
    fn into_grant(self, tenant_id: TenantId) -> Result<OrgTenantGrant, DomainError> {
        OrgTenantGrant::reconstitute(OrgTenantGrantRow {
            org_user_id: OrgUserId::from_uuid(self.org_user_id),
            tenant_id,
            role_id: RoleId::from_uuid(self.role_id),
            granted_by: ActedBy::from_stored(self.granted_by.map(OrgUserId::from_uuid)),
            granted_at: self.granted_at,
        })
    }
}

fn grants_in(
    tenant_id: TenantId,
    records: Vec<HeldGrantRecord>,
) -> Result<Vec<OrgTenantGrant>, DomainError> {
    records
        .into_iter()
        .map(|record| record.into_grant(tenant_id))
        .collect()
}

/// The members who may hold rights in the tenant, from `members`, with the
/// grants they hold there, from `grants`.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when a member's or a grant's row
/// breaks a rule it keeps.
pub(super) fn members_in(
    members: Vec<OrgUserRecord>,
    grants: Vec<HeldGrantRecord>,
    tenant_id: TenantId,
    limits: &DomainLimits,
) -> Result<MembersInTenant, DomainError> {
    let members = members
        .into_iter()
        .map(|record| record.into_org_user(limits))
        .collect::<Result<Vec<OrgUser>, _>>()?;
    Ok(MembersInTenant {
        members,
        grants: grants_in(tenant_id, grants)?,
    })
}
