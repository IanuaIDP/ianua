//! A tenant grant as its row holds it: read back into the aggregate, and
//! written out from it.

use ianua_domain::domains::organization::members::tenant_grant::{
    OrgTenantGrant, OrgTenantGrantRow,
};
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{ActedBy, OrgUserId, RoleId, TenantId};
use time::OffsetDateTime;
use uuid::Uuid;

/// A grant as it is read. The store's checked queries fill it.
pub(super) struct GrantRecord {
    pub(super) org_user_id: Uuid,
    pub(super) tenant_id: Uuid,
    pub(super) role_id: Uuid,
    pub(super) granted_by: Option<Uuid>,
    pub(super) granted_at: OffsetDateTime,
}

impl GrantRecord {
    /// The grant the record holds, rebuilt through the domain's checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the row breaks a rule the
    /// grant keeps.
    pub(super) fn into_grant(self) -> Result<OrgTenantGrant, DomainError> {
        OrgTenantGrant::reconstitute(OrgTenantGrantRow {
            org_user_id: OrgUserId::from_uuid(self.org_user_id),
            tenant_id: TenantId::from_uuid(self.tenant_id),
            role_id: RoleId::from_uuid(self.role_id),
            granted_by: ActedBy::from_stored(self.granted_by.map(OrgUserId::from_uuid)),
            granted_at: self.granted_at,
        })
    }
}

/// The grants of one member in one tenant, as the columns they are written
/// to, one list per column.
#[derive(Default)]
pub(super) struct GrantColumns {
    pub(super) role_ids: Vec<Uuid>,
    pub(super) granted_by: Vec<Option<Uuid>>,
    pub(super) granted_at: Vec<OffsetDateTime>,
}

impl GrantColumns {
    /// The columns `grants` are written to, every one of them held by
    /// `org_user_id` in `tenant_id`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Validation` when a grant is another member's
    /// or for another tenant: it would be written where it does not belong.
    pub(super) fn of(
        org_user_id: &OrgUserId,
        tenant_id: &TenantId,
        grants: &[OrgTenantGrant],
    ) -> Result<Self, DomainError> {
        let stray = grants
            .iter()
            .any(|grant| grant.org_user_id() != org_user_id || grant.tenant_id() != tenant_id);
        if stray {
            return Err(DomainError::invalid(message!(
                "infra-a-grant-replaced-in-a-tenant",
                "a grant replaced in a tenant belongs to that member and tenant"
            )));
        }
        Ok(grants.iter().fold(Self::default(), |mut columns, grant| {
            columns.role_ids.push(*grant.role_id().as_uuid());
            columns
                .granted_by
                .push(grant.granted_by().account().map(|by| *by.as_uuid()));
            columns.granted_at.push(grant.granted_at());
            columns
        }))
    }
}
