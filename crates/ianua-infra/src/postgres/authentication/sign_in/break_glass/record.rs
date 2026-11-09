//! A break-glass grant and a tenant's break-glass policy as their rows hold
//! them: read back into the aggregates, and written out from them.
//!
//! The grant's mapping is shared with the access records the authorization
//! context reads, so a grant reads the same however it was found.
//! Permissions are written as the roles write theirs, and an approver as
//! every human is kept in columns.

use ianua_domain::domains::authorization::break_glass::{
    BreakGlassAccess, BreakGlassGrant, BreakGlassGrantRow, BreakGlassPolicy, BreakGlassPolicyRow,
    GrantApproval, SelfService,
};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{BreakGlassGrantId, PersonKey, Revocation, TenantId, Text, UserId};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::authorization::principals::{HumanColumns, maybe_human_from};
use crate::postgres::authorization::roles::definitions::record::{
    custom_permissions_from, system_permissions_from, written,
};
use crate::postgres::foundation::stored::Stored;

const BREAK_GLASS: Stored = Stored("break-glass grant");

const POLICY: Stored = Stored("break-glass policy");

/// A break-glass grant as it is read. The stores' checked queries fill it.
pub(crate) struct BreakGlassRecord {
    pub(crate) id: Uuid,
    pub(crate) user_id: Uuid,
    pub(crate) grantee_person: String,
    pub(crate) system_permissions: Vec<String>,
    pub(crate) custom_permissions: Vec<String>,
    pub(crate) reason: String,
    pub(crate) approver_kind: Option<String>,
    pub(crate) approver_id: Option<Uuid>,
    pub(crate) approver_person: Option<String>,
    pub(crate) expires_at: OffsetDateTime,
    pub(crate) revoked_at: Option<OffsetDateTime>,
    pub(crate) created_at: OffsetDateTime,
}

impl BreakGlassRecord {
    /// The grant the record holds in `tenant_id`, rebuilt through the
    /// domain's checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a value no longer passes
    /// its rules, a permission is unknown, or the row breaks a rule the
    /// grant keeps.
    pub(crate) fn into_grant(self, tenant_id: TenantId) -> Result<BreakGlassGrant, DomainError> {
        let approver = maybe_human_from(
            BREAK_GLASS,
            self.approver_kind,
            self.approver_id,
            self.approver_person,
        )?;
        BreakGlassGrant::reconstitute(BreakGlassGrantRow {
            id: BreakGlassGrantId::from_uuid(self.id),
            tenant_id,
            user_id: UserId::from_uuid(self.user_id),
            grantee_person: BREAK_GLASS.value("grantee", PersonKey::new(self.grantee_person))?,
            access: BreakGlassAccess::from_stored(
                system_permissions_from(&self.system_permissions)?,
                custom_permissions_from(&self.custom_permissions)?,
            ),
            reason: BREAK_GLASS.value("reason", Text::new("reason", self.reason))?,
            approved_by: GrantApproval::from_stored(approver),
            expires_at: self.expires_at,
            revocation: Revocation::from_stored(self.revoked_at),
            created_at: self.created_at,
        })
    }
}

/// A break-glass grant's columns, as they are written.
pub(super) struct BreakGlassColumns<'a> {
    pub(super) id: &'a Uuid,
    pub(super) user_id: &'a Uuid,
    pub(super) grantee_person: &'a str,
    pub(super) system_permissions: Vec<String>,
    pub(super) custom_permissions: Vec<String>,
    pub(super) reason: &'a str,
    pub(super) approver_kind: Option<&'static str>,
    pub(super) approver_id: Option<Uuid>,
    pub(super) approver_person: Option<&'a str>,
    pub(super) expires_at: OffsetDateTime,
    pub(super) revoked_at: Option<OffsetDateTime>,
    pub(super) created_at: OffsetDateTime,
}

impl<'a> BreakGlassColumns<'a> {
    /// The columns `grant` is written to.
    pub(super) fn of(grant: &'a BreakGlassGrant) -> Self {
        let approver = grant.approved_by().approver().map(HumanColumns::of);
        Self {
            id: grant.id().as_uuid(),
            user_id: grant.user_id().as_uuid(),
            grantee_person: grant.grantee_person().as_str(),
            system_permissions: written(grant.access().system()),
            custom_permissions: written(grant.access().custom()),
            reason: grant.reason().as_str(),
            approver_kind: approver.as_ref().map(|human| human.kind),
            approver_id: approver.as_ref().map(|human| human.id),
            approver_person: approver.map(|human| human.person),
            expires_at: grant.expires_at(),
            revoked_at: grant.revoked_at(),
            created_at: grant.created_at(),
        }
    }
}

/// A break-glass policy as it is read. The store's checked queries fill it.
pub(super) struct PolicyRecord {
    pub(super) self_service_system: Option<Vec<String>>,
    pub(super) self_service_custom: Option<Vec<String>>,
    pub(super) updated_at: OffsetDateTime,
}

impl PolicyRecord {
    /// The policy of `tenant_id` the record holds, rebuilt through the
    /// domain's checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when only one list of
    /// permissions is kept, a permission is unknown, or the row breaks a
    /// rule the policy keeps.
    pub(super) fn into_policy(self, tenant_id: TenantId) -> Result<BreakGlassPolicy, DomainError> {
        let self_service = match (self.self_service_system, self.self_service_custom) {
            (None, None) => SelfService::Off,
            (Some(system), Some(custom)) => SelfService::UpTo(BreakGlassAccess::from_stored(
                system_permissions_from(&system)?,
                custom_permissions_from(&custom)?,
            )),
            (Some(_), None) | (None, Some(_)) => {
                return Err(DomainError::corrupt_row(
                    POLICY.0,
                    "half of what users may give themselves",
                ));
            }
        };
        BreakGlassPolicy::reconstitute(BreakGlassPolicyRow {
            tenant_id,
            self_service,
            updated_at: self.updated_at,
        })
    }
}

/// A break-glass policy's columns, as they are written: both lists of
/// permissions empty while self-service is off.
pub(super) struct PolicyColumns {
    pub(super) self_service_system: Option<Vec<String>>,
    pub(super) self_service_custom: Option<Vec<String>>,
    pub(super) updated_at: OffsetDateTime,
}

impl PolicyColumns {
    /// The columns `policy` is written to.
    pub(super) fn of(policy: &BreakGlassPolicy) -> Self {
        let (system, custom) = match policy.self_service() {
            SelfService::Off => (None, None),
            SelfService::UpTo(access) => (
                Some(written(access.system())),
                Some(written(access.custom())),
            ),
        };
        Self {
            self_service_system: system,
            self_service_custom: custom,
            updated_at: policy.updated_at(),
        }
    }
}
