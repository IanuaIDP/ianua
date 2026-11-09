//! An impersonation grant as its row holds it: read back into the
//! aggregate, and written out from it.

use ianua_domain::domains::operator::impersonation::{ImpersonationGrant, ImpersonationGrantRow};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{ImpersonationGrantId, OperatorId, Revocation, TenantId, Text, UserId};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::foundation::stored::Stored;

const GRANT: Stored = Stored("impersonation grant");

/// A grant as it is read. The store's checked queries fill it.
pub(super) struct GrantRecord {
    pub(super) id: Uuid,
    pub(super) operator_id: Uuid,
    pub(super) tenant_id: Uuid,
    pub(super) user_id: Uuid,
    pub(super) reason: String,
    pub(super) expires_at: OffsetDateTime,
    pub(super) revoked_at: Option<OffsetDateTime>,
    pub(super) created_at: OffsetDateTime,
}

impl GrantRecord {
    /// The grant the record holds, rebuilt through the domain's checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the reason no longer
    /// passes its rules or the row breaks a rule the grant keeps.
    pub(super) fn into_grant(self) -> Result<ImpersonationGrant, DomainError> {
        ImpersonationGrant::reconstitute(ImpersonationGrantRow {
            id: ImpersonationGrantId::from_uuid(self.id),
            operator_id: OperatorId::from_uuid(self.operator_id),
            tenant_id: TenantId::from_uuid(self.tenant_id),
            user_id: UserId::from_uuid(self.user_id),
            reason: GRANT.value("reason", Text::new("reason", self.reason))?,
            expires_at: self.expires_at,
            revocation: Revocation::from_stored(self.revoked_at),
            created_at: self.created_at,
        })
    }
}

/// A grant's columns, as they are written.
pub(super) struct GrantColumns<'a> {
    pub(super) id: &'a Uuid,
    pub(super) operator_id: &'a Uuid,
    pub(super) tenant_id: &'a Uuid,
    pub(super) user_id: &'a Uuid,
    pub(super) reason: &'a str,
    pub(super) expires_at: OffsetDateTime,
    pub(super) revoked_at: Option<OffsetDateTime>,
    pub(super) created_at: OffsetDateTime,
}

impl<'a> GrantColumns<'a> {
    /// The columns `grant` is written to.
    pub(super) fn of(grant: &'a ImpersonationGrant) -> Self {
        Self {
            id: grant.id().as_uuid(),
            operator_id: grant.operator_id().as_uuid(),
            tenant_id: grant.tenant_id().as_uuid(),
            user_id: grant.user_id().as_uuid(),
            reason: grant.reason().as_str(),
            expires_at: grant.expires_at(),
            revoked_at: grant.revoked_at(),
            created_at: grant.created_at(),
        }
    }
}
