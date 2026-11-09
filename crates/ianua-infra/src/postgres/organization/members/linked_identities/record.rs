//! A linked identity as its rows hold it, the group's own and one per link:
//! read back into the aggregate, and written out from it.

use ianua_domain::domains::organization::members::linked_identity::{
    LinkedIdentity, LinkedIdentityRow, TenantLink, TenantLinkRow,
};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{Email, LinkedIdentityId, OrganizationId, TenantId, UserId};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::foundation::stored::Stored;

const LINKED_IDENTITY: Stored = Stored("linked identity");

/// A group as it is read, without its links.
pub(super) struct LinkedIdentityRecord {
    pub(super) id: Uuid,
    pub(super) organization_id: Uuid,
    pub(super) email: String,
    pub(super) created_at: OffsetDateTime,
}

/// One link of a group, as it is read.
pub(super) struct LinkRecord {
    pub(super) tenant_id: Uuid,
    pub(super) user_id: Uuid,
    pub(super) linked_at: OffsetDateTime,
}

impl LinkedIdentityRecord {
    /// The group the record holds with `links`, rebuilt through the
    /// domain's checks. Every link carries the group's address, which the
    /// links table does not repeat.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the address no longer
    /// passes its rules, or the group breaks a rule it keeps: no link, or
    /// two links to one tenant or one account.
    pub(super) fn into_linked_identity(
        self,
        links: Vec<LinkRecord>,
    ) -> Result<LinkedIdentity, DomainError> {
        let email = LINKED_IDENTITY.value("email", Email::new(self.email))?;
        let links = links
            .into_iter()
            .map(|link| link.into_link(&email))
            .collect::<Result<Vec<_>, _>>()?;
        LinkedIdentity::reconstitute(LinkedIdentityRow {
            id: LinkedIdentityId::from_uuid(self.id),
            organization_id: OrganizationId::from_uuid(self.organization_id),
            email,
            links,
            created_at: self.created_at,
        })
    }
}

impl LinkRecord {
    fn into_link(self, email: &Email) -> Result<TenantLink, DomainError> {
        TenantLink::reconstitute(TenantLinkRow {
            tenant_id: TenantId::from_uuid(self.tenant_id),
            user_id: UserId::from_uuid(self.user_id),
            email: email.clone(),
            linked_at: self.linked_at,
        })
    }
}

/// A group's links, as the columns they are written to, one list per
/// column.
#[derive(Default)]
pub(super) struct LinkColumns {
    pub(super) tenant_ids: Vec<Uuid>,
    pub(super) user_ids: Vec<Uuid>,
    pub(super) linked_at: Vec<OffsetDateTime>,
}

impl LinkColumns {
    /// The columns the links of `identity` are written to.
    pub(super) fn of(identity: &LinkedIdentity) -> Self {
        identity
            .links()
            .iter()
            .fold(Self::default(), |mut columns, link| {
                columns.tenant_ids.push(*link.tenant_id().as_uuid());
                columns.user_ids.push(*link.user_id().as_uuid());
                columns.linked_at.push(link.linked_at());
                columns
            })
    }
}
