//! A place in a group as its row holds it: read back into the aggregate,
//! and written out from it.

use ianua_domain::domains::authorization::group::{GroupMembership, GroupMembershipRow};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::GroupId;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::authorization::principals::{kind_word, principal_from};
use crate::postgres::authorization::roles::assignments::record::expiry_from;
use crate::postgres::foundation::stored::Stored;

const MEMBERSHIP: Stored = Stored("group membership");

/// A membership as it is read. The store's checked queries fill it.
pub(crate) struct MembershipRecord {
    pub(crate) group_id: Uuid,
    pub(crate) principal_kind: String,
    pub(crate) principal_id: Uuid,
    pub(crate) joined_at: OffsetDateTime,
    pub(crate) expires_at: Option<OffsetDateTime>,
}

impl MembershipRecord {
    /// The membership the record holds, rebuilt through the domain's
    /// checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the member's kind is
    /// unknown, or it ends before it began.
    pub(crate) fn into_membership(self) -> Result<GroupMembership<ResolvedTenant>, DomainError> {
        GroupMembership::reconstitute(GroupMembershipRow {
            principal: principal_from(MEMBERSHIP, &self.principal_kind, self.principal_id)?,
            group_id: GroupId::from_uuid(self.group_id),
            joined_at: self.joined_at,
            expires: expiry_from(self.expires_at),
        })
    }
}

/// The memberships `records` hold.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` for the first record that does
/// not read back.
pub(crate) fn memberships_from(
    records: Vec<MembershipRecord>,
) -> Result<Vec<GroupMembership<ResolvedTenant>>, DomainError> {
    records
        .into_iter()
        .map(MembershipRecord::into_membership)
        .collect()
}

/// Several memberships as the columns they are written to, one list per
/// column, entry n of each being one membership.
#[derive(Default)]
pub(crate) struct MembershipColumns {
    pub(crate) group_ids: Vec<Uuid>,
    pub(crate) principal_kinds: Vec<&'static str>,
    pub(crate) principal_ids: Vec<Uuid>,
    pub(crate) joined_at: Vec<OffsetDateTime>,
    pub(crate) expires_at: Vec<Option<OffsetDateTime>>,
}

impl MembershipColumns {
    /// The columns `memberships` are written to.
    pub(crate) fn of(memberships: &[GroupMembership<ResolvedTenant>]) -> Self {
        memberships
            .iter()
            .fold(Self::default(), |mut columns, membership| {
                columns.group_ids.push(*membership.group_id().as_uuid());
                columns
                    .principal_kinds
                    .push(kind_word(membership.principal()));
                columns.principal_ids.push(membership.principal().id());
                columns.joined_at.push(membership.joined_at());
                columns.expires_at.push(membership.expires().instant());
                columns
            })
    }
}
