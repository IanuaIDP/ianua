//! A group as its row holds it, with the roles it carries: read back into
//! the aggregate, and written out from it.

use ianua_domain::domains::authorization::group::{Group, GroupOrigin, GroupPlace, GroupRow};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{GroupId, Label, RoleId};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::foundation::stored::Stored;

const GROUP: Stored = Stored("group");

/// A group as it is read. The store's checked queries fill it.
pub(crate) struct GroupRecord {
    pub(crate) id: Uuid,
    pub(crate) name: String,
    pub(crate) origin: String,
    pub(crate) parent_id: Option<Uuid>,
    pub(crate) role_ids: Vec<Uuid>,
    pub(crate) created_at: OffsetDateTime,
    pub(crate) updated_at: OffsetDateTime,
}

impl GroupRecord {
    /// The group the record holds, rebuilt through the domain's checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the name no longer passes
    /// its rules, the origin is unknown, or the row breaks a rule the group
    /// keeps.
    pub(crate) fn into_group(self) -> Result<Group<ResolvedTenant>, DomainError> {
        Group::reconstitute(GroupRow {
            id: GroupId::from_uuid(self.id),
            name: GROUP.value("name", Label::new("name", self.name))?,
            origin: GroupOrigin::from_stored(&self.origin)?,
            place: GroupPlace::from_stored(self.parent_id.map(GroupId::from_uuid)),
            role_ids: self.role_ids.into_iter().map(RoleId::from_uuid).collect(),
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

/// The groups `records` hold.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` for the first record that does
/// not read back.
pub(crate) fn groups_from(
    records: Vec<GroupRecord>,
) -> Result<Vec<Group<ResolvedTenant>>, DomainError> {
    records.into_iter().map(GroupRecord::into_group).collect()
}

/// A group's columns, as they are written.
pub(crate) struct GroupColumns<'a> {
    pub(crate) id: &'a Uuid,
    pub(crate) name: &'a str,
    pub(crate) origin: &'static str,
    pub(crate) parent_id: Option<Uuid>,
    pub(crate) role_ids: Vec<Uuid>,
    pub(crate) created_at: OffsetDateTime,
    pub(crate) updated_at: OffsetDateTime,
}

impl<'a> GroupColumns<'a> {
    /// The columns `group` is written to.
    pub(crate) fn of(group: &'a Group<ResolvedTenant>) -> Self {
        Self {
            id: group.id().as_uuid(),
            name: group.name().as_str(),
            origin: group.origin().as_str(),
            parent_id: group.place().parent().map(|parent| *parent.as_uuid()),
            role_ids: group
                .role_ids()
                .iter()
                .map(|role| *role.as_uuid())
                .collect(),
            created_at: group.created_at(),
            updated_at: group.updated_at(),
        }
    }
}
