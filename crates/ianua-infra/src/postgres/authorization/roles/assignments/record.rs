//! A role given straight to a principal, as its row holds it: read back
//! into the aggregate, and written out from it.

use ianua_app::ports::authorization::RoleHolder;
use ianua_domain::domains::authorization::role_assignment::{RoleAssignment, RoleAssignmentRow};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{ActorRef, Expiry, GroupId, RoleId};
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::authorization::principals::{kind_word, principal_from};
use crate::postgres::foundation::envelope::Kept;
use crate::postgres::foundation::stored::Stored;

const ASSIGNMENT: Stored = Stored("role assignment");

const HOLDER: Stored = Stored("role holder");

/// Who gave the role, as the domain writes an actor.
pub(crate) const ASSIGNED_BY: Kept = Kept {
    entity: ASSIGNMENT.0,
    column: "assigned_by",
    shape: 1,
};

/// An assignment as it is read. The store's checked queries fill it.
pub(crate) struct AssignmentRecord {
    pub(crate) role_id: Uuid,
    pub(crate) principal_kind: String,
    pub(crate) principal_id: Uuid,
    pub(crate) assigned_by: Value,
    pub(crate) assigned_at: OffsetDateTime,
    pub(crate) expires_at: Option<OffsetDateTime>,
}

impl AssignmentRecord {
    /// The assignment the record holds, rebuilt through the domain's
    /// checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the principal's kind is
    /// unknown, who gave it does not read, or it ends before it was given.
    pub(crate) fn into_assignment(self) -> Result<RoleAssignment<ResolvedTenant>, DomainError> {
        RoleAssignment::reconstitute(RoleAssignmentRow {
            principal: principal_from(ASSIGNMENT, &self.principal_kind, self.principal_id)?,
            role_id: RoleId::from_uuid(self.role_id),
            assigned_by: ASSIGNED_BY.open(self.assigned_by)?,
            assigned_at: self.assigned_at,
            expires: expiry_from(self.expires_at),
        })
    }
}

/// The end a nullable column holds: none, or the moment it comes.
pub(crate) fn expiry_from(stored: Option<OffsetDateTime>) -> Expiry {
    stored.map_or(Expiry::Never, Expiry::At)
}

/// The assignments `records` hold.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` for the first record that does
/// not read back.
pub(crate) fn assignments_from(
    records: Vec<AssignmentRecord>,
) -> Result<Vec<RoleAssignment<ResolvedTenant>>, DomainError> {
    records
        .into_iter()
        .map(AssignmentRecord::into_assignment)
        .collect()
}

/// An assignment's columns, as they are written.
pub(crate) struct AssignmentColumns<'a> {
    pub(crate) role_id: &'a Uuid,
    pub(crate) principal_kind: &'static str,
    pub(crate) principal_id: Uuid,
    pub(crate) assigned_by: Value,
    pub(crate) assigned_at: OffsetDateTime,
    pub(crate) expires_at: Option<OffsetDateTime>,
}

impl<'a> AssignmentColumns<'a> {
    /// The columns `assignment` is written to.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when who gave it cannot be
    /// written out as JSON.
    pub(crate) fn of(assignment: &'a RoleAssignment<ResolvedTenant>) -> Result<Self, DomainError> {
        Ok(Self {
            role_id: assignment.role_id().as_uuid(),
            principal_kind: kind_word(assignment.principal()),
            principal_id: assignment.principal().id(),
            assigned_by: actor_sealed(assignment.assigned_by())?,
            assigned_at: assignment.assigned_at(),
            expires_at: assignment.expires().instant(),
        })
    }
}

/// `actor` as the `assigned_by` column holds it.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when it cannot be written out.
pub(crate) fn actor_sealed(actor: &ActorRef) -> Result<Value, DomainError> {
    ASSIGNED_BY.seal(actor)
}

/// The kind a holder given the role straight is listed under.
const DIRECT: i64 = 0;

/// The kind a group carrying the role is listed under.
const GROUP: i64 = 1;

/// A holder of a role as a page of holders reads it: its kind and id.
pub(super) struct HolderRecord {
    pub(super) kind: i64,
    pub(super) principal_kind: Option<String>,
    pub(super) holder_id: Uuid,
}

/// The holders of one page, and the assignments read for the direct ones.
pub(super) struct Holders {
    pub(super) records: Vec<HolderRecord>,
    pub(super) assignments: Vec<AssignmentRecord>,
}

impl Holders {
    /// The holders, in the order of `records`, each direct one rebuilt
    /// through the assignment that makes it one.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a kind is unknown, or a
    /// direct holder's assignment is missing or does not read back.
    pub(super) fn into_holders(self) -> Result<Vec<RoleHolder>, DomainError> {
        let mut assignments = self.assignments;
        self.records
            .into_iter()
            .map(|record| holder_from(record, &mut assignments))
            .collect()
    }
}

/// The holder `record` is: a group by its id, or the principal of the
/// assignment among `assignments` that gives it the role.
fn holder_from(
    record: HolderRecord,
    assignments: &mut Vec<AssignmentRecord>,
) -> Result<RoleHolder, DomainError> {
    match (record.kind, record.principal_kind) {
        (GROUP, None) => Ok(RoleHolder::Group(GroupId::from_uuid(record.holder_id))),
        (DIRECT, Some(kind)) => {
            let at = assignments
                .iter()
                .position(|held| {
                    held.principal_id == record.holder_id && held.principal_kind == kind
                })
                .ok_or_else(|| DomainError::corrupt_row(HOLDER.0, "a holder with no assignment"))?;
            let assignment = assignments.swap_remove(at).into_assignment()?;
            Ok(RoleHolder::Direct(*assignment.principal()))
        }
        (_, _) => Err(DomainError::corrupt_row(
            HOLDER.0,
            "an unknown kind of holder",
        )),
    }
}

#[cfg(test)]
mod tests {
    //! The shape each JSON column is stored in today. A row written now is
    //! read for years, so when one of these fails, the domain changed how
    //! it writes the value: raise the column's shape and add the step that
    //! reads the old one, rather than changing the shape pinned here.

    use ianua_domain::types::UserId;
    use serde_json::json;

    use super::*;

    /// Who gave a role is written in the shape pinned here, the platform as
    /// a word and a person by their account, and reads back the same.
    #[test]
    fn who_assigned_it_is_stored_in_its_pinned_shape() {
        let ann = UserId::from_uuid(Uuid::nil());
        let platform = json!({"v": 1, "value": "System"});
        let person = json!({"v": 1, "value": {"User": "00000000-0000-0000-0000-000000000000"}});

        assert_eq!(ASSIGNED_BY.seal(&ActorRef::System).unwrap(), platform);
        assert_eq!(ASSIGNED_BY.seal(&ActorRef::User(ann)).unwrap(), person);
        let read: ActorRef = ASSIGNED_BY.open(person.clone()).unwrap();
        assert_eq!(ASSIGNED_BY.seal(&read).unwrap(), person);
    }
}
