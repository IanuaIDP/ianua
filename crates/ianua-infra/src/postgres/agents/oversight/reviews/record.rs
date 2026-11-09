//! A review assignment as its row holds it: read back into the aggregate,
//! and written out from it.

use ianua_domain::domains::agents::oversight::review::{ReviewAssignment, ReviewAssignmentRow};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{AgentId, Ending, ReviewAssignmentId};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::authorization::principals::{kind_word, principal_from};
use crate::postgres::foundation::stored::Stored;

const REVIEW: Stored = Stored("review assignment");

/// An assignment as it is read. The store's checked queries fill it.
pub(super) struct ReviewRecord {
    pub(super) id: Uuid,
    pub(super) reviewer_id: Uuid,
    pub(super) reviewed_id: Uuid,
    pub(super) assigned_by_kind: String,
    pub(super) assigned_by_id: Uuid,
    pub(super) assigned_at: OffsetDateTime,
    pub(super) ended_at: Option<OffsetDateTime>,
}

impl ReviewRecord {
    /// The assignment the record holds, rebuilt through the domain's
    /// checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the kind of who assigned
    /// it is unknown, or the row breaks a rule the assignment keeps.
    pub(super) fn into_review(self) -> Result<ReviewAssignment<ResolvedTenant>, DomainError> {
        ReviewAssignment::reconstitute(ReviewAssignmentRow {
            id: ReviewAssignmentId::from_uuid(self.id),
            reviewer: AgentId::from_uuid(self.reviewer_id),
            reviewed: AgentId::from_uuid(self.reviewed_id),
            assigned_by: principal_from(REVIEW, &self.assigned_by_kind, self.assigned_by_id)?,
            assigned_at: self.assigned_at,
            ending: Ending::from_stored(self.ended_at),
        })
    }
}

/// An assignment's columns, as they are written.
pub(super) struct ReviewColumns<'a> {
    pub(super) id: &'a Uuid,
    pub(super) reviewer_id: &'a Uuid,
    pub(super) reviewed_id: &'a Uuid,
    pub(super) assigned_by_kind: &'static str,
    pub(super) assigned_by_id: Uuid,
    pub(super) assigned_at: OffsetDateTime,
    pub(super) ended_at: Option<OffsetDateTime>,
}

impl<'a> ReviewColumns<'a> {
    /// The columns `assignment` is written to.
    pub(super) fn of(assignment: &'a ReviewAssignment<ResolvedTenant>) -> Self {
        Self {
            id: assignment.id().as_uuid(),
            reviewer_id: assignment.reviewer().as_uuid(),
            reviewed_id: assignment.reviewed().as_uuid(),
            assigned_by_kind: kind_word(assignment.assigned_by()),
            assigned_by_id: assignment.assigned_by().id(),
            assigned_at: assignment.assigned_at(),
            ended_at: assignment.ended_at(),
        }
    }
}
