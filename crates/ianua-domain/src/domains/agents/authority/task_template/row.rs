//! The rules a stored task template keeps between its fields, checked when
//! it is read back.

use crate::domains::agents::authority::task_template::{TaskTemplateRow, TemplateApproval};

/// Whether a stored template is unapproved, or approved by a different
/// person than proposed it. The same rule as
/// [`TaskTemplate::approve`](crate::domains::agents::authority::task_template::TaskTemplate::approve).
pub(super) fn approved_by_another(row: &TaskTemplateRow) -> bool {
    row.state
        .approval()
        .is_none_or(|approval| !approval.by().is_same_person_as(&row.proposed_by))
}

/// Whether a stored template was approved after it was proposed, and
/// retired after both.
pub(super) fn decided_in_order(row: &TaskTemplateRow) -> bool {
    let last_decided = row
        .state
        .approval()
        .map_or(row.proposed_at, TemplateApproval::at);
    row.proposed_at <= last_decided && row.state.retired_at().is_none_or(|at| last_decided <= at)
}
