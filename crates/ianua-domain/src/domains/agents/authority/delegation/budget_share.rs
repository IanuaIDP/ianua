//! How a parent's request budget is shared among the children passed on
//! from it.

use time::OffsetDateTime;

use crate::domains::agents::authority::capability::AgentBudget;
use crate::domains::agents::authority::delegation::Delegation;
use crate::isolation::scope::TenantScope;
use crate::shared::model::restriction::Restriction;

/// Whether a child of `parent` asking for `asked` fits beside the live
/// children of `parent` in `siblings`. See
/// [`Delegation::budget_fits_beside`].
pub(super) fn fits_beside<T: TenantScope>(
    parent: &Delegation<T>,
    asked: &Restriction<AgentBudget>,
    siblings: &[Delegation<T>],
    now: OffsetDateTime,
) -> bool {
    let Some(cap) = request_cap(parent.constraints().budget()) else {
        return true;
    };
    let taken: u64 = siblings
        .iter()
        .filter(|sibling| sibling.parent() == Some(*parent.id()) && sibling.is_valid(now))
        .map(|sibling| claimed(sibling.constraints().budget(), cap))
        .fold(0, u64::saturating_add);
    taken.saturating_add(claimed(asked, cap)) <= u64::from(cap)
}

/// The requests per window `budget` caps, when it caps any.
fn request_cap(budget: &Restriction<AgentBudget>) -> Option<u32> {
    budget
        .limit()
        .and_then(|budget| budget.max_requests().limit().copied())
}

/// What a child holding `budget` takes from a parent capped at
/// `parent_cap`. A child naming no cap takes all of it, as
/// [`Restriction::under`] gives it the parent's own.
fn claimed(budget: &Restriction<AgentBudget>, parent_cap: u32) -> u64 {
    u64::from(request_cap(budget).unwrap_or(parent_cap))
}
