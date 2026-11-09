//! How a subscription opens: on a plan's trial, once per organization, or
//! active at once.

use time::{Duration, OffsetDateTime};

use crate::domains::organization::billing::payment::{SubscriptionState, TrialUse};
use crate::domains::organization::billing::plan::OrganizationPlan;

/// A trial of `plan` starting at `now`, when the plan has one.
pub(super) fn trial_from(plan: OrganizationPlan, now: OffsetDateTime) -> Option<SubscriptionState> {
    plan.trial_days().map(|days| SubscriptionState::Trialing {
        ends_at: now.saturating_add(Duration::days(i64::from(days))),
    })
}

/// How a subscription to `plan` opens at `now`: trialing, using the
/// organization's one trial, when the plan has one, and active otherwise.
pub(super) fn opening_standing(
    plan: OrganizationPlan,
    now: OffsetDateTime,
) -> (SubscriptionState, TrialUse) {
    trial_from(plan, now).map_or((SubscriptionState::Active, TrialUse::Unused), |state| {
        (state, TrialUse::Used)
    })
}
