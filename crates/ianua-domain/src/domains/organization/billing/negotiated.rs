//! Limits a Custom organization agreed with sales, in place of a sold tier's.

use crate::domains::organization::billing::plan::{OrganizationPlan, PlanLimits};
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::validation::numeric::{validate_count, validate_range};

/// The fewest days of audit records any negotiated plan keeps.
const MIN_RETENTION_DAYS: u32 = 30;

/// The most days of audit records a negotiated plan keeps. A purge subtracts
/// it from now, so it stays well inside what a date can hold.
const MAX_RETENTION_DAYS: u32 = 3_650;

/// The widest API rate a negotiated plan allows, in requests per minute.
const MAX_RATE_PER_MINUTE: u32 = 1_000_000;

/// Limits negotiated for one Custom organization.
///
/// They are agreed with sales and set by the platform, never by the
/// organization. Every count is at least what the free tier allows, so a
/// typo in a contract never leaves an organization unable to keep what any
/// free one has. Retention and the API rate stay finite: the purge subtracts
/// the one from now, and the other protects the server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegotiatedLimits(Box<PlanLimits>);

impl NegotiatedLimits {
    /// Checks and wraps `limits` agreed for a Custom organization.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when a count is below the free tier's.
    /// - [`DomainError::Validation`] when the audit retention is outside 30
    ///   to 3,650 days, or the API rate outside 1 to 1,000,000 a minute.
    /// - [`DomainError::Validation`] when no isolation level is allowed, or
    ///   one is listed twice.
    pub fn new(limits: PlanLimits) -> Result<Self, DomainError> {
        ensure_at_least_free(&limits)?;
        validate_range(
            "audit_retention_days",
            limits.audit_retention_days,
            MIN_RETENTION_DAYS..=MAX_RETENTION_DAYS,
        )?;
        validate_range(
            "api_rate_limit_per_minute",
            limits.api_rate_limit_per_minute,
            1..=MAX_RATE_PER_MINUTE,
        )?;
        validate_count("allowed_isolation", limits.allowed_isolation.len(), 1..=4)?;
        if has_repeat(&limits) {
            return Err(DomainError::invalid(message!(
                "organization-an-isolation-level-is-listed-twice",
                "an isolation level is listed twice"
            )));
        }
        Ok(Self(Box::new(limits)))
    }

    /// The limits as the organization's enforcement reads them.
    #[must_use]
    pub fn limits(&self) -> &PlanLimits {
        &self.0
    }
}

/// The limits an organization works under: those its plan sets, or those
/// negotiated for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanTerms {
    /// The limits its plan sets.
    Standard,
    /// Limits negotiated for it. Only a Custom organization has them.
    Negotiated(NegotiatedLimits),
}

impl PlanTerms {
    /// The limits that apply on `plan` under these terms.
    #[must_use]
    pub fn limits_on(&self, plan: OrganizationPlan) -> PlanLimits {
        match self {
            Self::Standard => plan.default_limits(),
            Self::Negotiated(negotiated) => negotiated.limits().clone(),
        }
    }

    /// Whether these terms may stand on `plan`: negotiated limits belong to
    /// a Custom plan only.
    #[must_use]
    pub fn fit(&self, plan: OrganizationPlan) -> bool {
        match self {
            Self::Standard => true,
            Self::Negotiated(_) => plan == OrganizationPlan::Custom,
        }
    }
}

/// Refuses limits where a count is below what the free tier allows.
fn ensure_at_least_free(limits: &PlanLimits) -> Result<(), DomainError> {
    let free = PlanLimits::free();
    let below = limits.max_users < free.max_users
        || limits.max_tenants_per_org < free.max_tenants_per_org
        || limits.max_routes < free.max_routes
        || limits.max_domains < free.max_domains
        || limits.max_api_keys < free.max_api_keys
        || limits.max_oauth_clients < free.max_oauth_clients
        || limits.max_roles < free.max_roles
        || limits.max_groups < free.max_groups
        || limits.max_webhooks < free.max_webhooks
        || limits.max_agents < free.max_agents
        || limits.max_workflows < free.max_workflows
        || limits.max_sandboxes < free.max_sandboxes
        || limits.max_running_trials < free.max_running_trials
        || limits.max_running_evaluations < free.max_running_evaluations
        || limits.max_own_images < free.max_own_images
        || limits.max_memories < free.max_memories
        || limits.max_memory_entries < free.max_memory_entries
        || limits.max_proxy_requests_per_month < free.max_proxy_requests_per_month;
    if below {
        return Err(DomainError::invalid(message!(
            "organization-negotiated-limits-never-fall-below-the",
            "negotiated limits never fall below the free tier's"
        )));
    }
    Ok(())
}

/// Whether an isolation level is listed twice.
fn has_repeat(limits: &PlanLimits) -> bool {
    let levels = &limits.allowed_isolation;
    levels
        .iter()
        .enumerate()
        .any(|(at, level)| levels.iter().take(at).any(|earlier| earlier == level))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::tenant::provisioning::infrastructure::IsolationLevel;

    /// Limits a little above Business, as sales might agree them.
    fn agreed() -> PlanLimits {
        PlanLimits {
            max_users: 250_000,
            max_routes: 500,
            ..PlanLimits::business()
        }
    }

    /// Sales agrees 250,000 users and 500 routes for Acme. They are
    /// accepted and read back as agreed.
    #[test]
    fn limits_above_the_free_tier_are_accepted() {
        let negotiated = NegotiatedLimits::new(agreed()).unwrap();

        assert_eq!(negotiated.limits().max_users, 250_000);
    }

    /// A contract says zero routes by mistake. It is refused, so Acme is
    /// never left with less than any free organization.
    #[test]
    fn a_count_below_the_free_tier_is_refused() {
        let limits = PlanLimits {
            max_routes: 0,
            ..agreed()
        };

        assert!(matches!(
            NegotiatedLimits::new(limits),
            Err(DomainError::Validation(_))
        ));
    }

    /// Unlimited audit retention is refused: the purge subtracts it from
    /// now and would go out of range.
    #[test]
    fn retention_stays_finite() {
        let limits = PlanLimits {
            audit_retention_days: u32::MAX,
            ..agreed()
        };

        assert!(NegotiatedLimits::new(limits).is_err());
    }

    /// No isolation level at all, or the same one twice, is refused.
    #[test]
    fn isolation_levels_are_listed_once_and_at_least_once() {
        let none = PlanLimits {
            allowed_isolation: Vec::new(),
            ..agreed()
        };
        let twice = PlanLimits {
            allowed_isolation: vec![IsolationLevel::Shared, IsolationLevel::Shared],
            ..agreed()
        };

        assert!(NegotiatedLimits::new(none).is_err());
        assert!(NegotiatedLimits::new(twice).is_err());
    }

    /// Negotiated terms read their own limits. Standard terms read the
    /// plan's.
    #[test]
    fn terms_read_the_limits_they_name() {
        let negotiated = PlanTerms::Negotiated(NegotiatedLimits::new(agreed()).unwrap());

        assert_eq!(
            negotiated.limits_on(OrganizationPlan::Custom).max_users,
            250_000
        );
        assert_eq!(
            PlanTerms::Standard.limits_on(OrganizationPlan::Free),
            PlanLimits::free()
        );
    }

    /// Negotiated limits fit Custom but not Starter; standard terms still
    /// fit Starter.
    #[test]
    fn negotiated_terms_fit_only_a_custom_plan() {
        let negotiated = PlanTerms::Negotiated(NegotiatedLimits::new(agreed()).unwrap());

        assert!(negotiated.fit(OrganizationPlan::Custom));
        assert!(!negotiated.fit(OrganizationPlan::Starter));
        assert!(PlanTerms::Standard.fit(OrganizationPlan::Starter));
    }
}
