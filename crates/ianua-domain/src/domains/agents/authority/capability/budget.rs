//! How many requests an agent may make per time window under a delegation.

use crate::shared::errors::DomainError;
use crate::shared::model::restriction::Restriction;
use crate::shared::validation::numeric::validate_range;
use crate::types::{AgentId, DelegationId, PrincipalRef, Seconds};

/// How many requests an agent may make per rolling window under a delegation.
///
/// The proxy counts each request against the agent. When a person granted
/// the delegation, it counts against the delegation too. Requests past the
/// cap are refused.
///
/// Spend is capped per run instead, where it is measured: see
/// [`AgentRun::spend_limit`](crate::domains::agents::execution::run::AgentRun::spend_limit).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "AgentBudgetWire"))]
pub struct AgentBudget {
    max_requests: Restriction<u32>,
    window_seconds: Seconds,
}

/// A budget as it arrives, before [`AgentBudget::new`] has checked its window.
/// A stored `max_spend` field is ignored.
#[cfg(feature = "serde")]
#[derive(serde::Deserialize)]
struct AgentBudgetWire {
    max_requests: Restriction<u32>,
    window_seconds: Seconds,
}

#[cfg(feature = "serde")]
impl TryFrom<AgentBudgetWire> for AgentBudget {
    type Error = DomainError;

    /// Refuses a stored budget whose window is zero seconds.
    fn try_from(wire: AgentBudgetWire) -> Result<Self, Self::Error> {
        let budget = Self::new(wire.window_seconds)?;
        Ok(Self {
            max_requests: wire.max_requests,
            ..budget
        })
    }
}

impl AgentBudget {
    /// Creates a budget over a rolling window, with no request cap yet.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when `window_seconds` is zero.
    pub fn new(window_seconds: Seconds) -> Result<Self, DomainError> {
        validate_range("window_seconds", window_seconds.get(), 1..=u32::MAX)?;
        Ok(Self {
            max_requests: Restriction::Unrestricted,
            window_seconds,
        })
    }

    /// Caps the number of requests per window.
    #[must_use]
    pub fn with_max_requests(mut self, max_requests: u32) -> Self {
        self.max_requests = Restriction::To(max_requests);
        self
    }

    /// The request cap per window, or unrestricted.
    #[must_use]
    pub fn max_requests(&self) -> Restriction<u32> {
        self.max_requests
    }

    /// The rolling window length in seconds.
    #[must_use]
    pub fn window_seconds(&self) -> Seconds {
        self.window_seconds
    }

    /// The cap the gateway counts requests against, when there is one. A
    /// budget with no request cap counts nothing.
    #[must_use]
    pub fn request_budget(&self) -> Restriction<RequestBudget> {
        match self.max_requests {
            Restriction::To(max_requests) => Restriction::To(RequestBudget {
                max_requests,
                window_seconds: self.window_seconds,
            }),
            Restriction::Unrestricted => Restriction::Unrestricted,
        }
    }

    /// Whether this budget caps no higher than `other` over a window at least
    /// as long.
    ///
    /// No cap means unlimited, so it fits only when `other` has no cap either.
    /// A shorter window at the same cap allows more. 100 requests a second is
    /// far more than 100 an hour. So a budget that fits allows neither a
    /// bigger burst nor a higher rate than `other`.
    #[must_use]
    pub fn within(&self, other: &Self) -> bool {
        cap_within(self.max_requests, other.max_requests)
            && self.window_seconds >= other.window_seconds
    }
}

/// How many requests a task token may make per rolling window: the capped
/// budget its delegation carries, as the token states it and the gateway
/// counts it.
///
/// The gateway counts each request against the agent, and against the
/// delegation too when a person granted it, and refuses the request that
/// goes past the cap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestBudget {
    max_requests: u32,
    window_seconds: Seconds,
}

impl RequestBudget {
    /// `max_requests` per `window_seconds`, as a token states them.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when `window_seconds` is zero: a
    ///   window of no time counts nothing.
    pub fn new(max_requests: u32, window_seconds: Seconds) -> Result<Self, DomainError> {
        validate_range("window_seconds", window_seconds.get(), 1..=u32::MAX)?;
        Ok(Self {
            max_requests,
            window_seconds,
        })
    }

    /// The most requests per window.
    #[must_use]
    pub fn max_requests(&self) -> u32 {
        self.max_requests
    }

    /// The rolling window the requests are counted over.
    #[must_use]
    pub fn window_seconds(&self) -> Seconds {
        self.window_seconds
    }
}

/// What a request budget is counted against.
///
/// A delegation a person granted has a budget of its own. A delegation an
/// agent minted for itself through an exchange does not: every exchange
/// mints a new one, so counting it on its own would hand the agent a fresh
/// budget each time it asked. Those count against the agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BudgetKey {
    /// A delegation a person granted.
    Delegation(DelegationId),
    /// Every delegation an agent minted for itself.
    Agent(AgentId),
}

impl BudgetKey {
    /// The keys a request by `agent` under `delegation`, acting for
    /// `acting_for`, counts against.
    ///
    /// Always the agent, so neither a fresh exchange nor a second token is
    /// a second budget; and the delegation too unless the agent minted it
    /// for itself, so a cap a person granted holds on its own. A request
    /// spends every budget it counts against, and is refused once any of
    /// them is spent.
    #[must_use]
    pub fn counted_for(
        agent: AgentId,
        delegation: DelegationId,
        acting_for: PrincipalRef,
    ) -> Vec<Self> {
        if acting_for == PrincipalRef::Agent(agent) {
            return vec![Self::Agent(agent)];
        }
        vec![Self::Agent(agent), Self::Delegation(delegation)]
    }
}

/// Whether `mine` caps no higher than `theirs`. Anything fits under no cap.
/// No cap fits only under no cap.
fn cap_within<T: PartialOrd>(mine: Restriction<T>, theirs: Restriction<T>) -> bool {
    match (mine, theirs) {
        (_, Restriction::Unrestricted) => true,
        (Restriction::Unrestricted, Restriction::To(_)) => false,
        (Restriction::To(mine), Restriction::To(theirs)) => mine <= theirs,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::agents::authority::capability::DelegationConstraints;
    use crate::types::{Seconds, UserId};

    /// Ann granted her agent a delegation with a budget: its requests count
    /// against the agent and that delegation. A delegation the agent minted
    /// for itself counts against the agent alone, so minting another never
    /// buys a fresh budget.
    #[test]
    fn a_self_minted_delegation_counts_against_the_agent_only() {
        let (agent, delegation) = (AgentId::new(), DelegationId::new());

        let granted = BudgetKey::counted_for(agent, delegation, PrincipalRef::User(UserId::new()));
        let minted = BudgetKey::counted_for(agent, delegation, PrincipalRef::Agent(agent));

        assert_eq!(
            granted,
            [BudgetKey::Agent(agent), BudgetKey::Delegation(delegation)]
        );
        assert_eq!(minted, [BudgetKey::Agent(agent)]);
    }

    /// Requests made on another agent's behalf count against both the
    /// acting agent and its delegation.
    #[test]
    fn every_request_counts_against_the_agent_itself() {
        let agent = AgentId::new();
        let delegation = DelegationId::new();

        let keys = BudgetKey::counted_for(agent, delegation, PrincipalRef::Agent(AgentId::new()));

        assert!(keys.contains(&BudgetKey::Agent(agent)));
        assert!(keys.contains(&BudgetKey::Delegation(delegation)));
    }

    /// A budget over zero seconds is refused. A budget of 100 requests a
    /// minute keeps both numbers, and a delegation given it reports the cap.
    #[test]
    fn budget_rejects_zero_window_and_carries_caps() {
        assert!(AgentBudget::new(Seconds::new(0)).is_err());
        let budget = AgentBudget::new(Seconds::new(60))
            .unwrap()
            .with_max_requests(100);
        assert_eq!(budget.window_seconds(), Seconds::new(60));
        assert_eq!(budget.max_requests(), Restriction::To(100));

        let constraints = DelegationConstraints::new(Seconds::new(600), 1)
            .unwrap()
            .with_budget(budget);
        assert_eq!(
            constraints.budget().limit().map(AgentBudget::max_requests),
            Some(Restriction::To(100))
        );
    }

    /// A delegation capped at 100 requests a minute gives the gateway that
    /// cap to count; one with a window but no cap gives it nothing.
    #[test]
    fn only_a_capped_budget_is_counted() {
        let capped = AgentBudget::new(Seconds::new(60))
            .unwrap()
            .with_max_requests(100);
        let uncapped = AgentBudget::new(Seconds::new(60)).unwrap();

        assert_eq!(
            capped.request_budget(),
            Restriction::To(RequestBudget::new(100, Seconds::new(60)).unwrap())
        );
        assert_eq!(uncapped.request_budget(), Restriction::Unrestricted);
    }

    /// A request budget cannot use a zero-second window. A valid budget
    /// retains its hundred-request cap and sixty-second window.
    #[test]
    fn a_request_budget_over_no_time_is_refused() {
        let budget = RequestBudget::new(100, Seconds::new(60)).unwrap();

        assert!(matches!(
            RequestBudget::new(100, Seconds::new(0)),
            Err(DomainError::Validation(_))
        ));
        assert_eq!(budget.max_requests(), 100);
        assert_eq!(budget.window_seconds(), Seconds::new(60));
    }

    /// A budget fits a hundred-request hourly ceiling only when neither
    /// its cap increases nor its window shortens. An equal budget and a
    /// lower cap over a longer window fit.
    #[test]
    fn a_budget_is_within_another_only_on_every_axis_at_once() {
        let ceiling = AgentBudget::new(Seconds::new(3600))
            .unwrap()
            .with_max_requests(100);

        let narrower = AgentBudget::new(Seconds::new(7200))
            .unwrap()
            .with_max_requests(50);
        assert!(narrower.within(&ceiling));

        let same = AgentBudget::new(Seconds::new(3600))
            .unwrap()
            .with_max_requests(100);
        assert!(same.within(&ceiling), "equal caps are within");

        let more_requests = AgentBudget::new(Seconds::new(7200))
            .unwrap()
            .with_max_requests(101);
        let shorter_window = AgentBudget::new(Seconds::new(3599))
            .unwrap()
            .with_max_requests(50);

        assert!(!more_requests.within(&ceiling), "more requests is wider");
        assert!(
            !shorter_window.within(&ceiling),
            "the same cap over a shorter window is wider"
        );
    }

    /// A hundred-request per-second budget does not fit within a
    /// hundred-request hourly budget because its window is shorter.
    #[test]
    fn the_same_cap_per_second_is_not_within_the_same_cap_per_hour() {
        let hourly = AgentBudget::new(Seconds::new(3600))
            .unwrap()
            .with_max_requests(100);
        let per_second = AgentBudget::new(Seconds::new(1))
            .unwrap()
            .with_max_requests(100);

        assert!(!per_second.within(&hourly));
    }

    proptest::proptest! {
        /// For any two capped budgets, a child that fits inside the parent
        /// has a cap no higher and a rate of requests no higher.
        #[test]
        fn a_budget_within_another_never_allows_a_higher_rate(
            child_window in 1u32..100_000,
            child_cap in 0u32..10_000,
            parent_window in 1u32..100_000,
            parent_cap in 0u32..10_000,
        ) {
            let child = AgentBudget::new(Seconds::new(child_window)).unwrap().with_max_requests(child_cap);
            let parent = AgentBudget::new(Seconds::new(parent_window)).unwrap().with_max_requests(parent_cap);

            if child.within(&parent) {
                let child_rate = u128::from(child_cap) * u128::from(parent_window);
                let parent_rate = u128::from(parent_cap) * u128::from(child_window);
                proptest::prop_assert!(child_rate <= parent_rate);
                proptest::prop_assert!(child_cap <= parent_cap);
            }
        }
    }

    /// With equal windows, an uncapped budget cannot fit within a capped
    /// one. A capped budget fits an uncapped one, and uncapped budgets fit each other.
    #[test]
    fn an_unlimited_budget_is_within_another_only_if_that_one_is_unlimited() {
        let capped = AgentBudget::new(Seconds::new(600))
            .unwrap()
            .with_max_requests(100);
        let unlimited = AgentBudget::new(Seconds::new(600)).unwrap();

        assert!(capped.within(&unlimited), "any cap is within no cap");
        assert!(
            !unlimited.within(&capped),
            "dropping the cap would widen the budget"
        );
        assert!(unlimited.within(&AgentBudget::new(Seconds::new(600)).unwrap()));
    }

    /// A valid serialized budget loads successfully, but changing its
    /// window to zero prevents deserialization.
    #[cfg(feature = "serde")]
    #[test]
    fn a_stored_budget_with_a_zero_window_is_refused() {
        let written = AgentBudget::new(Seconds::new(60))
            .unwrap()
            .with_max_requests(100);
        let honest = serde_json::to_value(&written).unwrap();
        let mut zero_window = honest.clone();
        zero_window["window_seconds"] = serde_json::json!(0);

        assert!(serde_json::from_value::<AgentBudget>(honest).is_ok());
        assert!(serde_json::from_value::<AgentBudget>(zero_window).is_err());
    }

    /// A budget of 100 requests a minute is saved as JSON and loaded again.
    /// It comes back equal, with the same cap and window.
    #[cfg(feature = "serde")]
    #[test]
    fn a_budget_reads_back_what_it_writes() {
        let budget = AgentBudget::new(Seconds::new(60))
            .unwrap()
            .with_max_requests(100);

        let json = serde_json::to_string(&budget).unwrap();

        assert_eq!(serde_json::from_str::<AgentBudget>(&json).unwrap(), budget);
    }

    /// A stored budget carries a `max_spend` field as well as its request
    /// cap. It loads with the request cap kept and the spend field ignored.
    #[cfg(feature = "serde")]
    #[test]
    fn a_budget_stored_with_a_spend_cap_still_loads() {
        let mut stored = serde_json::to_value(
            AgentBudget::new(Seconds::new(60))
                .unwrap()
                .with_max_requests(100),
        )
        .unwrap();
        stored["max_spend"] = serde_json::json!({ "to": 5000 });

        let budget = serde_json::from_value::<AgentBudget>(stored).unwrap();

        assert_eq!(budget.max_requests(), Restriction::To(100));
    }
}
