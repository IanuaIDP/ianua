//! An agent's request budget: at most so many requests per window, as its
//! task token states, counted across the fleet.

use ianua_app::ports::agents::BudgetKey;
use ianua_domain::domains::agents::authority::capability::RequestBudget;
use ianua_domain::domains::proxy::request::context::{Caller, Metering, PipelineContext};
use ianua_domain::domains::proxy::stages::decision::StageDecision;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{AgentId, DelegationId, PrincipalRef, Seconds};

use super::limits::{Exhausted, refuse_over};
use super::{CounterStages, passed, unavailable};

/// An agent whose requests are counted, and what they are counted against.
struct Metered {
    keys: Vec<BudgetKey>,
    budget: RequestBudget,
}

impl CounterStages {
    /// Counts the request against its agent's request budget, and refuses
    /// it with a 429 once any budget it counts against is spent.
    ///
    /// Only an agent whose task token is metered is counted; every other
    /// caller passes.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the refusal's headers cannot be written.
    pub(crate) async fn agent_budget(
        &self,
        ctx: &mut PipelineContext,
    ) -> Result<StageDecision, DomainError> {
        let Some(metered) = metered(ctx) else {
            return Ok(passed("no request budget applies"));
        };
        let window = metered.budget.window_seconds();
        let Some(used) = self.within(self.highest_use(&metered.keys, window)).await else {
            return Ok(unavailable());
        };
        if used <= metered.budget.max_requests() {
            return Ok(passed("within the request budget"));
        }
        let over = Exhausted {
            limit: metered.budget.max_requests(),
            resets_in: window.get(),
        };
        refuse_over(ctx, &over, "request budget spent")
    }

    /// Records one use against each of `keys`, and answers the highest
    /// count among them. `None` as soon as one cannot be counted.
    async fn highest_use(&self, keys: &[BudgetKey], window: Seconds) -> Option<u32> {
        let mut highest = 0;
        for key in keys {
            highest = highest.max(self.budgets.record_use(key, window).await?);
        }
        Some(highest)
    }
}

fn metered(ctx: &PipelineContext) -> Option<Metered> {
    let Some(Caller::Agent {
        agent_id,
        delegation_id,
        acting_for,
        limits,
    }) = ctx.authentication().caller()
    else {
        return None;
    };
    let Metering::Metered(budget) = limits.metering else {
        return None;
    };
    Some(Metered {
        keys: budget_keys(*agent_id, *delegation_id, *acting_for),
        budget,
    })
}

/// Always the agent, so neither a fresh exchange nor a second token is a
/// second budget; and the delegation too unless the agent minted it for
/// itself, so a cap a person granted holds on its own.
fn budget_keys(
    agent: AgentId,
    delegation: DelegationId,
    acting_for: PrincipalRef,
) -> Vec<BudgetKey> {
    if acting_for == PrincipalRef::Agent(agent) {
        return vec![BudgetKey::Agent(agent)];
    }
    vec![BudgetKey::Agent(agent), BudgetKey::Delegation(delegation)]
}

#[cfg(test)]
mod tests {
    use ianua_domain::types::UserId;

    use super::super::fakes::{Rig, denial_status, header_value, signed_in_agent, signed_in_user};
    use super::*;

    fn budget(max_requests: u32) -> Metering {
        Metering::Metered(RequestBudget::new(max_requests, Seconds::new(300)).unwrap())
    }

    fn for_a_person() -> PrincipalRef {
        PrincipalRef::User(UserId::new())
    }

    /// An agent with a budget of two requests sends two; both pass.
    #[tokio::test]
    async fn requests_within_the_budget_pass() {
        let rig = Rig::counting();
        let stages = rig.stages();
        let mut ctx = signed_in_agent(budget(2), for_a_person());

        for _ in 0..2 {
            let decision = stages.agent_budget(&mut ctx).await.unwrap();
            assert!(!decision.is_terminal());
        }
    }

    /// The third request on a budget of two is refused with a 429 that says
    /// what the budget is.
    #[tokio::test]
    async fn a_request_past_the_budget_is_refused() {
        let rig = Rig::counting();
        let stages = rig.stages();
        let mut ctx = signed_in_agent(budget(2), for_a_person());
        for _ in 0..2 {
            stages.agent_budget(&mut ctx).await.unwrap();
        }

        let decision = stages.agent_budget(&mut ctx).await.unwrap();

        assert_eq!(denial_status(&decision), Some(429));
        assert_eq!(header_value(&ctx, "ratelimit-limit").as_deref(), Some("2"));
        assert_eq!(header_value(&ctx, "retry-after").as_deref(), Some("300"));
    }

    /// A delegation a person granted is counted against the agent and the
    /// delegation; one the agent minted for itself against the agent alone.
    #[test]
    fn a_self_minted_delegation_counts_against_the_agent_only() {
        let (agent, delegation) = (AgentId::new(), DelegationId::new());

        let granted = budget_keys(agent, delegation, for_a_person());
        let minted = budget_keys(agent, delegation, PrincipalRef::Agent(agent));

        assert_eq!(
            granted,
            [BudgetKey::Agent(agent), BudgetKey::Delegation(delegation)]
        );
        assert_eq!(minted, [BudgetKey::Agent(agent)]);
    }

    /// A person is not counted against any agent budget.
    #[tokio::test]
    async fn a_person_has_no_budget_to_spend() {
        let rig = Rig::unreachable();

        let decision = rig
            .stages()
            .agent_budget(&mut signed_in_user())
            .await
            .unwrap();

        assert!(!decision.is_terminal());
    }

    /// An unavailable counter yields 503 for a metered agent request.
    #[tokio::test]
    async fn an_unreachable_budget_counter_refuses() {
        let rig = Rig::unreachable();
        let mut ctx = signed_in_agent(budget(100), for_a_person());

        let decision = rig.stages().agent_budget(&mut ctx).await.unwrap();

        assert_eq!(denial_status(&decision), Some(503));
    }
}
