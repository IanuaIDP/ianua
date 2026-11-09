//! Refusing an agent that may not act, wherever it acts: one whose standing
//! denies it any action, and one that is not active and so may not be handed
//! authority or end a channel.

use ianua_domain::domains::agents::identity::agent::AgentIdentity;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::types::AgentId;

use crate::error::AppError;
use crate::ports::agents::AgentStandingCheck;
use crate::tenancy::ScopedTenant;

/// Refuses `agent_id` when its standing in `tenant` denies it any action,
/// such as a suspension or a containment.
///
/// # Errors
///
/// - `AppError::Forbidden` naming the reason the agent may not act.
/// - `AppError::Internal` if the standing cannot be read.
pub(crate) async fn ensure_in_good_standing(
    standing: &dyn AgentStandingCheck,
    tenant: &ScopedTenant,
    agent_id: &AgentId,
) -> Result<(), AppError> {
    let standing = standing
        .standing(tenant, agent_id)
        .await
        .map_err(AppError::from_domain)?;
    let Some(reason) = standing.denial_reason() else {
        return Ok(());
    };
    Err(AppError::Forbidden(reason.to_owned().into()))
}

/// Refuses `agent` unless it is active: a suspended or revoked agent neither
/// receives authority nor ends a channel.
///
/// # Errors
///
/// - `AppError::Conflict` if the agent is not active.
pub(crate) fn ensure_active(agent: &AgentIdentity<ResolvedTenant>) -> Result<(), AppError> {
    if agent.is_active() {
        return Ok(());
    }
    Err(AppError::Conflict(message!(
        "agents-agent-is-not-active",
        "agent is not active"
    )))
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::agents::identity::standing::AgentStanding;
    use ianua_domain::domains::agents::identity::status::AgentStatus;

    use super::*;
    use crate::ports::agents::AgentStore;
    use crate::test_support::agents::{FakeAgentStandings, FakeAgentStore};
    use crate::test_support::{block_on, test_ctx};

    fn standings_with(agent: AgentId, standing: AgentStanding) -> FakeAgentStandings {
        let standings = FakeAgentStandings::default();
        standings.set(&test_ctx().tenant(), agent, standing);
        standings
    }

    fn stored_agent(status: AgentStatus) -> AgentIdentity<ResolvedTenant> {
        let id = AgentId::new();
        let store = FakeAgentStore::empty();
        store.add_with_status(id, status);
        block_on(store.find_by_id(&test_ctx().tenant(), &id))
            .unwrap()
            .unwrap()
    }

    /// Ann's agent is active and attested, so it may act.
    #[test]
    fn an_agent_in_good_standing_may_act() {
        let agent = AgentId::new();
        let standings = standings_with(agent, AgentStanding::Active);

        let result = block_on(ensure_in_good_standing(
            &standings,
            &test_ctx().tenant(),
            &agent,
        ));

        assert!(result.is_ok());
    }

    /// Suspended standing makes the action guard return forbidden.
    #[test]
    fn a_suspended_agent_may_not_act() {
        let agent = AgentId::new();
        let standings = standings_with(agent, AgentStanding::Suspended);

        let result = block_on(ensure_in_good_standing(
            &standings,
            &test_ctx().tenant(),
            &agent,
        ));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// Required re-attestation blocks the agent's action with forbidden.
    #[test]
    fn an_agent_owing_a_reattestation_may_not_act() {
        let agent = AgentId::new();
        let standings = standings_with(agent, AgentStanding::MustReattest);

        let result = block_on(ensure_in_good_standing(
            &standings,
            &test_ctx().tenant(),
            &agent,
        ));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// Revoked standing cannot pass the action guard and returns forbidden.
    #[test]
    fn a_revoked_agent_may_not_act() {
        let agent = AgentId::new();
        let standings = standings_with(agent, AgentStanding::Revoked);

        let result = block_on(ensure_in_good_standing(
            &standings,
            &test_ctx().tenant(),
            &agent,
        ));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// Ann's agent is active, so it may be handed authority.
    #[test]
    fn an_active_agent_passes() {
        assert!(ensure_active(&stored_agent(AgentStatus::Active)).is_ok());
    }

    /// A suspended identity fails the active-agent prerequisite with conflict.
    #[test]
    fn a_suspended_agent_is_refused() {
        let result = ensure_active(&stored_agent(AgentStatus::Suspended));

        assert!(matches!(result, Err(AppError::Conflict(_))));
    }

    /// A revoked identity fails the active-agent prerequisite with conflict.
    #[test]
    fn a_revoked_agent_is_refused() {
        let result = ensure_active(&stored_agent(AgentStatus::Revoked));

        assert!(matches!(result, Err(AppError::Conflict(_))));
    }
}
