//! Automatic suspension: what the platform does to an agent caught out.
//!
//! Shared by every monitor that may stop an agent on its own (intent drift,
//! convergence). The platform acts, so the system is the actor on record. A
//! person resumes the agent after looking at why.

use ianua_domain::domains::agents::authority::intent::DriftPolicy;
use ianua_domain::domains::agents::identity::agent::{AgentIdentity, SuspendedBy};
use ianua_domain::shared::events::event::DomainEvent;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{AgentId, DelegationId};

use crate::error::{AppError, OrInternal};
use crate::ports::agents::{AgentStore, AgentVersion, DelegationStore};
use crate::tenancy::ScopedTenant;

/// Where an automatic suspension reads the drift policy and stops the agent.
pub(in crate::use_cases::agents) struct EnforcementStores<'a> {
    /// Reads the delegation's drift policy.
    pub(in crate::use_cases::agents) delegation_store: &'a dyn DelegationStore,
    /// Suspends the agent.
    pub(in crate::use_cases::agents) agent_store: &'a dyn AgentStore,
}

/// How many times a monitor reads and suspends an agent that keeps
/// changing under it before it gives up.
const SUSPEND_ATTEMPTS: usize = 3;

/// Suspends an active agent as one of the platform's monitors, returning
/// the suspension the agent raised, recorded as the platform's. An agent
/// that is missing or already stopped is left alone and yields none.
///
/// A stop must not be lost to a change made at the same moment, nor undo
/// one. So the suspension is saved only over the agent as it was read, and
/// read again when the agent changed meanwhile.
///
/// # Errors
///
/// - `AppError::Domain` when suspension is an invalid transition.
/// - `AppError::Conflict` when the agent changed under every attempt.
/// - `AppError::Internal` on persistence failure.
pub(in crate::use_cases::agents) async fn suspend_agent(
    agent_store: &dyn AgentStore,
    tenant_id: &ScopedTenant,
    agent_id: &AgentId,
) -> Result<Option<DomainEvent>, AppError> {
    for _ in 1..SUSPEND_ATTEMPTS {
        match suspended_once(agent_store, tenant_id, agent_id).await {
            Err(AppError::Conflict(_)) => continue,
            settled => return settled,
        }
    }
    suspended_once(agent_store, tenant_id, agent_id).await
}

/// Reads the agent, suspends it if it runs, and saves it only while it is
/// as it was read.
async fn suspended_once(
    agent_store: &dyn AgentStore,
    tenant_id: &ScopedTenant,
    agent_id: &AgentId,
) -> Result<Option<DomainEvent>, AppError> {
    let Some(mut agent) = agent_store
        .find_by_id(tenant_id, agent_id)
        .await
        .or_internal()?
        .filter(AgentIdentity::is_active)
    else {
        return Ok(None);
    };
    let read = AgentVersion::of(&agent);
    agent
        .suspend(SuspendedBy::Monitor)
        .map_err(AppError::from_domain)?;
    agent_store
        .save_unchanged_since(tenant_id, &agent, read)
        .await
        .map_err(AppError::from_domain)?;
    Ok(agent
        .take_events(tenant_id)
        .into_iter()
        .map(DomainEvent::system)
        .next())
}

/// Suspends the agent when the delegation it acted under enforces its
/// intent, returning the event to record; `None` when the policy does not
/// enforce or the agent was not running.
///
/// # Errors
///
/// - `AppError::Domain` when suspension is an invalid transition.
/// - `AppError::Internal` on persistence failure.
pub(in crate::use_cases::agents) async fn suspension_if_enforced(
    stores: EnforcementStores<'_>,
    tenant_id: &ScopedTenant,
    agent_id: &AgentId,
    delegation_id: &DelegationId,
) -> Result<Option<DomainEvent>, AppError> {
    if !enforces_drift(stores.delegation_store, tenant_id, delegation_id).await? {
        return Ok(None);
    }
    suspend_agent(stores.agent_store, tenant_id, agent_id).await
}

/// Whether the delegation an agent acted under enforces its intent, so the
/// platform may stop the agent on its own. A delegation that is missing,
/// binds no intent, or only warns does not.
async fn enforces_drift(
    delegation_store: &dyn DelegationStore,
    tenant_id: &ScopedTenant,
    delegation_id: &DelegationId,
) -> Result<bool, AppError> {
    let delegation = delegation_store
        .find_by_id(tenant_id, delegation_id)
        .await
        .or_internal()?;
    Ok(delegation
        .as_ref()
        .and_then(|d| d.constraints().intent().limit())
        .is_some_and(|binding| matches!(binding.drift_policy(), DriftPolicy::Enforce(_))))
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::agents::identity::status::AgentStatus;

    use super::*;
    use crate::test_support::agents::{FakeAgentStore, FakeDelegationStore};
    use crate::test_support::{block_on, test_ctx};

    /// A monitor catches Ann's agent drifting and stops it. The agent is
    /// suspended, and the suspension is recorded as the platform's.
    #[test]
    fn a_monitor_suspends_an_active_agent() {
        let id = AgentId::new();
        let store = FakeAgentStore::with_active(id);

        let event = block_on(suspend_agent(&store, &test_ctx().tenant(), &id)).unwrap();

        assert!(event.is_some());
        assert_eq!(
            store.find_by_id_direct(&id).unwrap().status(),
            AgentStatus::Suspended
        );
    }

    /// A fleet stop racing the monitor's save leaves the agent suspended;
    /// the monitor returns no duplicate suspension event.
    #[test]
    fn a_monitor_reads_again_when_the_agent_changed_under_it() {
        let id = AgentId::new();
        let store = FakeAgentStore::with_active(id);
        store.stops_the_fleet_before_each_save();

        let event = block_on(suspend_agent(&store, &test_ctx().tenant(), &id)).unwrap();

        assert!(event.is_none());
        assert_eq!(
            store.find_by_id_direct(&id).unwrap().status(),
            AgentStatus::Suspended
        );
    }

    /// A monitor flags an agent a person already suspended. It is left as it
    /// is, and nothing more is recorded.
    #[test]
    fn an_agent_already_stopped_is_left_alone() {
        let id = AgentId::new();
        let store = FakeAgentStore::empty();
        store.add_with_status(id, AgentStatus::Suspended);

        let event = block_on(suspend_agent(&store, &test_ctx().tenant(), &id)).unwrap();

        assert!(event.is_none());
    }

    /// A monitor flags an agent that acted under a delegation the tenant no
    /// longer has. Nothing says the drift is enforced, so the agent keeps
    /// running.
    #[test]
    fn a_missing_delegation_enforces_nothing() {
        let id = AgentId::new();
        let agents = FakeAgentStore::with_active(id);
        let stores = EnforcementStores {
            delegation_store: &FakeDelegationStore::empty(),
            agent_store: &agents,
        };

        let event = block_on(suspension_if_enforced(
            stores,
            &test_ctx().tenant(),
            &id,
            &DelegationId::new(),
        ))
        .unwrap();

        assert!(event.is_none());
        assert!(agents.find_by_id_direct(&id).unwrap().is_active());
    }
}
