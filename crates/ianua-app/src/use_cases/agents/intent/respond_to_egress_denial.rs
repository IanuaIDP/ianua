//! Respond to egress denial: hold a refused way out against the agent that
//! caused it.
//!
//! A worker over `AgentEgressDenied`. The egress gateway refused a service
//! traffic its policy does not allow while that service was handling an
//! agent's request, and the request carried the assertion naming the agent.
//! The service only did what it was asked: trying to reach an unlisted host
//! through a service is the agent's drift. It is recorded as drift every time,
//! and under `Enforce` the platform's monitor suspends the agent until a
//! person looks.

use std::sync::Arc;

use ianua_domain::domains::agents::events::oversight::AgentIntentDrift;
use ianua_domain::shared::events::event::DomainEvent;
use ianua_domain::types::{ActingFor, ActorRef, AgentId, DelegationId};

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::agents::{AgentStore, DelegationStore};
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::agents::lifecycle::containment::suspension::{
    EnforcementStores, suspension_if_enforced,
};

/// The refused call, as the gateway reported it.
pub struct RespondToEgressDenialRequest {
    /// The agent whose request caused the call.
    pub agent_id: AgentId,
    /// The delegation it acted under.
    pub delegation_id: DelegationId,
}

/// What the response did.
#[derive(Debug, PartialEq, Eq)]
pub enum EgressDenialResponse {
    /// Recorded as drift.
    Recorded,
    /// Recorded, and the agent was suspended.
    Suspended,
}

/// The ports [`RespondToEgressDenialUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RespondToEgressDenialPorts {
    /// Reads the delegation's drift policy.
    pub delegation_store: Arc<dyn DelegationStore>,
    /// Suspends the agent under `Enforce`.
    pub agent_store: Arc<dyn AgentStore>,
}

/// Holds a refused egress against the agent.
pub struct RespondToEgressDenialUseCase {
    ports: RespondToEgressDenialPorts,
}

impl RespondToEgressDenialUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: RespondToEgressDenialPorts) -> Self {
        Self { ports }
    }
}

impl Command for RespondToEgressDenialUseCase {
    type Caller = ScopedTenant;
    type Input = RespondToEgressDenialRequest;
    type Output = Result<EgressDenialResponse, AppError>;

    /// Records the drift and, under `Enforce`, suspends the agent.
    ///
    /// # Errors
    ///
    /// - `AppError::Domain` when the monitor may not suspend the agent.
    /// - `AppError::Internal` on persistence or audit failure.
    async fn execute(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        req: RespondToEgressDenialRequest,
    ) -> Result<EgressDenialResponse, AppError> {
        let suspended = suspension_if_enforced(
            EnforcementStores {
                delegation_store: self.ports.delegation_store.as_ref(),
                agent_store: self.ports.agent_store.as_ref(),
            },
            tenant,
            &req.agent_id,
            &req.delegation_id,
        )
        .await?;
        let response = match suspended {
            Some(_) => EgressDenialResponse::Suspended,
            None => EgressDenialResponse::Recorded,
        };
        let drift = AgentIntentDrift::observed_at_egress(**tenant, req.delegation_id).with_actor(
            ActorRef::Agent {
                id: req.agent_id,
                on_behalf_of: ActingFor::Itself,
            },
        );
        let events: Vec<DomainEvent> = std::iter::once(drift).chain(suspended).collect();
        auditor.dispatch(&events).await.or_internal()?;
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::agents::authority::intent::{
        DriftPolicy, DriftThreshold, IntentBinding, IntentDigest, IntentEnvelope, IntentStatement,
    };
    use ianua_domain::domains::agents::identity::status::AgentStatus;
    use ianua_domain::types::ActionClass;

    use super::*;
    use crate::test_support::agents::{FakeAgentStore, FakeDelegationStore, grant_to};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// A running agent, its delegation to read the reports, and what the
    /// response records.
    struct Fixture {
        agents: Arc<FakeAgentStore>,
        delegations: Arc<FakeDelegationStore>,
        sink: Arc<FakeEventDispatcher>,
        agent: AgentId,
        delegation: DelegationId,
    }

    fn fixture(policy: DriftPolicy) -> Fixture {
        let agent = AgentId::new();
        let delegations = Arc::new(FakeDelegationStore::empty());
        let binding = IntentBinding::new(
            IntentStatement::new("read the reports").unwrap(),
            IntentDigest::new([0; 32]),
            policy,
            IntentEnvelope::new([ActionClass::Read]),
        );
        let granted = grant_to(agent, Some(binding), None);
        block_on(delegations.save(&test_ctx().tenant(), &granted)).unwrap();
        Fixture {
            agents: Arc::new(FakeAgentStore::with_active(agent)),
            delegations,
            sink: Arc::new(FakeEventDispatcher::new()),
            agent,
            delegation: *granted.id(),
        }
    }

    impl Fixture {
        fn deny(&self) -> EgressDenialResponse {
            let use_case = RespondToEgressDenialUseCase::new(RespondToEgressDenialPorts {
                delegation_store: self.delegations.clone(),
                agent_store: self.agents.clone(),
            });
            block_on(use_case.execute(
                &test_ctx().tenant(),
                &test_auditor(self.sink.clone()),
                RespondToEgressDenialRequest {
                    agent_id: self.agent,
                    delegation_id: self.delegation,
                },
            ))
            .unwrap()
        }

        fn status(&self) -> AgentStatus {
            self.agents.find_by_id_direct(&self.agent).unwrap().status()
        }

        fn recorded(&self) -> Vec<String> {
            self.sink.records.lock().unwrap().clone()
        }
    }

    /// Responding to an egress denial under enforced intent suspends the
    /// agent and records drift and suspension.
    #[test]
    fn under_enforce_the_agent_is_suspended() {
        let f = fixture(DriftPolicy::Enforce(DriftThreshold::DEFAULT));

        let response = f.deny();

        assert_eq!(response, EgressDenialResponse::Suspended);
        assert_eq!(f.status(), AgentStatus::Suspended);
        assert_eq!(
            f.recorded(),
            ["agents.intent_drift", "agents.agent_suspended"]
        );
    }

    /// Under `Warn`, the refused way out is recorded as drift and the agent
    /// keeps running.
    #[test]
    fn under_warn_it_is_recorded_and_the_agent_keeps_running() {
        let f = fixture(DriftPolicy::Warn(DriftThreshold::DEFAULT));

        let response = f.deny();

        assert_eq!(response, EgressDenialResponse::Recorded);
        assert_eq!(f.status(), AgentStatus::Active);
        assert_eq!(f.recorded(), ["agents.intent_drift"]);
    }
}
