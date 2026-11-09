//! Require re-attestation: make an agent prove again what it is.
//!
//! From the next request the proxy refuses every token the agent presents
//! until it bootstraps again with a fresh platform attestation. Unlike
//! containment this leaves the agent's delegations in place: it earns them
//! back by proving again where it runs.

use std::sync::Arc;

use ianua_domain::domains::agents::identity::control::AgentControl;
use ianua_domain::domains::authorization::permission::AgentAction;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::AgentId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::agents::{AgentStore, AgentVersion};
use crate::use_case::Command;
use crate::use_cases::agents::lookup::{AgentReach, owned_agent};

/// The ports [`RequireReattestationUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RequireReattestationPorts {
    /// Loads and keeps the agent.
    pub agent_store: Arc<dyn AgentStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Holds an agent until it attests again.
pub struct RequireReattestationUseCase {
    ports: RequireReattestationPorts,
}

impl RequireReattestationUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: RequireReattestationPorts) -> Self {
        Self { ports }
    }
}

impl Command for RequireReattestationUseCase {
    type Caller = CallerContext;
    type Input = AgentId;
    type Output = Result<(), AppError>;

    /// Holds the agent until it re-attests, saved and then recorded. Asking
    /// again only moves the time it was required.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::NotFound` if the agent doesn't exist, or the caller
    ///   neither owns it nor may update agents, so that an agent of someone
    ///   else's answers as one that does not exist.
    /// - `AppError::Conflict` when the agent changed since it was read, as
    ///   when it bootstrapped meanwhile.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        agent_id: AgentId,
    ) -> Result<(), AppError> {
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let control = AgentControl::new(&authority);
        let store = self.ports.agent_store.as_ref();
        let reach = AgentReach::Acting(AgentAction::Update);
        let mut agent = owned_agent(store, &tenant, &agent_id, &control, reach).await?;
        let read = AgentVersion::of(&agent);
        agent
            .require_reattestation(&control)
            .map_err(AppError::from_domain)?;
        self.ports
            .agent_store
            .save_unchanged_since(&tenant, &agent, read)
            .await
            .map_err(AppError::from_domain)?;
        auditor
            .dispatch_by(&ctx.actor(), agent.take_events(&tenant))
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::agents::identity::agent::AgentIdentity;
    use ianua_domain::domains::authorization::permission::SystemPermission;
    use ianua_domain::types::Human;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::agents::{FakeAgentStore, agent_row, caller_person, someone_else};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    struct Bench {
        agent: AgentId,
        agents: Arc<FakeAgentStore>,
        sink: Arc<FakeEventDispatcher>,
    }

    impl Bench {
        fn owned_by(owner: Human) -> Self {
            let agent = AgentId::new();
            let agents = Arc::new(FakeAgentStore::empty());
            block_on(agents.save(
                &test_ctx().tenant(),
                &AgentIdentity::reconstitute(agent_row(agent, owner)).unwrap(),
            ))
            .unwrap();
            Self {
                agent,
                agents,
                sink: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn require(&self, people: FakeTenantAuthorities, agent: AgentId) -> Result<(), AppError> {
            let use_case = RequireReattestationUseCase::new(RequireReattestationPorts {
                agent_store: self.agents.clone(),
                tenant_authorities: Arc::new(people),
            });
            block_on(use_case.execute(&test_ctx(), &test_auditor(self.sink.clone()), agent))
        }

        fn held(&self) -> bool {
            self.agents
                .find_by_id_direct(&self.agent)
                .unwrap()
                .reattestation_required()
        }
    }

    /// Ann suspects where her agent runs and makes it re-attest. It is held
    /// until it does, and the hold is recorded.
    #[test]
    fn the_owner_holds_the_agent_and_it_is_recorded() {
        let bench = Bench::owned_by(caller_person());

        bench
            .require(FakeTenantAuthorities::holding(&[]), bench.agent)
            .unwrap();

        assert!(bench.held());
        assert_eq!(
            bench.sink.records.lock().unwrap().as_slice(),
            ["agents.reattestation_required"]
        );
    }

    /// Bob may update agents and holds Ann's agent until it re-attests.
    #[test]
    fn someone_allowed_to_update_agents_holds_the_agent() {
        let bench = Bench::owned_by(someone_else());

        bench
            .require(
                FakeTenantAuthorities::holding(&[SystemPermission::Agents(AgentAction::Update)]),
                bench.agent,
            )
            .unwrap();

        assert!(bench.held());
    }

    /// A viewer cannot require another person's agent to re-attest; the
    /// agent appears missing and no hold or audit record is stored.
    #[test]
    fn a_caller_who_neither_owns_nor_may_update_the_agent_is_refused() {
        let bench = Bench::owned_by(someone_else());

        let result = bench.require(
            FakeTenantAuthorities::holding(&[SystemPermission::Agents(AgentAction::View)]),
            bench.agent,
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(!bench.held());
        assert!(bench.sink.records.lock().unwrap().is_empty());
    }

    /// A signed-out caller cannot impose a re-attestation hold on their agent.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let bench = Bench::owned_by(caller_person());

        let result = bench.require(
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
            bench.agent,
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert!(!bench.held());
    }

    /// Ann names an agent the tenant does not have. It is not found.
    #[test]
    fn an_unknown_agent_is_not_found() {
        let bench = Bench::owned_by(caller_person());

        let result = bench.require(FakeTenantAuthorities::holding_everything(), AgentId::new());

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }
}
