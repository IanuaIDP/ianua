//! Set attestation policy: say which platform attestations an agent proves
//! itself with, so it can bootstrap with no secret of its own.

use std::sync::Arc;

use ianua_domain::domains::agents::identity::agent::AgentIdentity;
use ianua_domain::domains::agents::identity::attestation::AttestationPolicy;
use ianua_domain::domains::agents::identity::control::AgentControl;
use ianua_domain::domains::authorization::permission::AgentAction;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::AgentId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::agents::{AgentStore, AgentVersion};
use crate::use_case::Command;
use crate::use_cases::agents::lookup::{AgentReach, owned_agent};

/// Request to set an agent's attestation policy.
pub struct SetAttestationPolicyRequest {
    /// The agent whose policy is set.
    pub agent_id: AgentId,
    /// Which methods and origins are trusted, and how often it re-attests.
    pub policy: AttestationPolicy,
}

/// The ports [`SetAttestationPolicyUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct SetAttestationPolicyPorts {
    /// Loads and keeps agents.
    pub agent_store: Arc<dyn AgentStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Makes an agent prove itself by attesting.
pub struct SetAttestationPolicyUseCase {
    ports: SetAttestationPolicyPorts,
}

impl SetAttestationPolicyUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: SetAttestationPolicyPorts) -> Self {
        Self { ports }
    }
}

impl Command for SetAttestationPolicyUseCase {
    type Caller = CallerContext;
    type Input = SetAttestationPolicyRequest;
    type Output = Result<AgentIdentity<ResolvedTenant>, AppError>;

    /// Sets the agent's attestation policy, replacing any before it, and
    /// returns the agent, saved and then recorded.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::NotFound` if the agent doesn't exist, or the caller
    ///   neither owns it nor may update agents, so that an agent of someone
    ///   else's answers as one that does not exist.
    /// - `AppError::Conflict` when the agent changed since it was read.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        req: SetAttestationPolicyRequest,
    ) -> Result<AgentIdentity<ResolvedTenant>, AppError> {
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let control = AgentControl::new(&authority);
        let store = self.ports.agent_store.as_ref();
        let reach = AgentReach::Acting(AgentAction::Update);
        let mut agent = owned_agent(store, &tenant, &req.agent_id, &control, reach).await?;
        let read = AgentVersion::of(&agent);
        agent
            .trust_attestation(&control, req.policy)
            .map_err(AppError::from_domain)?;
        self.ports
            .agent_store
            .save_unchanged_since(&tenant, &agent, read)
            .await
            .map_err(AppError::from_domain)?;
        auditor
            .dispatch_by(&ctx.actor(), agent.take_events(&tenant))
            .await
            .or_internal()?;
        Ok(agent)
    }
}

#[cfg(test)]
mod tests {

    use ianua_domain::domains::authorization::permission::SystemPermission;
    use ianua_domain::types::Human;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::agents::{
        FakeAgentStore, agent_row, caller_person, someone_else, spiffe_policy,
    };
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

        fn set(
            &self,
            people: FakeTenantAuthorities,
            agent_id: AgentId,
        ) -> Result<AgentIdentity<ResolvedTenant>, AppError> {
            let use_case = SetAttestationPolicyUseCase::new(SetAttestationPolicyPorts {
                agent_store: self.agents.clone(),
                tenant_authorities: Arc::new(people),
            });
            block_on(use_case.execute(
                &test_ctx(),
                &test_auditor(self.sink.clone()),
                SetAttestationPolicyRequest {
                    agent_id,
                    policy: spiffe_policy(),
                },
            ))
        }

        fn stored_policy(&self) -> Option<AttestationPolicy> {
            self.agents
                .find_by_id_direct(&self.agent)
                .unwrap()
                .attestation_policy()
                .cloned()
        }
    }

    /// Ann moves her agent onto attestation from her cluster. The policy is
    /// kept, and the change is recorded.
    #[test]
    fn the_owner_sets_the_policy_and_it_is_recorded() {
        let bench = Bench::owned_by(caller_person());

        let updated = bench
            .set(FakeTenantAuthorities::holding(&[]), bench.agent)
            .unwrap();

        assert_eq!(updated.attestation_policy(), Some(&spiffe_policy()));
        assert_eq!(bench.stored_policy(), Some(spiffe_policy()));
        assert_eq!(
            bench.sink.records.lock().unwrap().as_slice(),
            ["agents.agent_updated"]
        );
    }

    /// Bob may update agents and sets the policy of Ann's agent.
    #[test]
    fn someone_allowed_to_update_agents_sets_the_policy() {
        let bench = Bench::owned_by(someone_else());

        let result = bench.set(
            FakeTenantAuthorities::holding(&[SystemPermission::Agents(AgentAction::Update)]),
            bench.agent,
        );

        assert!(result.is_ok());
        assert_eq!(bench.stored_policy(), Some(spiffe_policy()));
    }

    /// A viewer cannot set another person's agent attestation policy;
    /// the agent appears missing and its stored policy remains absent.
    #[test]
    fn a_caller_who_neither_owns_nor_may_update_the_agent_is_refused() {
        let bench = Bench::owned_by(someone_else());

        let result = bench.set(
            FakeTenantAuthorities::holding(&[SystemPermission::Agents(AgentAction::View)]),
            bench.agent,
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(bench.stored_policy(), None);
    }

    /// A signed-out caller cannot set an attestation policy on their agent.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let bench = Bench::owned_by(caller_person());

        let result = bench.set(
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
            bench.agent,
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(bench.stored_policy(), None);
    }

    /// Ann names an agent the tenant does not have. It is not found.
    #[test]
    fn an_unknown_agent_is_not_found() {
        let bench = Bench::owned_by(caller_person());

        let result = bench.set(FakeTenantAuthorities::holding_everything(), AgentId::new());

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }
}
