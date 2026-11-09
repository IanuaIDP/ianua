//! Register sighting: a person records that a sighted caller is one of the
//! tenant's agents.
//!
//! Someone allowed to manage agents creates the agent first, or picks one
//! already there, and ties the sighting to it, which puts the caller under
//! delegations like any agent. Only they deal with a sighting: Sam may
//! create agents, but marking a rogue agent as his own would drop it from
//! the list that shows it.

use std::sync::Arc;

use ianua_domain::domains::agents::identity::control::AgentControl;
use ianua_domain::domains::agents::identity::sighting::AgentSighting;
use ianua_domain::domains::authorization::permission::{AgentAction, SystemPermission};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{AgentId, AgentSightingId};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::agents::{AgentSightingStore, AgentStore};
use crate::services::lookup::existing_agent;
use crate::use_case::Command;
use crate::use_cases::agents::lookup::existing_sighting;

/// Which sighting is which agent.
pub struct RegisterRequest {
    /// The discovered caller record to associate with a registered identity.
    pub sighting_id: AgentSightingId,
    /// The agent the sighted caller is.
    pub agent_id: AgentId,
}

/// The ports [`RegisterUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RegisterPorts {
    /// Loads and keeps the sighting.
    pub sighting_store: Arc<dyn AgentSightingStore>,
    /// Loads the agent it is tied to.
    pub agent_store: Arc<dyn AgentStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Ties sightings to the agents they are.
pub struct RegisterUseCase {
    ports: RegisterPorts,
}

impl RegisterUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: RegisterPorts) -> Self {
        Self { ports }
    }
}

impl Command for RegisterUseCase {
    type Caller = CallerContext;
    type Input = RegisterRequest;
    type Output = Result<AgentSighting<ResolvedTenant>, AppError>;

    /// Ties `request.sighting_id` to `request.agent_id`, records
    /// `agents.agent_sighting_registered`, and returns the sighting.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not manage agents, before
    ///   any sighting or agent is read.
    /// - `AppError::NotFound` when the tenant has no such sighting or
    ///   agent.
    /// - `AppError::Domain` when the sighting is registered already.
    /// - `AppError::Internal` on persistence or audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: RegisterRequest,
    ) -> Result<AgentSighting<ResolvedTenant>, AppError> {
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        authority
            .ensure_holds(SystemPermission::Agents(AgentAction::Manage))
            .map_err(AppError::from_domain)?;
        let store = self.ports.sighting_store.as_ref();
        let mut sighting = existing_sighting(store, &tenant, &request.sighting_id).await?;
        let agent =
            existing_agent(self.ports.agent_store.as_ref(), &tenant, &request.agent_id).await?;
        sighting
            .register(&AgentControl::new(&authority), &agent)
            .map_err(AppError::from_domain)?;
        store.save(&tenant, &sighting).await.or_internal()?;
        auditor
            .dispatch_by(&ctx.actor(), sighting.take_events(&tenant))
            .await
            .or_internal()?;
        Ok(sighting)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::agents::identity::sighting::SightingState;
    use ianua_domain::domains::authorization::permission::{AgentAction, SystemPermission};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::agents::{FakeAgentSightingStore, FakeAgentStore, sighted_client};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// A sighting of client `cli_42`, an agent it may be, and the stores
    /// they are kept in.
    struct Scene {
        sighting: AgentSightingId,
        agent: AgentId,
        sightings: Arc<FakeAgentSightingStore>,
        agents: Arc<FakeAgentStore>,
        sink: Arc<FakeEventDispatcher>,
    }

    impl Scene {
        fn new() -> Self {
            let sighting = sighted_client("cli_42", "invoice-bot");
            let agent = AgentId::new();
            Self {
                sighting: *sighting.id(),
                agent,
                sightings: Arc::new(FakeAgentSightingStore::holding([sighting])),
                agents: Arc::new(FakeAgentStore::with_active(agent)),
                sink: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn ports(&self) -> RegisterPorts {
            RegisterPorts {
                sighting_store: self.sightings.clone(),
                agent_store: self.agents.clone(),
                ..RegisterPorts::fakes()
            }
        }

        fn register_with(
            &self,
            ports: RegisterPorts,
            agent_id: AgentId,
        ) -> Result<AgentSighting<ResolvedTenant>, AppError> {
            block_on(RegisterUseCase::new(ports).execute(
                &test_ctx(),
                &test_auditor(self.sink.clone()),
                RegisterRequest {
                    sighting_id: self.sighting,
                    agent_id,
                },
            ))
        }

        fn state(&self) -> SightingState {
            self.sightings.all()[0].state()
        }
    }

    /// Ann ties the sighting of `cli_42` to the agent she registered for
    /// it. It is kept registered as that agent, and recorded.
    #[test]
    fn a_sighting_is_registered_as_an_agent() {
        let scene = Scene::new();

        scene.register_with(scene.ports(), scene.agent).unwrap();

        assert!(matches!(
            scene.state(),
            SightingState::Registered { agent_id, .. } if agent_id == scene.agent
        ));
        assert_eq!(
            scene.sink.records.lock().unwrap().as_slice(),
            ["agents.agent_sighting_registered"]
        );
    }

    /// Ann ties the sighting to an agent the tenant does not have. It is
    /// not found and the sighting stays unreviewed.
    #[test]
    fn an_unknown_agent_is_not_found() {
        let scene = Scene::new();

        let result = scene.register_with(scene.ports(), AgentId::new());

        assert!(matches!(result, Err(AppError::NotFound(_))), "{result:?}");
        assert_eq!(scene.state(), SightingState::Unreviewed);
    }

    /// The create right alone cannot associate a sighting with an agent;
    /// the sighting remains unreviewed and no registration is recorded.
    #[test]
    fn a_caller_who_may_not_manage_agents_is_refused() {
        let scene = Scene::new();
        let ports = RegisterPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
                SystemPermission::Agents(AgentAction::Create),
            ])),
            ..scene.ports()
        };

        let result = scene.register_with(ports, scene.agent);

        assert!(matches!(result, Err(AppError::Forbidden(_))), "{result:?}");
        assert_eq!(scene.state(), SightingState::Unreviewed);
        assert!(scene.sink.records.lock().unwrap().is_empty());
    }

    /// A signed-out caller cannot register a sighting, which remains unreviewed.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let scene = Scene::new();
        let ports = RegisterPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..scene.ports()
        };

        let result = scene.register_with(ports, scene.agent);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(scene.state(), SightingState::Unreviewed);
    }
}
