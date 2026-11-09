//! Suspend agent: stop an agent until a person resumes it.

use std::sync::Arc;

use ianua_domain::domains::agents::identity::agent::SuspendedBy;
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

/// The ports [`SuspendAgentUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct SuspendAgentPorts {
    /// Loads and saves agents.
    pub agent_store: Arc<dyn AgentStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Suspends one agent of the caller's tenant.
pub struct SuspendAgentUseCase {
    ports: SuspendAgentPorts,
}

impl SuspendAgentUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: SuspendAgentPorts) -> Self {
        Self { ports }
    }
}

impl Command for SuspendAgentUseCase {
    type Caller = CallerContext;
    type Input = AgentId;
    type Output = Result<(), AppError>;

    /// Suspends the agent. None of its delegations work while it is
    /// suspended.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::NotFound` when the tenant has no such agent, or the
    ///   caller neither owns it nor may update agents, so that an agent of
    ///   someone else's answers as one that does not exist.
    /// - `AppError::Domain` when the agent is revoked or already suspended.
    /// - `AppError::Conflict` when the agent changed since it was read.
    /// - `AppError::Internal` on persistence or audit failure.
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
            .suspend(SuspendedBy::Person(control))
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
    use ianua_domain::domains::agents::identity::status::AgentStatus;
    use ianua_domain::domains::authorization::permission::SystemPermission;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::agents::{FakeAgentStore, callers_agent};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    fn suspend(
        store: &Arc<FakeAgentStore>,
        authorities: FakeTenantAuthorities,
        sink: &Arc<FakeEventDispatcher>,
        id: AgentId,
    ) -> Result<(), AppError> {
        let use_case = SuspendAgentUseCase::new(SuspendAgentPorts {
            agent_store: store.clone(),
            tenant_authorities: Arc::new(authorities),
        });
        block_on(use_case.execute(&test_ctx(), &test_auditor(sink.clone()), id))
    }

    fn status_of(store: &FakeAgentStore, id: &AgentId) -> AgentStatus {
        store.find_by_id_direct(id).unwrap().status()
    }

    /// Ann suspends her own agent, holding no agent rights. It stops, and the
    /// suspension is recorded.
    #[test]
    fn the_owner_suspends_their_agent_and_it_is_recorded() {
        let id = AgentId::new();
        let store = Arc::new(callers_agent(id));
        let sink = Arc::new(FakeEventDispatcher::new());

        suspend(&store, FakeTenantAuthorities::holding(&[]), &sink, id).unwrap();

        assert_eq!(status_of(&store, &id), AgentStatus::Suspended);
        assert_eq!(
            sink.records.lock().unwrap().as_slice(),
            ["agents.agent_suspended"]
        );
    }

    /// Bob, who may update agents, suspends Ann's agent during an incident.
    /// It stops.
    #[test]
    fn someone_allowed_to_update_agents_suspends_anothers() {
        let id = AgentId::new();
        let store = Arc::new(FakeAgentStore::with_active(id));
        let bob = FakeTenantAuthorities::holding(&[SystemPermission::Agents(AgentAction::Update)]);

        suspend(&store, bob, &Arc::new(FakeEventDispatcher::new()), id).unwrap();

        assert_eq!(status_of(&store, &id), AgentStatus::Suspended);
    }

    /// A viewer cannot suspend another person's agent; it appears missing,
    /// stays active, and produces no suspension record.
    #[test]
    fn a_viewer_cannot_suspend_anothers_agent() {
        let id = AgentId::new();
        let store = Arc::new(FakeAgentStore::with_active(id));
        let sam = FakeTenantAuthorities::holding(&[SystemPermission::Agents(AgentAction::View)]);
        let sink = Arc::new(FakeEventDispatcher::new());

        let result = suspend(&store, sam, &sink, id);

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(status_of(&store, &id), AgentStatus::Active);
        assert!(sink.records.lock().unwrap().is_empty());
    }

    /// A signed-out owner cannot suspend their agent, which stays active.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let id = AgentId::new();
        let store = Arc::new(callers_agent(id));

        let result = suspend(
            &store,
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
            &Arc::new(FakeEventDispatcher::new()),
            id,
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(status_of(&store, &id), AgentStatus::Active);
    }

    /// Ann suspends an agent the tenant does not have. It is not found.
    #[test]
    fn an_unknown_agent_is_not_found() {
        let result = suspend(
            &Arc::new(FakeAgentStore::empty()),
            FakeTenantAuthorities::holding_everything(),
            &Arc::new(FakeEventDispatcher::new()),
            AgentId::new(),
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Ann suspends an agent that is already suspended. The move is refused.
    #[test]
    fn suspending_twice_is_refused() {
        let id = AgentId::new();
        let store = Arc::new(FakeAgentStore::empty());
        store.add_with_status(id, AgentStatus::Suspended);

        let result = suspend(
            &store,
            FakeTenantAuthorities::holding_everything(),
            &Arc::new(FakeEventDispatcher::new()),
            id,
        );

        assert!(matches!(result, Err(AppError::Domain(_))));
    }
}
