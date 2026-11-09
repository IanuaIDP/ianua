//! Revoke agent: retire an agent for good.

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

/// The ports [`RevokeAgentUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RevokeAgentPorts {
    /// Loads and saves agents.
    pub agent_store: Arc<dyn AgentStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Revokes one agent of the caller's tenant, for good.
pub struct RevokeAgentUseCase {
    ports: RevokeAgentPorts,
}

impl RevokeAgentUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: RevokeAgentPorts) -> Self {
        Self { ports }
    }
}

impl Command for RevokeAgentUseCase {
    type Caller = CallerContext;
    type Input = AgentId;
    type Output = Result<(), AppError>;

    /// Revokes the agent. Nothing brings it back.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::NotFound` when the tenant has no such agent, or the
    ///   caller neither owns it nor may delete agents, so that an agent of
    ///   someone else's answers as one that does not exist.
    /// - `AppError::Domain` when the agent is already revoked.
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
        let reach = AgentReach::Acting(AgentAction::Delete);
        let mut agent = owned_agent(store, &tenant, &agent_id, &control, reach).await?;
        let read = AgentVersion::of(&agent);
        agent.revoke(&control).map_err(AppError::from_domain)?;
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

    fn revoke(
        store: &Arc<FakeAgentStore>,
        authorities: FakeTenantAuthorities,
        sink: &Arc<FakeEventDispatcher>,
        id: AgentId,
    ) -> Result<(), AppError> {
        let use_case = RevokeAgentUseCase::new(RevokeAgentPorts {
            agent_store: store.clone(),
            tenant_authorities: Arc::new(authorities),
        });
        block_on(use_case.execute(&test_ctx(), &test_auditor(sink.clone()), id))
    }

    fn status_of(store: &FakeAgentStore, id: &AgentId) -> AgentStatus {
        store.find_by_id_direct(id).unwrap().status()
    }

    /// Ann revokes her own agent. It is revoked and the revoke is recorded.
    #[test]
    fn the_owner_revokes_their_agent_and_it_is_recorded() {
        let id = AgentId::new();
        let store = Arc::new(callers_agent(id));
        let sink = Arc::new(FakeEventDispatcher::new());

        revoke(&store, FakeTenantAuthorities::holding(&[]), &sink, id).unwrap();

        assert_eq!(status_of(&store, &id), AgentStatus::Revoked);
        assert_eq!(
            sink.records.lock().unwrap().as_slice(),
            ["agents.agent_revoked"]
        );
    }

    /// Bob, who may delete agents, revokes Ann's leaked agent. It is
    /// revoked.
    #[test]
    fn someone_allowed_to_delete_agents_revokes_anothers() {
        let id = AgentId::new();
        let store = Arc::new(FakeAgentStore::with_active(id));
        let bob = FakeTenantAuthorities::holding(&[SystemPermission::Agents(AgentAction::Delete)]);

        revoke(&store, bob, &Arc::new(FakeEventDispatcher::new()), id).unwrap();

        assert_eq!(status_of(&store, &id), AgentStatus::Revoked);
    }

    /// The update right alone cannot revoke another person's agent;
    /// the agent appears missing and stays active.
    #[test]
    fn someone_who_may_only_update_cannot_revoke_anothers() {
        let id = AgentId::new();
        let store = Arc::new(FakeAgentStore::with_active(id));
        let sam = FakeTenantAuthorities::holding(&[SystemPermission::Agents(AgentAction::Update)]);

        let result = revoke(&store, sam, &Arc::new(FakeEventDispatcher::new()), id);

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(status_of(&store, &id), AgentStatus::Active);
    }

    /// A signed-out owner cannot revoke their agent, which stays active.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let id = AgentId::new();
        let store = Arc::new(callers_agent(id));

        let result = revoke(
            &store,
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
            &Arc::new(FakeEventDispatcher::new()),
            id,
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(status_of(&store, &id), AgentStatus::Active);
    }

    /// Ann revokes her agent a second time. The move is refused.
    #[test]
    fn revoking_twice_is_refused() {
        let id = AgentId::new();
        let store = Arc::new(callers_agent(id));
        let sink = Arc::new(FakeEventDispatcher::new());
        revoke(&store, FakeTenantAuthorities::holding(&[]), &sink, id).unwrap();

        let second = revoke(&store, FakeTenantAuthorities::holding(&[]), &sink, id);

        assert!(matches!(second, Err(AppError::Domain(_))));
    }
}
