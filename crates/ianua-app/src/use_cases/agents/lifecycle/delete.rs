//! Delete agent: remove a revoked agent's record for good.

use std::sync::Arc;

use ianua_domain::domains::agents::identity::control::AgentControl;
use ianua_domain::domains::authorization::permission::AgentAction;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::AgentId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::agents::AgentStore;
use crate::use_case::Command;
use crate::use_cases::agents::lookup::{AgentReach, owned_agent};

/// The ports [`DeleteAgentUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct DeleteAgentPorts {
    /// Loads and deletes agents.
    pub agent_store: Arc<dyn AgentStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Deletes one revoked agent of the caller's tenant.
pub struct DeleteAgentUseCase {
    ports: DeleteAgentPorts,
}

impl DeleteAgentUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: DeleteAgentPorts) -> Self {
        Self { ports }
    }
}

impl Command for DeleteAgentUseCase {
    type Caller = CallerContext;
    type Input = AgentId;
    type Output = Result<(), AppError>;

    /// Deletes the agent, which must already be revoked so every key and
    /// delegation it held is dead. Everything stored against it, such as
    /// its credentials, delegations, runs and approvals, goes with it.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::NotFound` when the tenant has no such agent, or the
    ///   caller neither owns it nor may delete agents, so that an agent of
    ///   someone else's answers as one that does not exist.
    /// - `AppError::Domain` when the agent is not revoked.
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
        agent.delete(&control).map_err(AppError::from_domain)?;
        self.ports
            .agent_store
            .delete(&tenant, &agent_id)
            .await
            .or_internal()?;
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
    use crate::test_support::agents::{FakeAgentStore, caller_person};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    fn callers_agent_in(status: AgentStatus) -> (AgentId, Arc<FakeAgentStore>) {
        let id = AgentId::new();
        let store = Arc::new(FakeAgentStore::empty());
        store.add_owned(id, caller_person(), status);
        (id, store)
    }

    fn delete(
        store: &Arc<FakeAgentStore>,
        authorities: FakeTenantAuthorities,
        sink: &Arc<FakeEventDispatcher>,
        id: AgentId,
    ) -> Result<(), AppError> {
        let use_case = DeleteAgentUseCase::new(DeleteAgentPorts {
            agent_store: store.clone(),
            tenant_authorities: Arc::new(authorities),
        });
        block_on(use_case.execute(&test_ctx(), &test_auditor(sink.clone()), id))
    }

    /// Ann deletes her revoked agent. Its record is gone and the delete is
    /// recorded under its name.
    #[test]
    fn a_revoked_agent_is_deleted_and_recorded() {
        let (id, store) = callers_agent_in(AgentStatus::Revoked);
        let sink = Arc::new(FakeEventDispatcher::new());

        delete(&store, FakeTenantAuthorities::holding(&[]), &sink, id).unwrap();

        assert_eq!(store.count(), 0);
        assert_eq!(
            sink.records.lock().unwrap().as_slice(),
            ["agents.agent_deleted"]
        );
        assert_eq!(
            sink.label_of("agents.agent_deleted", "agent").as_deref(),
            Some("fake-agent")
        );
    }

    /// Ann deletes her agent while it is still active. She is refused: an
    /// agent is revoked first, so nothing it held outlives its record.
    #[test]
    fn an_active_agent_is_kept() {
        let (id, store) = callers_agent_in(AgentStatus::Active);

        let result = delete(
            &store,
            FakeTenantAuthorities::holding(&[]),
            &Arc::new(FakeEventDispatcher::new()),
            id,
        );

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert_eq!(store.count(), 1);
    }

    /// A viewer cannot delete another person's revoked agent; it appears
    /// missing to the caller but remains stored.
    #[test]
    fn a_viewer_cannot_delete_anothers_agent() {
        let id = AgentId::new();
        let store = Arc::new(FakeAgentStore::empty());
        store.add_with_status(id, AgentStatus::Revoked);
        let sam = FakeTenantAuthorities::holding(&[SystemPermission::Agents(AgentAction::View)]);

        let result = delete(&store, sam, &Arc::new(FakeEventDispatcher::new()), id);

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(store.count(), 1);
    }

    /// A signed-out owner cannot delete their revoked agent, which remains stored.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let (id, store) = callers_agent_in(AgentStatus::Revoked);

        let result = delete(
            &store,
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
            &Arc::new(FakeEventDispatcher::new()),
            id,
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(store.count(), 1);
    }

    /// Ann deletes an agent the tenant does not have. It is not found.
    #[test]
    fn an_unknown_agent_is_not_found() {
        let result = delete(
            &Arc::new(FakeAgentStore::empty()),
            FakeTenantAuthorities::holding_everything(),
            &Arc::new(FakeEventDispatcher::new()),
            AgentId::new(),
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }
}
