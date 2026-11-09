//! Suspend all agents: the tenant-wide stop.
//!
//! Containing an agent stops one agent for good. When a tenant cannot tell
//! which of its agents has gone wrong, it stops all of them at once and
//! looks. This suspends every active agent in the tenant: the proxy refuses
//! their tokens on the next request, and their runs halt before their next
//! step. Unlike containment it can be undone, one agent at a time, once each
//! is known to be safe.
//!
//! A suspension revokes nothing: the agents keep their credentials and
//! delegations, which a resume gives back to use. So the stop is one status
//! change in storage, and one record of it.

use std::sync::Arc;

use ianua_domain::domains::agents::identity::control::AgentControl;
use ianua_domain::domains::agents::identity::fleet_suspension::FleetSuspension;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::agents::AgentStore;
use crate::use_case::Command;

/// The ports [`SuspendAllAgentsUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct SuspendAllAgentsPorts {
    /// Suspends the tenant's active agents.
    pub agent_store: Arc<dyn AgentStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Suspends every active agent of the caller's tenant.
pub struct SuspendAllAgentsUseCase {
    ports: SuspendAllAgentsPorts,
}

impl SuspendAllAgentsUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: SuspendAllAgentsPorts) -> Self {
        Self { ports }
    }
}

impl Command for SuspendAllAgentsUseCase {
    type Caller = CallerContext;
    type Input = ();
    type Output = Result<u32, AppError>;

    /// Suspends every active agent in the caller's tenant in one step,
    /// records the stop once with the count, and returns how many were
    /// stopped. Agents already suspended or revoked are left as they are.
    ///
    /// The stop is one statement in the request's unit of work: it stops
    /// every running agent or, on failure, none, and an agent created while
    /// it runs is either stopped with the rest or created after it.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not update agents.
    /// - `AppError::Internal` on persistence or dispatch failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        (): (),
    ) -> Result<u32, AppError> {
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let mut stop = FleetSuspension::<ResolvedTenant>::ordered(&AgentControl::new(&authority))
            .map_err(AppError::from_domain)?;
        let count = self
            .ports
            .agent_store
            .suspend_every_active(&tenant)
            .await
            .or_internal()?;
        stop.record_suspensions(count);
        auditor
            .dispatch_by(&ctx.actor(), stop.take_events(&tenant))
            .await
            .or_internal()?;
        Ok(u32::try_from(count).unwrap_or(u32::MAX))
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::agents::identity::status::AgentStatus;
    use ianua_domain::domains::authorization::permission::{AgentAction, SystemPermission};
    use ianua_domain::types::AgentId;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::agents::FakeAgentStore;
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    fn updater() -> FakeTenantAuthorities {
        FakeTenantAuthorities::holding(&[SystemPermission::Agents(AgentAction::Update)])
    }

    fn stop_all(
        store: &Arc<FakeAgentStore>,
        authorities: FakeTenantAuthorities,
        sink: &Arc<FakeEventDispatcher>,
    ) -> Result<u32, AppError> {
        let use_case = SuspendAllAgentsUseCase::new(SuspendAllAgentsPorts {
            agent_store: store.clone(),
            tenant_authorities: Arc::new(authorities),
        });
        block_on(use_case.execute(&test_ctx(), &test_auditor(sink.clone()), ()))
    }

    /// Ann, who may update agents, stops every agent while the tenant looks
    /// into a leak. All three stop, and the stop is recorded once, not once
    /// per agent.
    #[test]
    fn every_active_agent_is_stopped_and_the_stop_is_recorded_once() {
        let store = Arc::new(FakeAgentStore::empty());
        let ids = [AgentId::new(), AgentId::new(), AgentId::new()];
        ids.iter().for_each(|id| store.add_active(*id));
        let sink = Arc::new(FakeEventDispatcher::new());

        let stopped = stop_all(&store, updater(), &sink).unwrap();

        assert_eq!(stopped, 3);
        assert!(
            ids.iter()
                .all(|id| !store.find_by_id_direct(id).unwrap().is_active())
        );
        assert_eq!(
            sink.records.lock().unwrap().as_slice(),
            ["agents.all_agents_suspended"]
        );
    }

    /// One agent is already revoked when Ann stops them all. It stays
    /// revoked, and only the running one is counted.
    #[test]
    fn an_agent_already_stopped_is_left_alone() {
        let store = Arc::new(FakeAgentStore::empty());
        let revoked = AgentId::new();
        store.add_with_status(revoked, AgentStatus::Revoked);
        store.add_active(AgentId::new());

        let stopped = stop_all(&store, updater(), &Arc::new(FakeEventDispatcher::new())).unwrap();

        assert_eq!(stopped, 1);
        assert_eq!(
            store.find_by_id_direct(&revoked).unwrap().status(),
            AgentStatus::Revoked
        );
    }

    /// Ann stops every agent of a tenant with none. Nothing is stopped, and
    /// the attempt is still on the record.
    #[test]
    fn a_tenant_with_no_agents_stops_none() {
        let sink = Arc::new(FakeEventDispatcher::new());

        let stopped = stop_all(&Arc::new(FakeAgentStore::empty()), updater(), &sink).unwrap();

        assert_eq!(stopped, 0);
        assert_eq!(sink.records.lock().unwrap().len(), 1);
    }

    /// A viewer cannot suspend the fleet; the stored agent stays active
    /// and no fleet suspension is recorded.
    #[test]
    fn a_caller_who_may_not_update_agents_is_refused() {
        let id = AgentId::new();
        let store = Arc::new(FakeAgentStore::with_active(id));
        let sam = FakeTenantAuthorities::holding(&[SystemPermission::Agents(AgentAction::View)]);
        let sink = Arc::new(FakeEventDispatcher::new());

        let result = stop_all(&store, sam, &sink);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(store.find_by_id_direct(&id).unwrap().is_active());
        assert!(sink.records.lock().unwrap().is_empty());
    }

    /// A signed-out caller cannot suspend the fleet, leaving its agent active.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let id = AgentId::new();
        let store = Arc::new(FakeAgentStore::with_active(id));

        let result = stop_all(
            &store,
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
            &Arc::new(FakeEventDispatcher::new()),
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert!(store.find_by_id_direct(&id).unwrap().is_active());
    }
}
