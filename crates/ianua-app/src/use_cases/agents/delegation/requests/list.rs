//! List delegation requests: the delegations agents asked for, either of
//! the caller or by one agent.
//!
//! A person sees what agents asked of them, so they can answer. An agent's
//! owner, or someone allowed to view agents, sees everything that agent
//! asked of anyone.

use std::sync::Arc;

use ianua_domain::domains::agents::authority::delegation_request::DelegationRequest;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::AgentId;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::agents::{AgentStore, DelegationRequestStore};
use crate::use_case::Query;
use crate::use_cases::agents::delegation::reading::viewing::viewed_agent;

/// Whose requests to list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestsOf {
    /// Those agents made of the caller.
    AskedOfCaller,
    /// Those this agent made, of anyone.
    Agent(AgentId),
}

/// The ports [`ListRequestsUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ListRequestsPorts {
    /// Loads the requests.
    pub request_store: Arc<dyn DelegationRequestStore>,
    /// Loads the agent whose requests are listed.
    pub agent_store: Arc<dyn AgentStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Lists delegation requests.
pub struct ListRequestsUseCase {
    ports: ListRequestsPorts,
}

impl ListRequestsUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: ListRequestsPorts) -> Self {
        Self { ports }
    }
}

impl Query for ListRequestsUseCase {
    type Caller = CallerContext;
    type Input = RequestsOf;
    type Output = Result<Vec<DelegationRequest<ResolvedTenant>>, AppError>;

    /// The requests `of` names, newest first, answered or not.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::NotFound` when the tenant has no such agent, or the
    ///   caller neither owns it nor may view agents, so that an agent of
    ///   someone else's answers as one that does not exist.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        of: RequestsOf,
    ) -> Result<Vec<DelegationRequest<ResolvedTenant>>, AppError> {
        let tenant = ctx.tenant();
        let store = self.ports.request_store.as_ref();
        let RequestsOf::Agent(agent_id) = of else {
            let authority = self.ports.tenant_authorities.authority(ctx).await?;
            let asked_of = authority.who().principal();
            return store.list_asked_of(&tenant, &asked_of).await.or_internal();
        };
        let agent = viewed_agent(
            self.ports.agent_store.as_ref(),
            self.ports.tenant_authorities.as_ref(),
            ctx,
            &agent_id,
        )
        .await?;
        store
            .list_for_agent(&tenant, agent.id())
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::agents::authority::capability::CapabilitySet;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::agents::{
        FakeAgentStore, FakeDelegationRequestStore, asked_request, caller_person, someone,
    };
    use crate::test_support::{block_on, test_ctx};

    /// An agent of Owen's that asked the caller once and Bob once.
    struct Scene {
        agent: AgentId,
        ports: ListRequestsPorts,
    }

    fn scene() -> Scene {
        let agent = AgentId::new();
        let agents = FakeAgentStore::empty();
        agents.add_owned_by(agent, someone("owen@example.test"));
        let stored = agents.find_by_id_direct(&agent).unwrap();
        let requests = FakeDelegationRequestStore::holding([
            asked_request(&stored, caller_person(), CapabilitySet::empty()),
            asked_request(&stored, someone("bob@example.test"), CapabilitySet::empty()),
        ]);
        Scene {
            agent,
            ports: ListRequestsPorts {
                request_store: Arc::new(requests),
                agent_store: Arc::new(agents),
                ..ListRequestsPorts::fakes()
            },
        }
    }

    fn list(
        ports: ListRequestsPorts,
        of: RequestsOf,
    ) -> Result<Vec<DelegationRequest<ResolvedTenant>>, AppError> {
        block_on(ListRequestsUseCase::new(ports).execute(&test_ctx(), of))
    }

    /// Ann lists what agents asked of her. She sees the one request made of
    /// her, and not Bob's.
    #[test]
    fn a_person_sees_the_requests_made_of_them() {
        let scene = scene();

        let listed = list(scene.ports, RequestsOf::AskedOfCaller).unwrap();

        assert_eq!(listed.len(), 1);
        assert_eq!(
            listed[0].asked_of().principal(),
            caller_person().principal()
        );
    }

    /// Ann, who may view agents, lists what Owen's agent asked. She sees
    /// both requests.
    #[test]
    fn a_viewer_sees_everything_an_agent_asked() {
        let scene = scene();

        let listed = list(scene.ports, RequestsOf::Agent(scene.agent)).unwrap();

        assert_eq!(listed.len(), 2);
    }

    /// Listing another owner's delegation requests without agent-view
    /// permission reports the agent as missing.
    #[test]
    fn a_caller_who_may_not_view_the_agent_is_refused() {
        let scene = scene();
        let ports = ListRequestsPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[])),
            ..scene.ports
        };

        let result = list(ports, RequestsOf::Agent(scene.agent));

        assert!(matches!(result, Err(AppError::NotFound(_))), "{result:?}");
    }

    /// A signed-out caller cannot read delegation requests addressed to them.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let scene = scene();
        let ports = ListRequestsPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..scene.ports
        };

        let result = list(ports, RequestsOf::AskedOfCaller);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
