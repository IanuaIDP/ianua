//! Deny delegation request: a person refuses a delegation an agent asked
//! for.
//!
//! The person asked refuses it, and so may someone allowed to manage
//! agents, who stops an agent pestering people. A refused request grants
//! nothing and is never answered again.

use std::sync::Arc;

use ianua_domain::domains::agents::authority::delegation_request::DelegationRequest;
use ianua_domain::domains::agents::identity::control::AgentControl;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{AgentId, DelegationRequestId};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrConflict, OrInternal};
use crate::ports::agents::{AgentStore, DelegationRequestStore};
use crate::services::lookup::existing_agent;
use crate::use_case::Command;
use crate::use_cases::agents::delegation::requests::ANSWERED_MEANWHILE;
use crate::use_cases::agents::lookup::owned_delegation_request;

/// Which request to refuse, addressed under the agent that asked.
pub struct DenyRequestRequest {
    /// The agent the address names.
    pub agent_id: AgentId,
    /// The pending request to close without granting capabilities.
    pub request_id: DelegationRequestId,
}

/// The ports [`DenyRequestUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct DenyRequestPorts {
    /// Loads and keeps the request.
    pub request_store: Arc<dyn DelegationRequestStore>,
    /// Loads the agent that asked.
    pub agent_store: Arc<dyn AgentStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Refuses the delegations agents asked people for.
pub struct DenyRequestUseCase {
    ports: DenyRequestPorts,
}

impl DenyRequestUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: DenyRequestPorts) -> Self {
        Self { ports }
    }
}

impl Command for DenyRequestUseCase {
    type Caller = CallerContext;
    type Input = DenyRequestRequest;
    type Output = Result<DelegationRequest<ResolvedTenant>, AppError>;

    /// Refuses `input.request_id`, records
    /// `agents.delegation_request_denied`, and returns the request.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::NotFound` when the request does not exist under this
    ///   agent, the agent is gone, or the caller is neither the person asked
    ///   nor allowed to manage agents, so that it answers as a request that
    ///   does not exist.
    /// - `AppError::Domain` when the request was answered or lapsed.
    /// - `AppError::Conflict` when it was answered by someone else while
    ///   this refusal was under way.
    /// - `AppError::Internal` on persistence or audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        input: DenyRequestRequest,
    ) -> Result<DelegationRequest<ResolvedTenant>, AppError> {
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let control = AgentControl::new(&authority);
        let store = self.ports.request_store.as_ref();
        let mut request =
            owned_delegation_request(store, &tenant, &input.agent_id, &input.request_id, &control)
                .await?;
        let agent =
            existing_agent(self.ports.agent_store.as_ref(), &tenant, request.agent_id()).await?;
        request
            .deny(&control, &agent)
            .map_err(AppError::from_domain)?;
        store.save(&tenant, &request).await.or_conflict(message!(
            "agents-the-request-was-answered-by-someone",
            ANSWERED_MEANWHILE
        ))?;
        auditor
            .dispatch_by(&ctx.actor(), request.take_events(&tenant))
            .await
            .or_internal()?;
        Ok(request)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::agents::authority::capability::CapabilitySet;
    use ianua_domain::domains::agents::authority::delegation_request::RequestState;
    use ianua_domain::domains::authorization::permission::{AgentAction, SystemPermission};
    use ianua_domain::shared::model::aggregate::Aggregate;
    use ianua_domain::types::Human;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::agents::{
        FakeAgentStore, FakeDelegationRequestStore, asked_request, caller_person, someone,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// An agent of Owen's, asking `asked_of` for nothing in particular, and
    /// the stores they are kept in.
    struct Scene {
        agent: AgentId,
        request: DelegationRequestId,
        requests: Arc<FakeDelegationRequestStore>,
        agents: Arc<FakeAgentStore>,
        sink: Arc<FakeEventDispatcher>,
    }

    impl Scene {
        fn asking(asked_of: Human) -> Self {
            let agent = AgentId::new();
            let agents = Arc::new(FakeAgentStore::empty());
            agents.add_owned_by(agent, someone("owen@example.test"));
            let stored = agents.find_by_id_direct(&agent).unwrap();
            let request = asked_request(&stored, asked_of, CapabilitySet::empty());
            Self {
                agent,
                request: *request.id(),
                requests: Arc::new(FakeDelegationRequestStore::holding([request])),
                agents,
                sink: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn deny_holding(
            &self,
            held: &[SystemPermission],
        ) -> Result<DelegationRequest<ResolvedTenant>, AppError> {
            let ports = DenyRequestPorts {
                request_store: self.requests.clone(),
                agent_store: self.agents.clone(),
                tenant_authorities: Arc::new(FakeTenantAuthorities::holding(held)),
            };
            self.deny_with(ports)
        }

        fn deny_with(
            &self,
            ports: DenyRequestPorts,
        ) -> Result<DelegationRequest<ResolvedTenant>, AppError> {
            block_on(DenyRequestUseCase::new(ports).execute(
                &test_ctx(),
                &test_auditor(self.sink.clone()),
                DenyRequestRequest {
                    agent_id: self.agent,
                    request_id: self.request,
                },
            ))
        }

        fn state(&self) -> RequestState {
            self.requests.stored(&self.request).unwrap().state()
        }
    }

    /// Owen's agent asked Ann, and she refuses it. It is kept refused and
    /// the refusal is recorded.
    #[test]
    fn the_person_asked_refuses_the_request() {
        let scene = Scene::asking(caller_person());

        scene.deny_holding(&[]).unwrap();

        assert!(matches!(scene.state(), RequestState::Denied { .. }));
        assert_eq!(
            scene.sink.records.lock().unwrap().as_slice(),
            ["agents.delegation_request_denied"]
        );
    }

    /// Owen's agent keeps asking Bob. Ann, who manages agents, refuses it
    /// for him.
    #[test]
    fn an_agent_manager_refuses_a_request_made_of_someone_else() {
        let scene = Scene::asking(someone("bob@example.test"));

        scene
            .deny_holding(&[SystemPermission::Agents(AgentAction::Manage)])
            .unwrap();

        assert!(matches!(scene.state(), RequestState::Denied { .. }));
    }

    /// A viewer cannot deny a request addressed to someone else; it appears
    /// missing, stays pending, and records no denial.
    #[test]
    fn someone_else_may_not_refuse_it() {
        let scene = Scene::asking(someone("bob@example.test"));

        let result = scene.deny_holding(&[SystemPermission::Agents(AgentAction::View)]);

        assert!(matches!(result, Err(AppError::NotFound(_))), "{result:?}");
        assert_eq!(scene.state(), RequestState::Pending);
        assert!(scene.sink.records.lock().unwrap().is_empty());
    }

    /// A concurrent denial causes a conflict, preserves the first denial,
    /// and records no second denial event.
    #[test]
    fn a_refusal_of_a_request_answered_meanwhile_is_a_conflict() {
        let scene = Scene::asking(caller_person());
        let held = scene.requests.stored(&scene.request).unwrap();
        let scene = Scene {
            requests: Arc::new(FakeDelegationRequestStore::refused_while_answered([held])),
            ..scene
        };

        let result = scene.deny_holding(&[]);

        assert!(matches!(result, Err(AppError::Conflict(_))), "{result:?}");
        let first = scene.requests.stored(&scene.request).unwrap();
        assert_eq!(
            first.state(),
            RequestState::Denied {
                at: first.created_at()
            }
        );
        assert!(scene.sink.records.lock().unwrap().is_empty());
    }

    /// A signed-out caller cannot deny the request, which remains pending.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let scene = Scene::asking(caller_person());
        let ports = DenyRequestPorts {
            request_store: scene.requests.clone(),
            agent_store: scene.agents.clone(),
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
        };

        let result = scene.deny_with(ports);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(scene.state(), RequestState::Pending);
    }
}
