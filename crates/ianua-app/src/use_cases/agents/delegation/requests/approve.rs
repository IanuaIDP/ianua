//! Approve delegation request: the person an agent asked grants it.
//!
//! Granting a request is granting a delegation, checked the way
//! [`grant_delegation`](crate::use_cases::agents::delegation::granting::grant) checks one: the person
//! must own the agent or be allowed to delegate to agents, and the grant is
//! held to what they hold at the moment they answer, never to what the
//! agent asked for. Apps it names must be the tenant's, a shared resource
//! needs an open channel, and an agent that reviews another is given
//! nothing. Only the person asked grants it; the request and the
//! delegation it became are kept and recorded together.

use std::sync::Arc;

use ianua_domain::domains::agents::authority::delegation::{Delegate, Delegation};
use ianua_domain::domains::agents::authority::delegation_request::DelegationRequest;
use ianua_domain::domains::agents::identity::agent::AgentIdentity;
use ianua_domain::domains::agents::identity::control::AgentControl;
use ianua_domain::domains::authorization::permission::AgentAction;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::events::event::DomainEvent;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{AgentId, DelegationRequestId};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrConflict, OrInternal};
use crate::ports::agents::{
    AgentStore, DelegationRequestStore, DelegationStore, RelationshipResolver,
    ReviewAssignmentStore, ToolStore,
};
use crate::ports::authorization::ResourceTypeStore;
use crate::ports::messaging::AgentChannelStore;
use crate::ports::routing::ServiceStore;
use crate::ports::runtime::UnitOfWork;
use crate::services::kept_together::kept_together;
use crate::services::lookup::existing_agent;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::agents::delegation::granting::authority::{AuthoritySources, held_by};
use crate::use_cases::agents::delegation::granting::grant::ensure_known_apps;
use crate::use_cases::agents::delegation::requests::ANSWERED_MEANWHILE;
use crate::use_cases::agents::delegation::resources::sharing::{
    SharingAgent, SharingStores, refuse_unchanneled_sharing,
};
use crate::use_cases::agents::lookup::owned_delegation_request;
use crate::use_cases::agents::reviews::reviewing::review_duty;

/// Which request to grant, addressed under the agent that asked.
pub struct ApproveRequestRequest {
    /// The agent the address names.
    pub agent_id: AgentId,
    /// The pending request whose capabilities should be granted.
    pub request_id: DelegationRequestId,
}

/// The ports [`ApproveRequestUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ApproveRequestPorts {
    /// Loads and keeps the request.
    pub request_store: Arc<dyn DelegationRequestStore>,
    /// Loads the agent that asked.
    pub agent_store: Arc<dyn AgentStore>,
    /// Keeps the delegation, and says who holds a resource.
    pub delegation_store: Arc<dyn DelegationStore>,
    /// The relationship graph: what the person holds.
    pub relationship_resolver: Arc<dyn RelationshipResolver>,
    /// The tenant's tool registry, the bound on any tool grant.
    pub tool_store: Arc<dyn ToolStore>,
    /// Who reviews whom; an agent that reviews is given nothing.
    pub review_store: Arc<dyn ReviewAssignmentStore>,
    /// The channels people opened between agents; a shared resource needs
    /// one.
    pub channel_store: Arc<dyn AgentChannelStore>,
    /// The tenant's resource types, for how sensitive a shared object is.
    pub resource_type_store: Arc<dyn ResourceTypeStore>,
    /// The tenant's services; every app a delegation names must be one.
    pub service_store: Arc<dyn ServiceStore>,
    /// Keeps the request, the delegation and the record together.
    pub unit_of_work: Arc<dyn UnitOfWork>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Grants the delegations agents asked people for.
pub struct ApproveRequestUseCase {
    ports: ApproveRequestPorts,
}

impl ApproveRequestUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: ApproveRequestPorts) -> Self {
        Self { ports }
    }

    /// Refuses a request naming an app the tenant does not serve, or
    /// sharing a resource with the agent over no open channel.
    async fn ensure_shareable(
        &self,
        tenant: &ScopedTenant,
        request: &DelegationRequest<ResolvedTenant>,
    ) -> Result<(), AppError> {
        ensure_known_apps(
            self.ports.service_store.as_ref(),
            tenant,
            request.constraints().apps(),
        )
        .await?;
        refuse_unchanneled_sharing(
            SharingStores {
                delegations: self.ports.delegation_store.as_ref(),
                channels: self.ports.channel_store.as_ref(),
                resource_types: self.ports.resource_type_store.as_ref(),
            },
            SharingAgent {
                tenant_id: tenant,
                agent: request.agent_id(),
            },
            request.granted().resources(),
        )
        .await
    }

    /// The delegation `request` becomes, granted by the person `control`
    /// names to `agent`, held to what they hold now.
    async fn granted(
        &self,
        tenant: &ScopedTenant,
        control: &AgentControl<'_>,
        request: &mut DelegationRequest<ResolvedTenant>,
        agent: &AgentIdentity<ResolvedTenant>,
    ) -> Result<Delegation<ResolvedTenant>, AppError> {
        let sources = AuthoritySources {
            resolver: self.ports.relationship_resolver.as_ref(),
            tools: self.ports.tool_store.as_ref(),
        };
        let held = held_by(sources, tenant, control, request.granted()).await?;
        let duty = review_duty(self.ports.review_store.as_ref(), tenant, agent.id()).await?;
        request
            .approve(&held, &Delegate { agent, duty })
            .map_err(AppError::from_domain)
    }

    /// Keeps the answered request and its delegation, and records both,
    /// together.
    async fn keep(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: &mut DelegationRequest<ResolvedTenant>,
        delegation: &mut Delegation<ResolvedTenant>,
    ) -> Result<(), AppError> {
        let tenant = ctx.tenant();
        let work = async {
            self.ports
                .request_store
                .save(&tenant, request)
                .await
                .or_conflict(message!(
                    "agents-the-request-was-answered-by-someone",
                    ANSWERED_MEANWHILE
                ))?;
            self.ports
                .delegation_store
                .save(&tenant, delegation)
                .await
                .or_internal()?;
            auditor
                .dispatch_by(&ctx.actor(), granted_record(&tenant, request, delegation))
                .await
                .or_internal()
        };
        kept_together(self.ports.unit_of_work.as_ref(), work).await
    }
}

impl Command for ApproveRequestUseCase {
    type Caller = CallerContext;
    type Input = ApproveRequestRequest;
    type Output = Result<Delegation<ResolvedTenant>, AppError>;

    /// Grants the request `input.request_id` as a delegation from the
    /// caller to the agent that asked, and records
    /// `agents.delegation_request_approved` and the grant. The agent takes
    /// its token from the delegation through the token exchange.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `NotFound` for a missing agent/request or a caller neither asked nor allowed to manage agents.
    /// - `AppError::Forbidden` for a caller not asked, lacking ownership/delegation rights or requested access, a closed shared-resource channel, or an agent unable to act or reviewing another.
    /// - `AppError::Domain` for an answered/expired request or an app outside the tenant's services.
    /// - `AppError::Conflict` for a concurrent answer; `Internal` on persistence or audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        input: ApproveRequestRequest,
    ) -> Result<Delegation<ResolvedTenant>, AppError> {
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let control = AgentControl::new(&authority);
        let store = self.ports.request_store.as_ref();
        let mut request =
            owned_delegation_request(store, &tenant, &input.agent_id, &input.request_id, &control)
                .await?;
        let agent =
            existing_agent(self.ports.agent_store.as_ref(), &tenant, request.agent_id()).await?;
        control
            .ensure_may(agent.owner(), AgentAction::Delegate)
            .map_err(AppError::from_domain)?;
        self.ensure_shareable(&tenant, &request).await?;
        let mut delegation = self
            .granted(&tenant, &control, &mut request, &agent)
            .await?;
        self.keep(ctx, auditor, &mut request, &mut delegation)
            .await?;
        Ok(delegation)
    }
}

/// What granting the request records: the answer, then the grant.
fn granted_record(
    tenant: &ScopedTenant,
    request: &mut DelegationRequest<ResolvedTenant>,
    delegation: &mut Delegation<ResolvedTenant>,
) -> Vec<DomainEvent> {
    let mut recorded = request.take_events(tenant);
    recorded.extend(delegation.take_events(tenant));
    recorded
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::agents::authority::capability::CapabilitySet;
    use ianua_domain::domains::agents::authority::delegation_request::RequestState;
    use ianua_domain::domains::authorization::permission::{RoutingAction, SystemPermission};
    use ianua_domain::types::Human;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::agents::{
        FakeAgentStore, FakeDelegationRequestStore, FakeDelegationStore, asked_request,
        caller_person, callers_agent, someone,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    fn reports() -> CapabilitySet {
        CapabilitySet::new(vec![SystemPermission::Routing(RoutingAction::View)], vec![])
    }

    /// The caller's agent, asking `asked_of` to let it view routes, and the
    /// stores they are kept in.
    struct Scene {
        agent: AgentId,
        request: DelegationRequestId,
        requests: Arc<FakeDelegationRequestStore>,
        delegations: Arc<FakeDelegationStore>,
        agents: Arc<FakeAgentStore>,
        sink: Arc<FakeEventDispatcher>,
    }

    impl Scene {
        fn asking(asked_of: Human) -> Self {
            let agent = AgentId::new();
            let agents = Arc::new(callers_agent(agent));
            let stored = block_on(agents.find_by_id(&test_ctx().tenant(), &agent))
                .unwrap()
                .unwrap();
            let request = asked_request(&stored, asked_of, reports());
            Self {
                agent,
                request: *request.id(),
                requests: Arc::new(FakeDelegationRequestStore::holding([request])),
                delegations: Arc::new(FakeDelegationStore::empty()),
                agents,
                sink: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn ports(&self) -> ApproveRequestPorts {
            ApproveRequestPorts {
                request_store: self.requests.clone(),
                agent_store: self.agents.clone(),
                delegation_store: self.delegations.clone(),
                ..ApproveRequestPorts::fakes()
            }
        }

        fn approve_with(
            &self,
            ports: ApproveRequestPorts,
            agent_id: AgentId,
        ) -> Result<Delegation<ResolvedTenant>, AppError> {
            block_on(ApproveRequestUseCase::new(ports).execute(
                &test_ctx(),
                &test_auditor(self.sink.clone()),
                ApproveRequestRequest {
                    agent_id,
                    request_id: self.request,
                },
            ))
        }

        fn approve(&self) -> Result<Delegation<ResolvedTenant>, AppError> {
            self.approve_with(self.ports(), self.agent)
        }

        fn state(&self) -> RequestState {
            self.requests.stored(&self.request).unwrap().state()
        }

        fn records(&self) -> Vec<String> {
            self.sink.records.lock().unwrap().clone()
        }
    }

    /// Ann's agent asked her to view routes, and she grants it. A
    /// delegation from her is kept, the request names it, and both are
    /// recorded.
    #[test]
    fn the_person_asked_grants_the_request() {
        let scene = Scene::asking(caller_person());

        let delegation = scene.approve().unwrap();

        assert_eq!(*delegation.delegator(), caller_person().principal());
        assert_eq!(scene.delegations.count(), 1);
        assert!(matches!(
            scene.state(),
            RequestState::Approved { delegation_id, .. } if delegation_id == *delegation.id()
        ));
        let records = scene.records();
        assert_eq!(records[0], "agents.delegation_request_approved");
        assert!(records.contains(&"agents.delegation_granted".to_owned()));
    }

    /// Approving a request addressed to someone else is refused, leaving it
    /// pending without saving a delegation or recording an event.
    #[test]
    fn only_the_person_asked_grants_it() {
        let scene = Scene::asking(someone("bob@example.test"));

        let result = scene.approve();

        assert!(matches!(result, Err(AppError::Forbidden(_))), "{result:?}");
        assert_eq!(scene.state(), RequestState::Pending);
        assert_eq!(scene.delegations.count(), 0);
        assert!(scene.records().is_empty());
    }

    /// A caller lacking the requested route-view permission cannot approve
    /// the grant; the request stays pending and no delegation is saved.
    #[test]
    fn a_grant_past_what_the_person_holds_now_is_refused() {
        let scene = Scene::asking(caller_person());
        let ports = ApproveRequestPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
                SystemPermission::Agents(AgentAction::Delegate),
            ])),
            ..scene.ports()
        };

        let result = scene.approve_with(ports, scene.agent);

        assert!(matches!(result, Err(AppError::Forbidden(_))), "{result:?}");
        assert_eq!(scene.state(), RequestState::Pending);
        assert_eq!(scene.delegations.count(), 0);
    }

    /// Approving through another agent's address reports the request as
    /// missing and leaves it pending.
    #[test]
    fn a_request_under_another_agents_address_is_not_found() {
        let scene = Scene::asking(caller_person());

        let result = scene.approve_with(scene.ports(), AgentId::new());

        assert!(matches!(result, Err(AppError::NotFound(_))), "{result:?}");
        assert_eq!(scene.state(), RequestState::Pending);
    }

    /// A signed-out caller cannot approve the request, which remains pending.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let scene = Scene::asking(caller_person());
        let ports = ApproveRequestPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..scene.ports()
        };

        let result = scene.approve_with(ports, scene.agent);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(scene.state(), RequestState::Pending);
    }
}
