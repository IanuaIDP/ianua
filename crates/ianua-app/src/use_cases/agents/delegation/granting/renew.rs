//! Renew delegation: the person who granted a delegation gives it its
//! lifetime again, from now.
//!
//! Renewing is granting again: the domain holds it to what the person holds
//! today, so a right they lost is not kept alive through an old grant, and
//! refuses an agent that may no longer receive authority. Only a delegation
//! a person granted at the top of its chain is renewed; one already expired
//! or revoked is granted anew instead.

use std::sync::Arc;

use ianua_domain::domains::agents::authority::delegation::{Delegate, Delegation};
use ianua_domain::domains::agents::identity::control::AgentControl;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{AgentId, DelegationId};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::agents::{
    AgentStore, DelegationStore, RelationshipResolver, ReviewAssignmentStore, ToolStore,
};
use crate::services::lookup::existing_agent;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::agents::delegation::granting::authority::{AuthoritySources, held_by};
use crate::use_cases::agents::lookup::owned_granted_delegation;
use crate::use_cases::agents::reviews::reviewing::review_duty;

/// Which delegation to renew, addressed under the agent holding it.
pub struct RenewRequest {
    /// The agent the address names.
    pub agent_id: AgentId,
    /// The existing grant whose lifetime should be extended.
    pub delegation_id: DelegationId,
}

/// The ports [`RenewUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RenewPorts {
    /// Loads and keeps the delegation.
    pub delegation_store: Arc<dyn DelegationStore>,
    /// Loads the agent holding it.
    pub agent_store: Arc<dyn AgentStore>,
    /// The relationship graph: what the person holds.
    pub relationship_resolver: Arc<dyn RelationshipResolver>,
    /// The tenant's tool registry, the bound on any tool grant.
    pub tool_store: Arc<dyn ToolStore>,
    /// Who reviews whom; an agent that reviews may not receive authority.
    pub review_store: Arc<dyn ReviewAssignmentStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Renews delegations people granted.
pub struct RenewUseCase {
    ports: RenewPorts,
}

impl RenewUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: RenewPorts) -> Self {
        Self { ports }
    }

    /// `delegation` renewed by the person `control` names, held to what
    /// they hold today and refused when its agent may no longer receive
    /// authority.
    async fn renewed(
        &self,
        tenant: &ScopedTenant,
        control: &AgentControl<'_>,
        mut delegation: Delegation<ResolvedTenant>,
    ) -> Result<Delegation<ResolvedTenant>, AppError> {
        let sources = AuthoritySources {
            resolver: self.ports.relationship_resolver.as_ref(),
            tools: self.ports.tool_store.as_ref(),
        };
        let held = held_by(sources, tenant, control, delegation.granted()).await?;
        let agents = self.ports.agent_store.as_ref();
        let agent = existing_agent(agents, tenant, delegation.delegate()).await?;
        let duty = review_duty(self.ports.review_store.as_ref(), tenant, agent.id()).await?;
        let delegate = Delegate {
            agent: &agent,
            duty,
        };
        delegation
            .renew(&held, &delegate)
            .map_err(AppError::from_domain)?;
        Ok(delegation)
    }
}

impl Command for RenewUseCase {
    type Caller = CallerContext;
    type Input = RenewRequest;
    type Output = Result<Delegation<ResolvedTenant>, AppError>;

    /// Renews `request.delegation_id` for its lifetime from now, records
    /// `agents.delegation_renewed` with when it now expires, and returns
    /// it.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::NotFound` when the delegation does not exist under this
    ///   agent, the agent is gone, or the caller did not grant it, so that a
    ///   delegation someone else granted answers as one that does not exist.
    /// - `AppError::Forbidden` when the caller no longer holds all it
    ///   grants, or the agent may not receive authority now.
    /// - `AppError::Domain` when it was not granted by a person at the top
    ///   of its chain, or is revoked or expired.
    /// - `AppError::Internal` on persistence or audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: RenewRequest,
    ) -> Result<Delegation<ResolvedTenant>, AppError> {
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let control = AgentControl::new(&authority);
        let store = self.ports.delegation_store.as_ref();
        let granted = owned_granted_delegation(
            store,
            &tenant,
            &request.agent_id,
            &request.delegation_id,
            &control,
        )
        .await?;
        let mut delegation = self.renewed(&tenant, &control, granted).await?;
        store.save(&tenant, &delegation).await.or_internal()?;
        auditor
            .dispatch_by(&ctx.actor(), delegation.take_events(&tenant))
            .await
            .or_internal()?;
        Ok(delegation)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::agents::authority::capability::CapabilitySet;
    use ianua_domain::domains::agents::authority::delegation::DelegationRenewal;
    use ianua_domain::domains::authorization::permission::{
        AgentAction, RoutingAction, SystemPermission,
    };
    use ianua_domain::types::Human;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::agents::{
        FakeAgentStore, FakeDelegationStore, caller_person, callers_agent, root_delegation, someone,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    fn reports() -> CapabilitySet {
        CapabilitySet::new(vec![SystemPermission::Routing(RoutingAction::View)], vec![])
    }

    /// The caller's agent, holding a delegation `delegator` granted it, and
    /// the stores they are kept in.
    struct Scene {
        agent: AgentId,
        delegation: DelegationId,
        delegations: Arc<FakeDelegationStore>,
        agents: Arc<FakeAgentStore>,
        sink: Arc<FakeEventDispatcher>,
    }

    impl Scene {
        fn granted_by(delegator: &Human) -> Self {
            let agent = AgentId::new();
            let delegation = root_delegation(delegator.principal(), agent, reports());
            let delegations = FakeDelegationStore::empty();
            block_on(delegations.save(&test_ctx().tenant(), &delegation)).unwrap();
            Self {
                agent,
                delegation: *delegation.id(),
                delegations: Arc::new(delegations),
                agents: Arc::new(callers_agent(agent)),
                sink: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn ports(&self) -> RenewPorts {
            RenewPorts {
                delegation_store: self.delegations.clone(),
                agent_store: self.agents.clone(),
                ..RenewPorts::fakes()
            }
        }

        fn renew_with(&self, ports: RenewPorts) -> Result<Delegation<ResolvedTenant>, AppError> {
            block_on(RenewUseCase::new(ports).execute(
                &test_ctx(),
                &test_auditor(self.sink.clone()),
                RenewRequest {
                    agent_id: self.agent,
                    delegation_id: self.delegation,
                },
            ))
        }

        fn stored(&self) -> Delegation<ResolvedTenant> {
            block_on(
                self.delegations
                    .find_by_id(&test_ctx().tenant(), &self.delegation),
            )
            .unwrap()
            .unwrap()
        }
    }

    /// Ann renews the delegation she gave her agent. It is kept renewed,
    /// living its lifetime again from now, and the renewal is recorded.
    #[test]
    fn the_delegator_renews_their_delegation() {
        let scene = Scene::granted_by(&caller_person());
        let before = scene.stored().expires_at();

        let renewed = scene.renew_with(scene.ports()).unwrap();

        assert!(matches!(renewed.renewed(), DelegationRenewal::RenewedAt(_)));
        assert!(scene.stored().expires_at() >= before);
        assert_eq!(
            scene.sink.records.lock().unwrap().as_slice(),
            ["agents.delegation_renewed"]
        );
    }

    /// Renewing another person's grant reports it as missing, leaves it
    /// unrenewed, and records no renewal.
    #[test]
    fn only_the_delegator_renews_it() {
        let scene = Scene::granted_by(&someone("bob@example.test"));

        let result = scene.renew_with(scene.ports());

        assert!(matches!(result, Err(AppError::NotFound(_))), "{result:?}");
        assert_eq!(scene.stored().renewed(), DelegationRenewal::NotRenewed);
        assert!(scene.sink.records.lock().unwrap().is_empty());
    }

    /// A delegator lacking the granted route-view permission cannot renew
    /// the delegation, which remains unrenewed.
    #[test]
    fn a_delegator_who_lost_what_it_grants_may_not_renew_it() {
        let scene = Scene::granted_by(&caller_person());
        let ports = RenewPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
                SystemPermission::Agents(AgentAction::Delegate),
            ])),
            ..scene.ports()
        };

        let result = scene.renew_with(ports);

        assert!(matches!(result, Err(AppError::Forbidden(_))), "{result:?}");
        assert_eq!(scene.stored().renewed(), DelegationRenewal::NotRenewed);
    }

    /// Renewing through another agent's address reports the delegation as
    /// missing.
    #[test]
    fn a_delegation_under_another_agents_address_is_not_found() {
        let scene = Scene::granted_by(&caller_person());

        let result = block_on(RenewUseCase::new(scene.ports()).execute(
            &test_ctx(),
            &test_auditor(scene.sink.clone()),
            RenewRequest {
                agent_id: AgentId::new(),
                delegation_id: scene.delegation,
            },
        ));

        assert!(matches!(result, Err(AppError::NotFound(_))), "{result:?}");
    }

    /// A signed-out caller cannot renew the delegation, which stays unrenewed.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let scene = Scene::granted_by(&caller_person());
        let ports = RenewPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..scene.ports()
        };

        let result = scene.renew_with(ports);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(scene.stored().renewed(), DelegationRenewal::NotRenewed);
    }
}
