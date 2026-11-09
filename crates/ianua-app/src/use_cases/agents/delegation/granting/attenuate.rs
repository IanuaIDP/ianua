//! Attenuate delegation: part of an agent's delegation is passed on to
//! another agent.
//!
//! The child is always the holding agent's: its delegator is that agent,
//! whoever asked. Either the agent passes it on, signed in as itself, or a
//! person speaks for it: its owner, or someone allowed to delegate to
//! agents. The domain keeps the child inside the parent, refuses an agent
//! that is reviewing another or may not act now, and refuses anyone else.
//!
//! The parent must belong to the agent the address names: the route reads
//! `.../agents/{id}/delegations/{delegation_id}/attenuate`, and a parent of
//! another agent reads as missing.

use std::sync::Arc;

use ianua_domain::domains::agents::authority::capability::{CapabilitySet, DelegationConstraints};
use ianua_domain::domains::agents::authority::delegation::{
    AttenuateParams, Attenuator, Delegate, Delegation,
};
use ianua_domain::domains::agents::identity::agent::AgentIdentity;
use ianua_domain::domains::agents::identity::control::AgentControl;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::clock;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{ActorRef, AgentId, Audience, DelegationId, Label, PrincipalRef};

use crate::acting::agent::SignedInAgent;
use crate::acting::{AgentActors, TenantAuthorities};
use crate::auditor::RequestAuditor;
use crate::context::{AgentAssertion, CallerContext};
use crate::error::{AppError, OrInternal};
use crate::ports::agents::{AgentStore, DelegationStore, RelationshipResolver, ToolStore};
use crate::ports::authorization::ResourceTypeStore;
use crate::ports::notifications::AlertThrottle;
use crate::services::agents::sign_in::{AgentDoor, signed_in_at};
use crate::services::agents::standing::ensure_active;
use crate::services::lookup::existing_agent;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::agents::delegation::granting::authority::{AuthoritySources, speaker_for};
use crate::use_cases::agents::delegation::granting::grant::{
    FollowUpPorts, GrantedDelegation, TaskTokenMinting, TaskTokenPorts, issued_task_token,
};
use crate::use_cases::agents::delegation::granting::lineage::principal_chain;
use crate::use_cases::agents::delegation::resources::sharing::{
    SharingAgent, SharingStores, refuse_unchanneled_sharing,
};
use crate::use_cases::agents::lookup::owned_delegation;
use crate::use_cases::agents::reviews::reviewing::review_duty;

/// Who passes part of a delegation on.
pub enum Attenuating {
    /// A person with a say over the agent holding it.
    Person(Box<CallerContext>),
    /// The agent holding it, signing in as itself.
    Agent {
        /// The tenant the request was addressed to.
        tenant: ScopedTenant,
        /// The assertion its own key signed.
        assertion: AgentAssertion,
    },
}

impl Attenuating {
    /// The tenant the request acts in.
    fn tenant(&self) -> ScopedTenant {
        match self {
            Self::Person(ctx) => ctx.tenant(),
            Self::Agent { tenant, .. } => *tenant,
        }
    }
}

/// Request to pass part of a delegation on.
pub struct AttenuateRequest {
    /// The agent the address named; the parent must be one of its
    /// delegations.
    pub agent_id: AgentId,
    /// The delegation passed on from.
    pub parent_id: DelegationId,
    /// The agent receiving the child.
    pub delegate: AgentId,
    /// The capabilities to hand over, all granted by the parent.
    pub granted: CapabilitySet,
    /// The child's limits, held inside the parent's.
    pub constraints: DelegationConstraints,
    /// A title people see for the child.
    pub name: Option<Label>,
}

/// The ports [`AttenuateUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct AttenuatePorts {
    /// What a narrower delegation is checked against and kept in: the agent, its delegations, the tenant's resource types, relations and tools.
    pub records: AttenuationRecordPorts,
    /// What mints the task token a delegation hands its agent.
    pub tokens: TaskTokenPorts,
    /// What follows a delegation: the agent's channel and the reviews it asks for.
    pub follow_up: FollowUpPorts,
    /// How the holding agent signs in as itself.
    pub agent_actors: Arc<dyn AgentActors>,
    /// Holds back records of a refused sign-in that looks like an attack
    /// to one a window per agent and kind of attack.
    pub alert_throttle: Arc<dyn AlertThrottle>,
    /// What a person passing it on holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// What a narrower delegation is checked against and kept in: the agent, its delegations, the tenant's resource types, relations and tools.
#[derive(ianua_macros::Fakes)]
pub struct AttenuationRecordPorts {
    /// Loads the agents.
    pub agent_store: Arc<dyn AgentStore>,
    /// Loads the parent, saves the child, and says who holds a resource.
    pub delegation_store: Arc<dyn DelegationStore>,
    /// The tenant's resource types, for how sensitive a shared object is.
    pub resource_type_store: Arc<dyn ResourceTypeStore>,
    /// The relationship graph, for what a steward holds.
    pub relationship_resolver: Arc<dyn RelationshipResolver>,
    /// The tenant's tool registry, for what a steward holds.
    pub tool_store: Arc<dyn ToolStore>,
}

/// Passes parts of delegations on from one agent to another.
pub struct AttenuateUseCase {
    ports: AttenuatePorts,
    audience: Audience,
}

impl AttenuateUseCase {
    /// A use case working through `ports`, taking agent assertions made for
    /// `audience`.
    #[must_use]
    pub fn new(ports: AttenuatePorts, audience: Audience) -> Self {
        Self { ports, audience }
    }

    /// The parent `request` names, as the named agent's, and the agent
    /// receiving the child, once sharing with it needs no missing channel.
    async fn parties(
        &self,
        tenant: &ScopedTenant,
        request: &AttenuateRequest,
    ) -> Result<(Delegation<ResolvedTenant>, AgentIdentity<ResolvedTenant>), AppError> {
        let store = self.ports.records.delegation_store.as_ref();
        let parent = owned_delegation(store, tenant, &request.agent_id, &request.parent_id).await?;
        let receiver = existing_agent(
            self.ports.records.agent_store.as_ref(),
            tenant,
            &request.delegate,
        )
        .await?;
        ensure_shareable(&self.ports, tenant, request).await?;
        Ok((parent, receiver))
    }

    /// Who passes the delegation on, an agent signed in as itself before
    /// anything is looked up, a refusal that looks like an attack recorded
    /// through `auditor`.
    async fn speaking<'a>(
        &self,
        by: &'a Attenuating,
        auditor: &RequestAuditor,
    ) -> Result<Speaking<'a>, AppError> {
        match by {
            Attenuating::Person(ctx) => Ok(Speaking::Person(ctx)),
            Attenuating::Agent { tenant, assertion } => {
                let door = AgentDoor {
                    actors: self.ports.agent_actors.as_ref(),
                    attacks: self.ports.alert_throttle.as_ref(),
                    tenant,
                    audience: &self.audience,
                };
                let signed = signed_in_at(door, auditor, assertion).await?;
                Ok(Speaking::Agent(Box::new(signed)))
            }
        }
    }

    /// The child `speaking` cuts as `cut` asks, with who cut it.
    async fn attenuated(
        &self,
        speaking: &Speaking<'_>,
        cut: Cut<'_>,
    ) -> Result<(Delegation<ResolvedTenant>, ActorRef), AppError> {
        match speaking {
            Speaking::Person(ctx) => self.by_person(ctx, cut).await,
            Speaking::Agent(signed) => by_agent(signed, cut),
        }
    }

    /// The task token `child` is handed out with, naming the tenant's own
    /// issuer.
    async fn task_token_for(
        &self,
        tenant: &ScopedTenant,
        child: &Delegation<ResolvedTenant>,
    ) -> Result<String, AppError> {
        let minting = TaskTokenMinting {
            tokens: self.ports.tokens.token_issuer.as_ref(),
            issuers: &self.ports.tokens.issuers,
        };
        issued_task_token(minting, tenant, child).await
    }

    /// The child a person speaking for the holding agent cuts.
    async fn by_person(
        &self,
        ctx: &CallerContext,
        cut: Cut<'_>,
    ) -> Result<(Delegation<ResolvedTenant>, ActorRef), AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let holder = existing_agent(
            self.ports.records.agent_store.as_ref(),
            &ctx.tenant(),
            cut.parent.delegate(),
        )
        .await?;
        ensure_active(&holder)?;
        let control = AgentControl::new(&authority);
        let sources = AuthoritySources {
            resolver: self.ports.records.relationship_resolver.as_ref(),
            tools: self.ports.records.tool_store.as_ref(),
        };
        let speaker = speaker_for(
            sources,
            &ctx.tenant(),
            &control,
            &holder,
            &cut.params.granted,
        )
        .await?;
        let by = speaker.attenuator(control, &holder);
        let child = cut
            .parent
            .attenuate(&by, &cut.delegate, cut.params)
            .map_err(AppError::from_domain)?;
        Ok((child, ctx.actor()))
    }
}

/// Who passes a delegation on: a person speaking for the holding agent, or
/// the holding agent, already signed in as itself.
enum Speaking<'a> {
    /// A caller asking to act for the holding agent.
    Person(&'a CallerContext),
    /// The holding agent.
    Agent(Box<SignedInAgent>),
}

/// What is cut from which parent, for whom.
struct Cut<'a> {
    /// The delegation passed on from.
    parent: &'a Delegation<ResolvedTenant>,
    /// The agent receiving the child.
    delegate: Delegate<'a, ResolvedTenant>,
    /// What the child is asked to be.
    params: AttenuateParams,
}

impl Command for AttenuateUseCase {
    type Caller = Attenuating;
    type Input = AttenuateRequest;
    type Output = Result<GrantedDelegation, AppError>;

    /// Cuts the child `request` asks for from its parent, saves it, mints
    /// its task token and returns it with the line of principals behind it.
    ///
    /// Agents sign in before lookups. Replayed, forged or wrong-agent assertions
    /// record `agents.token_attack_refused` once per agent and attack kind per window.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid person's session/key; `NotFound` for a missing parent/receiver or a parent belonging to another agent.
    /// - `AppError::Conflict` for an inactive holding agent or a token bound to a credential the receiver lacks.
    /// - `AppError::Forbidden` when the caller cannot speak for the holder, the agent assertion fails, the child exceeds its parent or remaining shared budget, sharing lacks an open channel, or the receiver reviews another agent or cannot act.
    /// - `AppError::Domain` for a revoked or expired parent.
    /// - `AppError::Internal` on persistence failure, including recording a refused agent sign-in.
    async fn execute(
        &self,
        by: &Attenuating,
        auditor: &RequestAuditor,
        request: AttenuateRequest,
    ) -> Result<GrantedDelegation, AppError> {
        let tenant = by.tenant();
        let speaking = self.speaking(by, auditor).await?;
        let store = self.ports.records.delegation_store.as_ref();
        let (parent, receiver) = self.parties(&tenant, &request).await?;
        let reviews = self.ports.follow_up.review_store.as_ref();
        let delegate = Delegate {
            agent: &receiver,
            duty: review_duty(reviews, &tenant, receiver.id()).await?,
        };
        let cut = Cut {
            parent: &parent,
            delegate,
            params: params(request),
        };
        let (mut child, actor) = self.attenuated(&speaking, cut).await?;
        ensure_budget_shared(store, &tenant, &parent, &child).await?;
        let task_token = self.task_token_for(&tenant, &child).await?;
        store.save(&tenant, &child).await.or_internal()?;
        let chain = principal_chain(store, &tenant, &child).await?;
        auditor
            .dispatch_by(&actor, child.take_events(&tenant))
            .await
            .or_internal()?;
        Ok(GrantedDelegation {
            delegation: child,
            task_token,
            chain,
        })
    }
}

/// Refuses sharing a resource with the receiving agent over no open
/// channel.
async fn ensure_shareable(
    ports: &AttenuatePorts,
    tenant: &ScopedTenant,
    request: &AttenuateRequest,
) -> Result<(), AppError> {
    refuse_unchanneled_sharing(
        SharingStores {
            delegations: ports.records.delegation_store.as_ref(),
            channels: ports.follow_up.channel_store.as_ref(),
            resource_types: ports.records.resource_type_store.as_ref(),
        },
        SharingAgent {
            tenant_id: tenant,
            agent: &request.delegate,
        },
        request.granted.resources(),
    )
    .await
}

/// Refuses a child whose request budget does not fit beside the children
/// already passed on from `parent`, which share its budget. Ann's agent may
/// make 100 requests an hour; ten children of 100 each would make 1,000.
async fn ensure_budget_shared(
    store: &dyn DelegationStore,
    tenant: &ScopedTenant,
    parent: &Delegation<ResolvedTenant>,
    child: &Delegation<ResolvedTenant>,
) -> Result<(), AppError> {
    let passed_on = store
        .find_by_delegator(tenant, &PrincipalRef::Agent(*parent.delegate()))
        .await
        .or_internal()?;
    if parent.budget_fits_beside(child.constraints().budget(), &passed_on, clock::now()) {
        return Ok(());
    }
    Err(AppError::Forbidden(message!(
        "agents-sub-delegation-budget-exceeds-what-its",
        "sub-delegation budget exceeds what its parent has left"
    )))
}

/// The child the holding agent, signed in as itself, cuts.
fn by_agent(
    signed: &SignedInAgent,
    cut: Cut<'_>,
) -> Result<(Delegation<ResolvedTenant>, ActorRef), AppError> {
    let child = cut
        .parent
        .attenuate(
            &Attenuator::Agent(&signed.acting),
            &cut.delegate,
            cut.params,
        )
        .map_err(AppError::from_domain)?;
    Ok((child, signed.actor()))
}

/// What the child is asked to be.
fn params(request: AttenuateRequest) -> AttenuateParams {
    AttenuateParams {
        granted: request.granted,
        constraints: request.constraints,
        name: request.name,
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::agents::authority::capability::AgentBudget;
    use ianua_domain::domains::agents::authority::delegation::{DelegationStatus, Lineage};
    use ianua_domain::domains::agents::identity::status::AgentStatus;
    use ianua_domain::domains::authorization::permission::{
        AgentAction, RoutingAction, SystemPermission,
    };
    use ianua_domain::shared::events::data::FieldValue;
    use ianua_domain::types::Seconds;

    use super::*;
    use crate::acting::agent::{AgentActing, AgentActingPorts};
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal, RefusingAgentActors};
    use crate::test_support::agents::{
        FakeAgentStore, FakeAssertionVerifier, FakeDelegationStore, StoredGrant, caller_person,
        callers_agent, root_delegation, signing_in, stored_delegation,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    fn caps(action: RoutingAction) -> CapabilitySet {
        CapabilitySet::new(vec![SystemPermission::Routing(action)], vec![])
    }

    fn audience() -> Audience {
        Audience::new("ianua:agents").unwrap()
    }

    /// Ann's agent holding a delegation from her, and a sub-agent to pass
    /// part of it to.
    struct Scenario {
        agents: Arc<FakeAgentStore>,
        delegations: Arc<FakeDelegationStore>,
        holder: AgentId,
        parent: DelegationId,
        sub: AgentId,
    }

    fn scenario_with(agents: FakeAgentStore, holder: AgentId, granted: CapabilitySet) -> Scenario {
        let sub = AgentId::new();
        agents.add_active(sub);
        let delegations = FakeDelegationStore::empty();
        let parent = root_delegation(caller_person().principal(), holder, granted);
        block_on(delegations.save(&test_ctx().tenant(), &parent)).unwrap();
        Scenario {
            agents: Arc::new(agents),
            delegations: Arc::new(delegations),
            holder,
            parent: *parent.id(),
            sub,
        }
    }

    fn scenario(granted: CapabilitySet) -> Scenario {
        let holder = AgentId::new();
        scenario_with(callers_agent(holder), holder, granted)
    }

    fn hourly(requests: u32) -> AgentBudget {
        AgentBudget::new(Seconds::new(3600))
            .unwrap()
            .with_max_requests(requests)
    }

    /// Ann's agent may view routes and make 100 requests an hour, under a
    /// delegation from her, and a sub-agent to pass part of it to.
    fn budgeted() -> Scenario {
        let holder = AgentId::new();
        let agents = callers_agent(holder);
        let sub = AgentId::new();
        agents.add_active(sub);
        let parent = stored_delegation(StoredGrant {
            delegator: caller_person().principal(),
            delegate: holder,
            granted: caps(RoutingAction::View),
            constraints: DelegationConstraints::new(Seconds::new(600), 3)
                .unwrap()
                .with_budget(hourly(100)),
            lineage: Lineage::Root,
            status: DelegationStatus::Active,
        });
        let delegations = FakeDelegationStore::empty();
        block_on(delegations.save(&test_ctx().tenant(), &parent)).unwrap();
        Scenario {
            agents: Arc::new(agents),
            delegations: Arc::new(delegations),
            holder,
            parent: *parent.id(),
            sub,
        }
    }

    impl Scenario {
        fn ports(&self) -> AttenuatePorts {
            AttenuatePorts {
                records: AttenuationRecordPorts {
                    agent_store: self.agents.clone(),
                    delegation_store: self.delegations.clone(),
                    ..AttenuationRecordPorts::fakes()
                },
                ..AttenuatePorts::fakes()
            }
        }

        fn request(&self, granted: CapabilitySet) -> AttenuateRequest {
            AttenuateRequest {
                agent_id: self.holder,
                parent_id: self.parent,
                delegate: self.sub,
                granted,
                constraints: DelegationConstraints::new(Seconds::new(300), 2).unwrap(),
                name: None,
            }
        }

        fn signed_in_as(&self, agent: AgentId) -> (AttenuatePorts, Attenuating) {
            let (agent_sign_in, assertion) = signing_in(self.agents.clone(), agent);
            let ports = AttenuatePorts {
                agent_actors: Arc::new(AgentActing::new(agent_sign_in)),
                ..self.ports()
            };
            let by = Attenuating::Agent {
                tenant: test_ctx().tenant(),
                assertion,
            };
            (ports, by)
        }
    }

    fn run_as(
        ports: AttenuatePorts,
        by: &Attenuating,
        sink: &Arc<FakeEventDispatcher>,
        request: AttenuateRequest,
    ) -> Result<GrantedDelegation, AppError> {
        block_on(AttenuateUseCase::new(ports, audience()).execute(
            by,
            &test_auditor(sink.clone()),
            request,
        ))
    }

    fn run(
        ports: AttenuatePorts,
        request: AttenuateRequest,
    ) -> Result<GrantedDelegation, AppError> {
        run_as(
            ports,
            &Attenuating::Person(Box::new(test_ctx())),
            &Arc::new(FakeEventDispatcher::new()),
            request,
        )
    }

    /// Ann passes "view routes" from her agent's delegation on to a
    /// sub-agent. The child sits one level under the parent, its line runs
    /// back to Ann, and it is saved.
    #[test]
    fn a_child_within_the_parent_is_saved_under_it() {
        let s = scenario(caps(RoutingAction::View));

        let granted = run(s.ports(), s.request(caps(RoutingAction::View))).unwrap();

        assert_eq!(granted.delegation.depth(), 1);
        assert_eq!(granted.delegation.parent(), Some(s.parent));
        assert_eq!(
            granted.chain,
            vec![PrincipalRef::Agent(s.holder), caller_person().principal()]
        );
        assert_eq!(s.delegations.count(), 2);
    }

    /// Ann titles the child "Q1 reconciliation sub-delegation". The record
    /// names it so.
    #[test]
    fn the_record_prefers_the_childs_title() {
        let s = scenario(caps(RoutingAction::View));
        let sink = Arc::new(FakeEventDispatcher::new());
        let mut request = s.request(caps(RoutingAction::View));
        request.name = Some(Label::new("name", "Q1 reconciliation sub-delegation").unwrap());

        run_as(
            s.ports(),
            &Attenuating::Person(Box::new(test_ctx())),
            &sink,
            request,
        )
        .unwrap();

        let payload = sink.payload_of("agents.delegation_granted");
        let Some(FieldValue::Reference(reference)) = payload.value("delegation") else {
            panic!("the record names the delegation");
        };
        assert_eq!(reference.label(), "Q1 reconciliation sub-delegation");
    }

    /// A route-view parent cannot grant route management to a child, and
    /// only the original delegation remains stored.
    #[test]
    fn a_child_reaching_past_the_parent_is_refused() {
        let s = scenario(caps(RoutingAction::View));

        let result = run(s.ports(), s.request(caps(RoutingAction::Manage)));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(s.delegations.count(), 1);
    }

    /// With 60 of the parent's 100 requests allocated, a child asking for
    /// 50 is refused while one asking for the remaining 40 is saved.
    #[test]
    fn children_share_their_parents_budget() {
        let s = budgeted();
        let asking = |requests| AttenuateRequest {
            constraints: DelegationConstraints::new(Seconds::new(300), 2)
                .unwrap()
                .with_budget(hourly(requests)),
            ..s.request(caps(RoutingAction::View))
        };
        run(s.ports(), asking(60)).unwrap();

        let over = run(s.ports(), asking(50));
        let within = run(s.ports(), asking(40));

        assert!(matches!(over, Err(AppError::Forbidden(_))));
        assert!(within.is_ok());
        assert_eq!(s.delegations.count(), 3);
    }

    /// A child asking for 500 requests exceeds its parent's 100-request
    /// budget and is refused without saving another delegation.
    #[test]
    fn a_child_spending_more_than_its_parent_is_refused() {
        let s = budgeted();
        let request = AttenuateRequest {
            constraints: DelegationConstraints::new(Seconds::new(300), 2)
                .unwrap()
                .with_budget(hourly(500)),
            ..s.request(caps(RoutingAction::View))
        };

        let result = run(s.ports(), request);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(s.delegations.count(), 1);
    }

    /// Ann names a parent delegation that does not exist. It is not found.
    #[test]
    fn an_unknown_parent_is_not_found() {
        let s = scenario(caps(RoutingAction::View));
        let mut request = s.request(caps(RoutingAction::View));
        request.parent_id = DelegationId::new();

        assert!(matches!(
            run(s.ports(), request),
            Err(AppError::NotFound(_))
        ));
    }

    /// Addressing a parent under another agent reports it as missing and
    /// saves no child delegation.
    #[test]
    fn a_parent_reached_through_another_agents_address_is_not_found() {
        let s = scenario(caps(RoutingAction::View));
        let mut request = s.request(caps(RoutingAction::View));
        request.agent_id = AgentId::new();

        let result = run(s.ports(), request);

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(s.delegations.count(), 1);
    }

    /// A suspended holder causes attenuation to conflict without saving a
    /// child delegation.
    #[test]
    fn a_suspended_holder_hands_nothing_on() {
        let holder = AgentId::new();
        let agents = FakeAgentStore::empty();
        agents.add_with_status(holder, AgentStatus::Suspended);
        let s = scenario_with(agents, holder, caps(RoutingAction::View));

        let result = run(s.ports(), s.request(caps(RoutingAction::View)));

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert_eq!(s.delegations.count(), 1);
    }

    /// A route manager without authority over the holding agent cannot
    /// pass on its delegation, and no child is saved.
    #[test]
    fn a_person_with_no_say_over_the_holder_is_refused() {
        let holder = AgentId::new();
        let s = scenario_with(
            FakeAgentStore::with_active(holder),
            holder,
            caps(RoutingAction::View),
        );
        let ports = AttenuatePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
                SystemPermission::Routing(RoutingAction::Manage),
            ])),
            ..s.ports()
        };

        let result = run(ports, s.request(caps(RoutingAction::View)));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(s.delegations.count(), 1);
    }

    /// A steward lacking route-view permission cannot pass it on from
    /// another owner's agent, and no child delegation is saved.
    #[test]
    fn a_steward_passes_on_nothing_they_do_not_hold() {
        let holder = AgentId::new();
        let s = scenario_with(
            FakeAgentStore::with_active(holder),
            holder,
            caps(RoutingAction::View),
        );
        let ports = AttenuatePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
                SystemPermission::Agents(AgentAction::Delegate),
            ])),
            ..s.ports()
        };

        let result = run(ports, s.request(caps(RoutingAction::View)));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(s.delegations.count(), 1);
    }

    /// Bob may delegate to agents and may view routes himself. He passes
    /// "view routes" on from Sam's agent's delegation to a sub-agent. The
    /// child is saved.
    #[test]
    fn a_steward_passes_on_what_they_hold() {
        let holder = AgentId::new();
        let s = scenario_with(
            FakeAgentStore::with_active(holder),
            holder,
            caps(RoutingAction::View),
        );
        let ports = AttenuatePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
                SystemPermission::Agents(AgentAction::Delegate),
                SystemPermission::Routing(RoutingAction::View),
            ])),
            ..s.ports()
        };

        run(ports, s.request(caps(RoutingAction::View))).unwrap();

        assert_eq!(s.delegations.count(), 2);
    }

    /// A signed-out caller cannot attenuate a delegation; no child is saved.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let s = scenario(caps(RoutingAction::View));
        let ports = AttenuatePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..s.ports()
        };

        let result = run(ports, s.request(caps(RoutingAction::View)));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(s.delegations.count(), 1);
    }

    /// A suspended receiver cannot receive a child delegation, and only the
    /// parent remains stored.
    #[test]
    fn a_suspended_receiver_is_given_nothing() {
        let s = scenario(caps(RoutingAction::View));
        s.agents.add_with_status(s.sub, AgentStatus::Suspended);

        let result = run(s.ports(), s.request(caps(RoutingAction::View)));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(s.delegations.count(), 1);
    }

    /// The holding agent signs in as itself and saves a child beneath its
    /// parent delegation.
    #[test]
    fn the_holding_agent_signed_in_passes_part_on() {
        let s = scenario(caps(RoutingAction::View));
        let (ports, by) = s.signed_in_as(s.holder);
        let sink = Arc::new(FakeEventDispatcher::new());

        let granted = run_as(ports, &by, &sink, s.request(caps(RoutingAction::View))).unwrap();

        assert_eq!(granted.delegation.parent(), Some(s.parent));
        assert_eq!(s.delegations.count(), 2);
    }

    /// A rejected assertion refuses attenuation without saving a child
    /// delegation and records a token attack.
    #[test]
    fn a_forged_assertion_is_recorded_as_an_attack() {
        let s = scenario(caps(RoutingAction::View));
        let (agent_sign_in, assertion) = signing_in(s.agents.clone(), s.holder);
        let ports = AttenuatePorts {
            agent_actors: Arc::new(AgentActing::new(AgentActingPorts {
                verifier: Arc::new(FakeAssertionVerifier::rejecting("agent-key")),
                ..agent_sign_in
            })),
            ..s.ports()
        };
        let by = Attenuating::Agent {
            tenant: test_ctx().tenant(),
            assertion,
        };
        let sink = Arc::new(FakeEventDispatcher::new());

        let result = run_as(ports, &by, &sink, s.request(caps(RoutingAction::View)));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(s.delegations.count(), 1);
        assert!(
            sink.records
                .lock()
                .unwrap()
                .contains(&"agents.token_attack_refused".to_owned())
        );
    }

    /// A signed-in agent cannot attenuate another agent's delegation, and
    /// no child is saved.
    #[test]
    fn another_agent_signed_in_cannot_pass_the_delegation_on() {
        let s = scenario(caps(RoutingAction::View));
        let mallorys = AgentId::new();
        s.agents.add_active(mallorys);
        let (ports, by) = s.signed_in_as(mallorys);

        let result = run_as(
            ports,
            &by,
            &Arc::new(FakeEventDispatcher::new()),
            s.request(caps(RoutingAction::View)),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(s.delegations.count(), 1);
    }

    /// An agent refused at sign-in cannot attenuate a delegation, and no
    /// child is saved.
    #[test]
    fn an_agent_the_sign_in_refuses_passes_nothing_on() {
        let s = scenario(caps(RoutingAction::View));
        let (mut ports, by) = s.signed_in_as(s.holder);
        ports.agent_actors = Arc::new(RefusingAgentActors);

        let result = run_as(
            ports,
            &by,
            &Arc::new(FakeEventDispatcher::new()),
            s.request(caps(RoutingAction::View)),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(s.delegations.count(), 1);
    }
}
