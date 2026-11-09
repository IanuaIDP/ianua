//! Authorize resource: a dry run of a resource-scoped agent action.
//!
//! Two gates, both required, deny by default:
//! 1. **Delegation scope.** The agent must hold a delegated resource
//!    capability for the target object; otherwise it has no business
//!    touching it at all.
//! 2. **Relationship.** Either the delegated capability matches exactly, or
//!    the [`RelationshipResolver`] confirms the required relation holds on
//!    the object, resolving the relation hierarchy the domain does not
//!    model.

use std::sync::Arc;

use ianua_domain::domains::agents::authority::capability::{CapabilitySet, ResourceCapability};
use ianua_domain::shared::clock;
use ianua_domain::types::{AgentId, PrincipalRef};

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::agents::{AgentStore, DelegationStore, RelationshipResolver};
use crate::tenancy::ScopedTenant;
use crate::use_case::Query;
use crate::use_cases::agents::access::AgentAuthorizeOutcome;
use crate::use_cases::agents::evidence::watching::watched_agent;

/// Which agent to check, and the capability it must be able to exercise.
pub struct AuthorizeResourceRequest {
    /// The agent whose delegated authority is checked.
    pub agent_id: AgentId,
    /// The relation the agent needs on the target object.
    pub required: ResourceCapability,
}

/// The ports [`AuthorizeResourceUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct AuthorizeResourcePorts {
    /// Loads the identity whose resource rights are checked.
    pub agent_store: Arc<dyn AgentStore>,
    /// The agent's delegations.
    pub delegation_store: Arc<dyn DelegationStore>,
    /// The relationship graph.
    pub resolver: Arc<dyn RelationshipResolver>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Runs the dry-run resource-scoped authorization check for an agent.
pub struct AuthorizeResourceUseCase {
    ports: AuthorizeResourcePorts,
}

impl AuthorizeResourceUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: AuthorizeResourcePorts) -> Self {
        Self { ports }
    }
}

impl Query for AuthorizeResourceUseCase {
    type Caller = CallerContext;
    type Input = AuthorizeResourceRequest;
    type Output = Result<AgentAuthorizeOutcome, AppError>;

    /// Whether the agent may exercise the required capability on its target
    /// resource.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::NotFound` when the tenant has no such agent, or the
    ///   caller neither owns it nor may view agents, so that an agent of
    ///   someone else's answers as one that does not exist.
    /// - `AppError::Internal` on persistence or resolver failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        request: AuthorizeResourceRequest,
    ) -> Result<AgentAuthorizeOutcome, AppError> {
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let agent = watched_agent(
            self.ports.agent_store.as_ref(),
            &authority,
            &tenant,
            &request.agent_id,
        )
        .await?;
        if !agent.may_act_at(clock::now()) {
            return Ok(AgentAuthorizeOutcome::deny("agent may not act now"));
        }
        let effective =
            effective_capabilities(self.ports.delegation_store.as_ref(), &tenant, agent.id())
                .await?;
        if let Some(outcome) = delegation_scope_outcome(&effective, &request.required) {
            return Ok(outcome);
        }
        relationship_outcome(
            self.ports.resolver.as_ref(),
            &tenant,
            agent.id(),
            &request.required,
        )
        .await
    }
}

/// The union of what the agent's live delegations grant.
async fn effective_capabilities(
    store: &dyn DelegationStore,
    tenant: &ScopedTenant,
    agent_id: &AgentId,
) -> Result<CapabilitySet, AppError> {
    let now = clock::now();
    Ok(store
        .list_for_agent(tenant, agent_id)
        .await
        .or_internal()?
        .iter()
        .filter(|d| d.is_valid(now))
        .fold(CapabilitySet::empty(), |acc, d| acc.union(d.granted())))
}

/// The outcome decided by delegation scope alone: a deny when no delegation
/// touches the object, an allow when one grants `required` exactly, and
/// `None` when the relationship graph has to decide.
fn delegation_scope_outcome(
    effective: &CapabilitySet,
    required: &ResourceCapability,
) -> Option<AgentAuthorizeOutcome> {
    let scoped = effective
        .resources()
        .iter()
        .any(|held| held.resource_ref() == required.resource_ref());
    if !scoped {
        return Some(AgentAuthorizeOutcome::deny(
            "resource not delegated to this agent",
        ));
    }
    if effective.permits_resource(required) {
        return Some(AgentAuthorizeOutcome::allow(
            "granted directly by a delegated resource capability",
        ));
    }
    None
}

/// The outcome once the relationship graph is asked whether `required`
/// holds for the agent on its object.
async fn relationship_outcome(
    resolver: &dyn RelationshipResolver,
    tenant: &ScopedTenant,
    agent_id: &AgentId,
    required: &ResourceCapability,
) -> Result<AgentAuthorizeOutcome, AppError> {
    let via_graph = resolver
        .check(
            tenant,
            &PrincipalRef::Agent(*agent_id),
            required.relation(),
            required.resource_ref(),
        )
        .await
        .or_internal()?;
    if via_graph {
        return Ok(AgentAuthorizeOutcome::allow(
            "granted via the relationship graph",
        ));
    }
    Ok(AgentAuthorizeOutcome::deny(
        "relation not satisfied on this resource",
    ))
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::agents::authority::capability::DelegationConstraints;
    use ianua_domain::domains::agents::authority::delegation::{DelegationStatus, Lineage};
    use ianua_domain::domains::agents::identity::status::AgentStatus;
    use ianua_domain::domains::authorization::permission::{AgentAction, SystemPermission};
    use ianua_domain::types::{Seconds, UserId};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::agents::{
        FakeAgentStore, FakeDelegationStore, FakeRelationshipResolver, StoredGrant, callers_agent,
        resource_cap, stored_delegation,
    };
    use crate::test_support::{block_on, test_ctx};

    struct Fixture {
        agent_id: AgentId,
        agents: Arc<FakeAgentStore>,
        delegations: Arc<FakeDelegationStore>,
        resolver: FakeRelationshipResolver,
    }

    /// The caller's agent, holding one delegation of `resources` in
    /// `status`, judged by `resolver`.
    fn setup_in(
        resources: Vec<ResourceCapability>,
        resolver: FakeRelationshipResolver,
        status: DelegationStatus,
    ) -> Fixture {
        let agent_id = AgentId::new();
        let delegations = Arc::new(FakeDelegationStore::empty());
        let delegation = stored_delegation(StoredGrant {
            delegator: PrincipalRef::User(UserId::new()),
            delegate: agent_id,
            granted: CapabilitySet::empty().with_resources(resources),
            constraints: DelegationConstraints::new(Seconds::new(600), 0).unwrap(),
            lineage: Lineage::Root,
            status,
        });
        block_on(delegations.save(&test_ctx().tenant(), &delegation)).unwrap();
        Fixture {
            agent_id,
            agents: Arc::new(callers_agent(agent_id)),
            delegations,
            resolver,
        }
    }

    fn setup(resources: Vec<ResourceCapability>, resolver: FakeRelationshipResolver) -> Fixture {
        setup_in(resources, resolver, DelegationStatus::Active)
    }

    impl Fixture {
        fn check_with(
            &self,
            authorities: FakeTenantAuthorities,
            required: ResourceCapability,
        ) -> Result<AgentAuthorizeOutcome, AppError> {
            let use_case = AuthorizeResourceUseCase::new(AuthorizeResourcePorts {
                agent_store: self.agents.clone(),
                delegation_store: self.delegations.clone(),
                resolver: Arc::new(self.resolver),
                tenant_authorities: Arc::new(authorities),
            });
            block_on(use_case.execute(
                &test_ctx(),
                AuthorizeResourceRequest {
                    agent_id: self.agent_id,
                    required,
                },
            ))
        }

        fn check(&self, required: ResourceCapability) -> AgentAuthorizeOutcome {
            self.check_with(FakeTenantAuthorities::holding(&[]), required)
                .unwrap()
        }
    }

    /// The agent holds `reader` on calendar a and asks for exactly that. It
    /// is allowed without asking the graph.
    #[test]
    fn an_exact_delegated_capability_is_allowed_without_the_graph() {
        let f = setup(
            vec![resource_cap("reader", "calendar:a")],
            FakeRelationshipResolver::HoldsNothing,
        );

        assert!(f.check(resource_cap("reader", "calendar:a")).is_allowed());
    }

    /// The agent holds `owner` on calendar a and asks to read it. The graph
    /// says an owner reads, so it is allowed.
    #[test]
    fn a_broader_relation_is_allowed_through_the_graph() {
        let f = setup(
            vec![resource_cap("owner", "calendar:a")],
            FakeRelationshipResolver::HoldsEverything,
        );

        assert!(f.check(resource_cap("reader", "calendar:a")).is_allowed());
    }

    /// A graph relation cannot authorize a calendar outside the agent's
    /// delegated resource scope.
    #[test]
    fn an_object_no_delegation_names_is_denied_whatever_the_graph_says() {
        let f = setup(
            vec![resource_cap("owner", "calendar:other")],
            FakeRelationshipResolver::HoldsEverything,
        );

        assert!(!f.check(resource_cap("reader", "calendar:a")).is_allowed());
    }

    /// A delegated viewer cannot edit the calendar when the graph does not
    /// grant the editor relation.
    #[test]
    fn a_relation_the_graph_does_not_back_is_denied() {
        let f = setup(
            vec![resource_cap("viewer", "calendar:a")],
            FakeRelationshipResolver::HoldsNothing,
        );

        assert!(!f.check(resource_cap("editor", "calendar:a")).is_allowed());
    }

    /// A revoked reader delegation cannot authorize reading its calendar.
    #[test]
    fn a_revoked_delegation_scopes_nothing() {
        let f = setup_in(
            vec![resource_cap("reader", "calendar:a")],
            FakeRelationshipResolver::HoldsEverything,
            DelegationStatus::Revoked,
        );

        assert!(!f.check(resource_cap("reader", "calendar:a")).is_allowed());
    }

    /// Suspending an agent denies a resource capability it holds exactly.
    #[test]
    fn a_suspended_agent_is_denied() {
        let f = setup(
            vec![resource_cap("reader", "calendar:a")],
            FakeRelationshipResolver::HoldsEverything,
        );
        f.agents.add_with_status(f.agent_id, AgentStatus::Suspended);

        let outcome = f
            .check_with(
                FakeTenantAuthorities::holding(&[SystemPermission::Agents(AgentAction::View)]),
                resource_cap("reader", "calendar:a"),
            )
            .unwrap();

        assert!(!outcome.is_allowed());
    }

    /// Checking resource access for an unknown agent reports it as missing.
    #[test]
    fn an_unknown_agent_is_not_found() {
        let f = Fixture {
            agent_id: AgentId::new(),
            ..setup(
                vec![resource_cap("reader", "calendar:a")],
                FakeRelationshipResolver::HoldsEverything,
            )
        };

        let result = f.check_with(
            FakeTenantAuthorities::holding_everything(),
            resource_cap("reader", "calendar:a"),
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A caller without agent-view permission sees another owner's agent as
    /// missing when checking its resource access.
    #[test]
    fn a_caller_without_the_view_right_is_refused() {
        let f = setup(
            vec![resource_cap("reader", "calendar:a")],
            FakeRelationshipResolver::HoldsEverything,
        );
        let f = Fixture {
            agents: Arc::new(FakeAgentStore::with_active(f.agent_id)),
            ..f
        };

        let result = f.check_with(
            FakeTenantAuthorities::holding(&[]),
            resource_cap("reader", "calendar:a"),
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A signed-out caller cannot check an agent's resource access.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let f = setup(
            vec![resource_cap("reader", "calendar:a")],
            FakeRelationshipResolver::HoldsEverything,
        );

        let result = f.check_with(
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
            resource_cap("reader", "calendar:a"),
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
