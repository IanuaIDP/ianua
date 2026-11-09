//! Grant resource authority: the write that puts edges into the
//! relationship graph.
//!
//! The graph answers "may this person hand out `relation` on `object`?", so
//! something has to put edges into it. Authority propagates rather than being
//! conjured: a caller may grant only a relation they hold themselves, which
//! makes every grant traceable back to someone who held it first.
//!
//! That chain has to start somewhere, and the root is the tenant's agent
//! administrator, who may seed a relation nobody holds yet. Without that
//! root, either nobody could ever grant a resource or anybody could.
//!
//! Taking a relation away is
//! [`revoke_resource_relation`](crate::use_cases::agents::delegation::resources::revoke_relation),
//! held to the same rule.

use std::sync::Arc;

use ianua_domain::domains::agents::authority::capability::ResourceCapability;
use ianua_domain::domains::agents::authority::relation_change::RelationChange;
use ianua_domain::domains::agents::identity::control::{AgentControl, RelationHolding};
use ianua_domain::domains::authorization::authority::TenantAuthority;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::PrincipalRef;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::agents::{RelationshipResolver, ResourceGrantStore};
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;

/// Request to move a resource relation between principals.
pub struct ResourceGrantRequest {
    /// The principal receiving or losing the relation.
    pub subject: PrincipalRef,
    /// The relation and object.
    pub capability: ResourceCapability,
}

/// The ports [`GrantResourceRelationUseCase`] and its revoking twin need.
#[derive(Clone, ianua_macros::Fakes)]
pub struct ResourceGrantPorts {
    /// Reads what the caller already holds.
    pub resolver: Arc<dyn RelationshipResolver>,
    /// Writes the grant.
    pub grants: Arc<dyn ResourceGrantStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Grants resource authority.
pub struct GrantResourceRelationUseCase {
    ports: ResourceGrantPorts,
}

impl GrantResourceRelationUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: ResourceGrantPorts) -> Self {
        Self { ports }
    }
}

impl Command for GrantResourceRelationUseCase {
    type Caller = CallerContext;
    type Input = ResourceGrantRequest;
    type Output = Result<(), AppError>;

    /// Gives `req.subject` the relation `req.capability` names, attributed
    /// to the caller.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller neither holds the relation
    ///   nor administers agents.
    /// - `AppError::Internal` when the graph cannot be read or written.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        req: ResourceGrantRequest,
    ) -> Result<(), AppError> {
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let holding = relation_holding(&self.ports, &tenant, &authority, &req.capability).await?;
        let mut change = RelationChange::<ResolvedTenant>::grant(
            &AgentControl::new(&authority),
            holding,
            req.subject,
            req.capability,
        )
        .map_err(AppError::from_domain)?;
        self.ports
            .grants
            .grant(
                &tenant,
                change.subject(),
                change.capability(),
                &authority.who().principal(),
            )
            .await
            .or_internal()?;
        auditor
            .dispatch_by(&ctx.actor(), change.take_events(&tenant))
            .await
            .or_internal()
    }
}

/// Whether the caller holds `capability` themselves, as the relationship
/// graph answers.
///
/// # Errors
///
/// - `AppError::Internal` when the graph cannot be read.
pub(in crate::use_cases::agents) async fn relation_holding(
    ports: &ResourceGrantPorts,
    tenant: &ScopedTenant,
    authority: &TenantAuthority,
    capability: &ResourceCapability,
) -> Result<RelationHolding, AppError> {
    let held = ports
        .resolver
        .check(
            tenant,
            &authority.who().principal(),
            capability.relation(),
            capability.resource_ref(),
        )
        .await
        .or_internal()?;
    Ok(RelationHolding::from(held))
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{AgentAction, SystemPermission};
    use ianua_domain::types::UserId;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::agents::{FakeResourceGraph, caller_person, resource_cap};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    fn ports(graph: &Arc<FakeResourceGraph>, holding: &[SystemPermission]) -> ResourceGrantPorts {
        ResourceGrantPorts {
            resolver: graph.clone(),
            grants: graph.clone(),
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(holding)),
        }
    }

    fn admin(graph: &Arc<FakeResourceGraph>) -> ResourceGrantPorts {
        ports(graph, &[SystemPermission::Agents(AgentAction::Manage)])
    }

    fn delegator(graph: &Arc<FakeResourceGraph>) -> ResourceGrantPorts {
        ports(graph, &[SystemPermission::Agents(AgentAction::Delegate)])
    }

    fn grant(
        ports: ResourceGrantPorts,
        sink: &Arc<FakeEventDispatcher>,
        object: &str,
    ) -> Result<(), AppError> {
        block_on(GrantResourceRelationUseCase::new(ports).execute(
            &test_ctx(),
            &test_auditor(sink.clone()),
            ResourceGrantRequest {
                subject: PrincipalRef::User(UserId::new()),
                capability: resource_cap("owner", object),
            },
        ))
    }

    fn quietly(ports: ResourceGrantPorts, object: &str) -> Result<(), AppError> {
        grant(ports, &Arc::new(FakeEventDispatcher::new()), object)
    }

    /// Ann administers agents. She gives Bob ownership of the budget, which
    /// nobody holds yet. The graph holds it.
    #[test]
    fn an_agent_administrator_may_seed_a_relation_nobody_holds() {
        let graph = Arc::new(FakeResourceGraph::empty());

        quietly(admin(&graph), "doc:budget").unwrap();

        assert_eq!(graph.count(), 1);
    }

    /// Agent-delegation permission cannot grant an unheld ownership
    /// relation, and the resource graph stays empty.
    #[test]
    fn a_delegator_cannot_grant_a_relation_they_do_not_hold() {
        let graph = Arc::new(FakeResourceGraph::empty());

        let result = quietly(delegator(&graph), "doc:ceo-salary");

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(graph.count(), 0);
    }

    /// Ann owns the budget and passes ownership on to Bob. Both hold it.
    #[test]
    fn a_holder_may_pass_on_what_they_hold() {
        let graph = Arc::new(FakeResourceGraph::empty());
        graph.insert(
            &test_ctx().tenant(),
            caller_person().principal(),
            resource_cap("owner", "doc:budget"),
        );

        quietly(delegator(&graph), "doc:budget").unwrap();

        assert_eq!(graph.count(), 2);
    }

    /// Ann gives Bob ownership of the budget. The grant is recorded.
    #[test]
    fn a_grant_is_recorded_in_the_audit_trail() {
        let graph = Arc::new(FakeResourceGraph::empty());
        let sink = Arc::new(FakeEventDispatcher::new());

        grant(admin(&graph), &sink, "doc:budget").unwrap();

        assert_eq!(
            sink.records.lock().unwrap().as_slice(),
            ["agents.resource_relation_granted"]
        );
    }

    /// A signed-out caller cannot grant a relation; the resource graph
    /// stays empty.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let graph = Arc::new(FakeResourceGraph::empty());
        let ports = ResourceGrantPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..admin(&graph)
        };

        let result = quietly(ports, "doc:budget");

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(graph.count(), 0);
    }
}
