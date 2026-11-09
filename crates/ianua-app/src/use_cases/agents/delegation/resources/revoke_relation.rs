//! Revoke resource authority: take an edge out of the relationship graph.
//!
//! Held to the same rule as
//! [granting](crate::use_cases::agents::delegation::resources::grant_relation):
//! taking away a relation you could not have given is still a change to
//! authority you do not hold.

use ianua_domain::domains::agents::authority::relation_change::RelationChange;
use ianua_domain::domains::agents::identity::control::AgentControl;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;

use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::use_case::Command;
use crate::use_cases::agents::delegation::resources::grant_relation::{
    ResourceGrantPorts, ResourceGrantRequest, relation_holding,
};

/// Revokes resource authority.
pub struct RevokeResourceRelationUseCase {
    ports: ResourceGrantPorts,
}

impl RevokeResourceRelationUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: ResourceGrantPorts) -> Self {
        Self { ports }
    }
}

impl Command for RevokeResourceRelationUseCase {
    type Caller = CallerContext;
    type Input = ResourceGrantRequest;
    type Output = Result<(), AppError>;

    /// Takes the relation `req.capability` names from `req.subject`.
    /// Removing a grant that does not exist succeeds.
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
        let mut change = RelationChange::<ResolvedTenant>::revoke(
            &AgentControl::new(&authority),
            holding,
            req.subject,
            req.capability,
        )
        .map_err(AppError::from_domain)?;
        self.ports
            .grants
            .revoke(&tenant, change.subject(), change.capability())
            .await
            .or_internal()?;
        auditor
            .dispatch_by(&ctx.actor(), change.take_events(&tenant))
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use ianua_domain::domains::agents::authority::capability::{
        Relation, ResourceCapability, ResourceRef,
    };
    use ianua_domain::domains::authorization::permission::{AgentAction, SystemPermission};
    use ianua_domain::types::{PrincipalRef, UserId};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::agents::FakeResourceGraph;
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    fn budget() -> ResourceCapability {
        ResourceCapability::new(
            Relation::new("owner").unwrap(),
            ResourceRef::new("doc:budget").unwrap(),
        )
    }

    /// A graph where Bob owns the budget.
    fn bob_owns_the_budget() -> (Arc<FakeResourceGraph>, PrincipalRef) {
        let graph = Arc::new(FakeResourceGraph::empty());
        let bob = PrincipalRef::User(UserId::new());
        graph.insert(&test_ctx().tenant(), bob, budget());
        (graph, bob)
    }

    fn ports(
        graph: &Arc<FakeResourceGraph>,
        authorities: FakeTenantAuthorities,
    ) -> ResourceGrantPorts {
        ResourceGrantPorts {
            resolver: graph.clone(),
            grants: graph.clone(),
            tenant_authorities: Arc::new(authorities),
        }
    }

    fn revoke(
        ports: ResourceGrantPorts,
        sink: &Arc<FakeEventDispatcher>,
        subject: PrincipalRef,
    ) -> Result<(), AppError> {
        block_on(RevokeResourceRelationUseCase::new(ports).execute(
            &test_ctx(),
            &test_auditor(sink.clone()),
            ResourceGrantRequest {
                subject,
                capability: budget(),
            },
        ))
    }

    /// A caller with delegation permission but no budget ownership cannot
    /// revoke the existing owner's relation.
    #[test]
    fn revoking_is_held_to_the_same_rule_as_granting() {
        let (graph, bob) = bob_owns_the_budget();
        let mallory = ports(
            &graph,
            FakeTenantAuthorities::holding(&[SystemPermission::Agents(AgentAction::Delegate)]),
        );

        let result = revoke(mallory, &Arc::new(FakeEventDispatcher::new()), bob);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(graph.count(), 1);
    }

    /// Ann administers agents and takes Bob's ownership of the budget away.
    /// It is gone and the change is recorded.
    #[test]
    fn a_revoke_is_recorded_in_the_audit_trail() {
        let (graph, bob) = bob_owns_the_budget();
        let ann = ports(
            &graph,
            FakeTenantAuthorities::holding(&[SystemPermission::Agents(AgentAction::Manage)]),
        );
        let sink = Arc::new(FakeEventDispatcher::new());

        revoke(ann, &sink, bob).unwrap();

        assert_eq!(graph.count(), 0);
        assert_eq!(
            sink.records.lock().unwrap().as_slice(),
            ["agents.resource_relation_revoked"]
        );
    }

    /// A signed-out caller cannot revoke the budget's existing ownership
    /// relation.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let (graph, bob) = bob_owns_the_budget();
        let replayed = ports(&graph, FakeTenantAuthorities::refusing(Refusal::SignedOut));

        let result = revoke(replayed, &Arc::new(FakeEventDispatcher::new()), bob);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(graph.count(), 1);
    }
}
