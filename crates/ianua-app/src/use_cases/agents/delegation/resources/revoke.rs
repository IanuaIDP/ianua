//! Revoke delegation resource: remove one resource capability from a
//! delegation and keep the rest of what it grants.
//!
//! Removing a capability only narrows what the delegation carries, so
//! nothing it is taken from bounds it. Who may take it is still the domain's
//! call: the person who granted the delegation, the agent's owner, or
//! someone allowed to delegate to agents. Removing a capability the
//! delegation does not carry changes nothing.

use std::sync::Arc;

use ianua_domain::domains::agents::authority::capability::{Relation, ResourceRef};
use ianua_domain::domains::agents::authority::delegation::{Delegation, Revoker};
use ianua_domain::domains::agents::identity::control::AgentControl;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{AgentId, DelegationId};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::agents::{AgentStore, DelegationStore};
use crate::use_case::Command;
use crate::use_cases::agents::lookup::{
    DelegationAddress, DelegationOfAgent, owned_delegation_to_revoke,
};

/// Request to revoke a single resource capability from an existing delegation.
pub struct RevokeResourceRequest {
    /// The agent the route named. The delegation must be one of its own.
    pub agent_id: AgentId,
    /// The delegation losing the capability.
    pub delegation_id: DelegationId,
    /// The relation being revoked.
    pub relation: Relation,
    /// The object reference being revoked.
    pub resource_ref: ResourceRef,
}

/// The ports [`RevokeResourceUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RevokeResourcePorts {
    /// Loads and saves the delegation.
    pub delegation_store: Arc<dyn DelegationStore>,
    /// The agent holding the delegation, whose owner has a say over it.
    pub agent_store: Arc<dyn AgentStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Revokes a single resource capability from an existing delegation.
pub struct RevokeResourceUseCase {
    ports: RevokeResourcePorts,
}

impl RevokeResourceUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: RevokeResourcePorts) -> Self {
        Self { ports }
    }
}

impl Command for RevokeResourceUseCase {
    type Caller = CallerContext;
    type Input = RevokeResourceRequest;
    type Output = Result<Delegation<ResolvedTenant>, AppError>;

    /// Removes the `{relation, resource}` pair from the delegation, in
    /// place. A pair it does not carry changes nothing.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::NotFound` when the delegation or its agent does not
    ///   exist, the delegation is not the named agent's, or the caller
    ///   neither granted it nor has a say over its agent, so that it answers
    ///   as one that does not exist.
    /// - `AppError::Domain` when the delegation is revoked.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        req: RevokeResourceRequest,
    ) -> Result<Delegation<ResolvedTenant>, AppError> {
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let control = AgentControl::new(&authority);
        let store = self.ports.delegation_store.as_ref();
        let address = DelegationAddress {
            agent_id: req.agent_id,
            delegation_id: req.delegation_id,
        };
        let agents = self.ports.agent_store.as_ref();
        let DelegationOfAgent {
            mut delegation,
            agent,
        } = owned_delegation_to_revoke(store, agents, &tenant, address, &control).await?;
        let revoker = Revoker::Person {
            control,
            agent_owner: agent.owner(),
        };
        delegation
            .revoke_resource(revoker, &req.relation, &req.resource_ref)
            .map_err(AppError::from_domain)?;
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
    use ianua_domain::domains::agents::authority::capability::{
        CapabilitySet, DelegationConstraints, ResourceCapability,
    };
    use ianua_domain::domains::agents::authority::delegation::{DelegationStatus, Lineage};
    use ianua_domain::domains::authorization::permission::{AgentAction, SystemPermission};
    use ianua_domain::types::{PrincipalRef, Seconds, UserId};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::agents::{
        FakeAgentStore, FakeDelegationStore, StoredGrant, caller_person, resource_cap,
        stored_delegation,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// A tenant with one agent, owned by a person other than the caller,
    /// holding a delegation that grants the ledger.
    struct Tenant {
        delegations: Arc<FakeDelegationStore>,
        agents: Arc<FakeAgentStore>,
        delegation: Delegation<ResolvedTenant>,
    }

    impl Tenant {
        fn granted_by(delegator: PrincipalRef, status: DelegationStatus) -> Self {
            let agent = AgentId::new();
            let delegation = stored_delegation(StoredGrant {
                delegator,
                delegate: agent,
                granted: CapabilitySet::empty()
                    .with_resources(vec![resource_cap("reader", "ledger:2026-q1")]),
                constraints: DelegationConstraints::new(Seconds::new(600), 1).unwrap(),
                lineage: Lineage::Root,
                status,
            });
            let delegations = Arc::new(FakeDelegationStore::empty());
            block_on(delegations.save(&test_ctx().tenant(), &delegation)).unwrap();
            Self {
                delegations,
                agents: Arc::new(FakeAgentStore::with_active(agent)),
                delegation,
            }
        }

        fn by_caller() -> Self {
            Self::granted_by(caller_person().principal(), DelegationStatus::Active)
        }

        fn ports(&self) -> RevokeResourcePorts {
            RevokeResourcePorts {
                delegation_store: self.delegations.clone(),
                agent_store: self.agents.clone(),
                ..RevokeResourcePorts::fakes()
            }
        }

        fn grants(&self) -> Vec<ResourceCapability> {
            block_on(
                self.delegations
                    .find_by_id(&test_ctx().tenant(), self.delegation.id()),
            )
            .unwrap()
            .unwrap()
            .granted()
            .resources()
            .to_vec()
        }

        fn take(
            &self,
            ports: RevokeResourcePorts,
            capability: &ResourceCapability,
        ) -> Result<Delegation<ResolvedTenant>, AppError> {
            block_on(RevokeResourceUseCase::new(ports).execute(
                &test_ctx(),
                &test_auditor(Arc::new(FakeEventDispatcher::new())),
                RevokeResourceRequest {
                    agent_id: *self.delegation.delegate(),
                    delegation_id: *self.delegation.id(),
                    relation: capability.relation().clone(),
                    resource_ref: capability.resource_ref().clone(),
                },
            ))
        }
    }

    fn holding(rights: &[SystemPermission]) -> Arc<FakeTenantAuthorities> {
        Arc::new(FakeTenantAuthorities::holding(rights))
    }

    /// Ann takes the ledger back from the delegation she gave. It no longer
    /// grants it, as stored too, and the change is recorded.
    #[test]
    fn the_delegator_takes_a_resource_back() {
        let tenant = Tenant::by_caller();
        let sink = Arc::new(FakeEventDispatcher::new());

        block_on(
            RevokeResourceUseCase::new(tenant.ports()).execute(
                &test_ctx(),
                &test_auditor(sink.clone()),
                RevokeResourceRequest {
                    agent_id: *tenant.delegation.delegate(),
                    delegation_id: *tenant.delegation.id(),
                    relation: resource_cap("reader", "ledger:2026-q1").relation().clone(),
                    resource_ref: resource_cap("reader", "ledger:2026-q1")
                        .resource_ref()
                        .clone(),
                },
            ),
        )
        .unwrap();

        assert!(tenant.grants().is_empty());
        assert_eq!(
            sink.records.lock().unwrap().as_slice(),
            ["agents.delegation_resource_revoked"]
        );
    }

    /// Ann takes back a calendar the delegation never granted. Nothing
    /// changes and the ledger stays.
    #[test]
    fn taking_back_what_it_does_not_grant_changes_nothing() {
        let tenant = Tenant::by_caller();
        let calendar = ResourceCapability::new(
            Relation::new("owner").unwrap(),
            ResourceRef::new("calendar:abc").unwrap(),
        );

        let result = tenant.take(tenant.ports(), &calendar).unwrap();

        assert_eq!(
            result.granted().resources(),
            &[resource_cap("reader", "ledger:2026-q1")]
        );
    }

    /// Bob may delegate to agents. He takes the ledger back from a
    /// delegation someone else gave. It no longer grants it.
    #[test]
    fn someone_allowed_to_delegate_takes_a_resource_back() {
        let tenant =
            Tenant::granted_by(PrincipalRef::User(UserId::new()), DelegationStatus::Active);
        let bob = RevokeResourcePorts {
            tenant_authorities: holding(&[SystemPermission::Agents(AgentAction::Delegate)]),
            ..tenant.ports()
        };

        tenant
            .take(bob, &resource_cap("reader", "ledger:2026-q1"))
            .unwrap();

        assert!(tenant.grants().is_empty());
    }

    /// A viewer without ownership or grant authority sees the delegation as
    /// missing and cannot remove its ledger capability.
    #[test]
    fn a_caller_without_a_say_over_the_agent_is_refused() {
        let tenant =
            Tenant::granted_by(PrincipalRef::User(UserId::new()), DelegationStatus::Active);
        let mallory = RevokeResourcePorts {
            tenant_authorities: holding(&[SystemPermission::Agents(AgentAction::View)]),
            ..tenant.ports()
        };

        let result = tenant.take(mallory, &resource_cap("reader", "ledger:2026-q1"));

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(
            tenant.grants(),
            vec![resource_cap("reader", "ledger:2026-q1")]
        );
    }

    /// Removing a resource through another agent's address reports the
    /// delegation as missing.
    #[test]
    fn a_delegation_named_through_another_agent_is_not_found() {
        let tenant = Tenant::by_caller();

        let result = block_on(
            RevokeResourceUseCase::new(tenant.ports()).execute(
                &test_ctx(),
                &test_auditor(Arc::new(FakeEventDispatcher::new())),
                RevokeResourceRequest {
                    agent_id: AgentId::new(),
                    delegation_id: *tenant.delegation.id(),
                    relation: resource_cap("reader", "ledger:2026-q1").relation().clone(),
                    resource_ref: resource_cap("reader", "ledger:2026-q1")
                        .resource_ref()
                        .clone(),
                },
            ),
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Removing a resource from a revoked delegation fails and preserves
    /// its stored ledger capability.
    #[test]
    fn a_revoked_delegation_is_not_changed() {
        let tenant = Tenant::granted_by(caller_person().principal(), DelegationStatus::Revoked);

        let result = tenant.take(tenant.ports(), &resource_cap("reader", "ledger:2026-q1"));

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert_eq!(
            tenant.grants(),
            vec![resource_cap("reader", "ledger:2026-q1")]
        );
    }

    /// A signed-out caller cannot remove the delegation's ledger capability.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let tenant = Tenant::by_caller();
        let ports = RevokeResourcePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..tenant.ports()
        };

        let result = tenant.take(ports, &resource_cap("reader", "ledger:2026-q1"));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(
            tenant.grants(),
            vec![resource_cap("reader", "ledger:2026-q1")]
        );
    }
}
