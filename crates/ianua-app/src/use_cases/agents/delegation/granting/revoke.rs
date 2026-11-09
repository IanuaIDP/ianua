//! Revoke delegation: take a delegation back, with everything cut or minted
//! from it.
//!
//! Whoever granted it may take it back, and so may the agent's owner or
//! someone allowed to delegate to agents. A delegation is live only while
//! everything above it is, so the whole subtree goes in one store statement
//! and the cost does not grow with the width of the graph torn down.

use std::sync::Arc;

use ianua_domain::domains::agents::authority::delegation::Revoker;
use ianua_domain::domains::agents::identity::control::AgentControl;
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

/// The ports [`RevokeUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RevokePorts {
    /// Loads the agent holding the delegation, for its owner.
    pub agent_store: Arc<dyn AgentStore>,
    /// Loads delegations and revokes subtrees.
    pub delegation_store: Arc<dyn DelegationStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Which delegation to revoke, addressed under the agent holding it.
pub struct RevokeRequest {
    /// The agent the address named; the delegation must be one of its own.
    pub agent_id: AgentId,
    /// The delegation to revoke, with its whole subtree.
    pub delegation_id: DelegationId,
}

/// Takes delegations back.
pub struct RevokeUseCase {
    ports: RevokePorts,
}

impl RevokeUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: RevokePorts) -> Self {
        Self { ports }
    }
}

impl Command for RevokeUseCase {
    type Caller = CallerContext;
    type Input = RevokeRequest;
    type Output = Result<(), AppError>;

    /// Revokes the delegation `request` names and everything cut or minted
    /// from it.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::NotFound` when the delegation does not exist, is not the
    ///   named agent's, or the caller neither granted it, owns the agent,
    ///   nor may delegate to agents, so that it answers as one that does not
    ///   exist.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: RevokeRequest,
    ) -> Result<(), AppError> {
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let control = AgentControl::new(&authority);
        let store = self.ports.delegation_store.as_ref();
        let address = DelegationAddress {
            agent_id: request.agent_id,
            delegation_id: request.delegation_id,
        };
        let agents = self.ports.agent_store.as_ref();
        let DelegationOfAgent {
            mut delegation,
            agent,
        } = owned_delegation_to_revoke(store, agents, &tenant, address, &control).await?;
        delegation
            .revoke(Revoker::Person {
                control,
                agent_owner: agent.owner(),
            })
            .map_err(AppError::from_domain)?;
        store
            .revoke_subtree(&tenant, delegation.id())
            .await
            .or_internal()?;
        auditor
            .dispatch_by(&ctx.actor(), delegation.take_events(&tenant))
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::agents::authority::capability::CapabilitySet;
    use ianua_domain::domains::agents::authority::delegation::{
        Delegation, DelegationRenewal, DelegationRow, DelegationStatus, Lineage,
    };
    use ianua_domain::domains::authorization::permission::{RoutingAction, SystemPermission};
    use ianua_domain::isolation::scope::ResolvedTenant;
    use ianua_domain::shared::clock;
    use ianua_domain::shared::events::data::FieldValue;
    use ianua_domain::shared::model::aggregate::Aggregate;
    use ianua_domain::types::{AgentCredentialId, Label, PrincipalRef, UserId};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::agents::{
        FakeAgentStore, FakeDelegationStore, caller_person, callers_agent, child_delegation,
        root_delegation,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    fn caps() -> CapabilitySet {
        CapabilitySet::new(vec![SystemPermission::Routing(RoutingAction::View)], vec![])
    }

    /// The delegation store, the agents and the delegation to revoke.
    struct Bench {
        delegations: Arc<FakeDelegationStore>,
        agents: Arc<FakeAgentStore>,
        root: Delegation<ResolvedTenant>,
    }

    fn bench_with(agents: FakeAgentStore, root: Delegation<ResolvedTenant>) -> Bench {
        let delegations = FakeDelegationStore::empty();
        block_on(delegations.save(&test_ctx().tenant(), &root)).unwrap();
        Bench {
            delegations: Arc::new(delegations),
            agents: Arc::new(agents),
            root,
        }
    }

    /// A delegation from someone else to the caller's own agent.
    fn bench() -> Bench {
        let agent = AgentId::new();
        let root = root_delegation(PrincipalRef::User(UserId::new()), agent, caps());
        bench_with(callers_agent(agent), root)
    }

    impl Bench {
        fn save(&self, delegation: &Delegation<ResolvedTenant>) {
            block_on(self.delegations.save(&test_ctx().tenant(), delegation)).unwrap();
        }

        fn ports(&self) -> RevokePorts {
            RevokePorts {
                agent_store: self.agents.clone(),
                delegation_store: self.delegations.clone(),
                ..RevokePorts::fakes()
            }
        }

        fn request(&self) -> RevokeRequest {
            RevokeRequest {
                agent_id: *self.root.delegate(),
                delegation_id: *self.root.id(),
            }
        }

        fn is_revoked(&self, id: &DelegationId) -> bool {
            block_on(self.delegations.find_by_id(&test_ctx().tenant(), id))
                .unwrap()
                .unwrap()
                .is_revoked()
        }
    }

    fn revoke(
        ports: RevokePorts,
        sink: &Arc<FakeEventDispatcher>,
        request: RevokeRequest,
    ) -> Result<(), AppError> {
        block_on(RevokeUseCase::new(ports).execute(
            &test_ctx(),
            &test_auditor(sink.clone()),
            request,
        ))
    }

    fn quietly(ports: RevokePorts, request: RevokeRequest) -> Result<(), AppError> {
        revoke(ports, &Arc::new(FakeEventDispatcher::new()), request)
    }

    /// Ann revokes her agent's delegation, which it passed on twice. All
    /// three are revoked, and the revoke is recorded.
    #[test]
    fn revoking_takes_everything_passed_on_with_it() {
        let b = bench();
        let child = child_delegation(&b.root, AgentId::new(), caps());
        let grandchild = child_delegation(&child, AgentId::new(), caps());
        b.save(&child);
        b.save(&grandchild);
        let sink = Arc::new(FakeEventDispatcher::new());

        revoke(b.ports(), &sink, b.request()).unwrap();

        for id in [b.root.id(), child.id(), grandchild.id()] {
            assert!(b.is_revoked(id));
        }
        assert_eq!(
            sink.records.lock().unwrap().as_slice(),
            ["agents.delegation_revoked"]
        );
    }

    /// The agent minted itself a token's delegation from the grant. Ann
    /// revokes the grant, and the minted delegation goes with it.
    #[test]
    fn revoking_reaches_what_was_minted_from_it() {
        let b = bench();
        let agent = *b.root.delegate();
        let now = clock::now();
        let minted = Delegation::reconstitute(DelegationRow {
            id: DelegationId::new(),
            delegator: PrincipalRef::Agent(agent),
            delegate: agent,
            granted: caps(),
            constraints: b.root.constraints().clone(),
            lineage: Lineage::Minted {
                from: vec![*b.root.id()],
                delegator: *b.root.delegator(),
                signed_in_with: AgentCredentialId::new(),
            },
            depth: 0,
            status: DelegationStatus::Active,
            issued_at: now,
            expires_at: b.root.expires_at(),
            renewed: DelegationRenewal::NotRenewed,
            updated_at: now,
            name: None,
        })
        .unwrap();
        b.save(&minted);

        quietly(b.ports(), b.request()).unwrap();

        assert!(b.is_revoked(minted.id()));
    }

    /// Ann titles the delegation "Q1 reconciliation delegation". The record
    /// of its revoke names it so.
    #[test]
    fn the_record_prefers_the_delegations_title() {
        let agent = AgentId::new();
        let root = Delegation::reconstitute(DelegationRow {
            name: Some(Label::new("name", "Q1 reconciliation delegation").unwrap()),
            ..row_of(&root_delegation(
                PrincipalRef::User(UserId::new()),
                agent,
                caps(),
            ))
        })
        .unwrap();
        let b = bench_with(callers_agent(agent), root);
        let sink = Arc::new(FakeEventDispatcher::new());

        revoke(b.ports(), &sink, b.request()).unwrap();

        let payload = sink.payload_of("agents.delegation_revoked");
        let Some(FieldValue::Reference(reference)) = payload.value("delegation") else {
            panic!("the record names the delegation");
        };
        assert_eq!(reference.label(), "Q1 reconciliation delegation");
    }

    /// Revoking through another agent's address reports the delegation as
    /// missing and leaves it unrevoked.
    #[test]
    fn a_delegation_addressed_under_another_agent_is_not_found() {
        let b = bench();
        let mut request = b.request();
        request.agent_id = AgentId::new();

        let result = quietly(b.ports(), request);

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(!b.is_revoked(b.root.id()));
    }

    /// Ann revokes a delegation that does not exist. It is not found.
    #[test]
    fn an_unknown_delegation_is_not_found() {
        let b = bench();
        let mut request = b.request();
        request.delegation_id = DelegationId::new();

        assert!(matches!(
            quietly(b.ports(), request),
            Err(AppError::NotFound(_))
        ));
    }

    /// Ann granted Bob's agent a delegation and holds no agent rights. She
    /// takes it back all the same.
    #[test]
    fn the_person_who_granted_it_takes_it_back() {
        let agent = AgentId::new();
        let root = root_delegation(caller_person().principal(), agent, caps());
        let b = bench_with(FakeAgentStore::with_active(agent), root);
        let ports = RevokePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[])),
            ..b.ports()
        };

        quietly(ports, b.request()).unwrap();

        assert!(b.is_revoked(b.root.id()));
    }

    /// A caller without authority over the agent or its grant sees the
    /// delegation as missing and cannot revoke it.
    #[test]
    fn a_caller_with_no_say_is_refused() {
        let agent = AgentId::new();
        let root = root_delegation(PrincipalRef::User(UserId::new()), agent, caps());
        let b = bench_with(FakeAgentStore::with_active(agent), root);
        let ports = RevokePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[])),
            ..b.ports()
        };

        let result = quietly(ports, b.request());

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(!b.is_revoked(b.root.id()));
    }

    /// A signed-out caller cannot revoke the delegation, which stays unrevoked.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let b = bench();
        let ports = RevokePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..b.ports()
        };

        let result = quietly(ports, b.request());

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert!(!b.is_revoked(b.root.id()));
    }

    fn row_of(delegation: &Delegation<ResolvedTenant>) -> DelegationRow {
        DelegationRow {
            id: *delegation.id(),
            delegator: *delegation.delegator(),
            delegate: *delegation.delegate(),
            granted: delegation.granted().clone(),
            constraints: delegation.constraints().clone(),
            lineage: delegation.lineage().clone(),
            depth: delegation.depth(),
            status: DelegationStatus::Active,
            issued_at: delegation.created_at(),
            expires_at: delegation.expires_at(),
            renewed: delegation.renewed(),
            updated_at: delegation.updated_at(),
            name: None,
        }
    }
}
