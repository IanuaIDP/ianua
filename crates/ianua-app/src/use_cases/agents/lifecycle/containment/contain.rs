//! Contain agent: the fleet kill-switch.
//!
//! One action stops an agent and everything it handed authority to: the
//! agent is revoked, its signing credentials are revoked, and every
//! delegation it holds is torn down with everything passed on or minted
//! from it.
//!
//! Revoking delegations alone is not containment. The agent would keep an
//! active identity and a live key, go straight back to the token endpoint
//! and mint itself a fresh delegation. Revoking the agent and its keys makes
//! containment terminal: signing in fails, there is nothing left to mint
//! from, and unlike a suspension nothing a resume can undo. A contained
//! workload that is trusted again is created anew as another agent.

use std::sync::Arc;

use ianua_domain::domains::agents::identity::agent::AgentIdentity;
use ianua_domain::domains::agents::identity::control::AgentControl;
use ianua_domain::domains::authorization::permission::AgentAction;
use ianua_domain::domains::crypto::key_status::KeyStatus;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::AgentId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::agents::{AgentCredentialStore, AgentStore, AgentVersion, DelegationStore};
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::agents::lookup::{AgentReach, owned_agent};

/// The ports [`ContainAgentUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ContainAgentPorts {
    /// Walks and revokes delegations.
    pub delegation_store: Arc<dyn DelegationStore>,
    /// Revokes the agent itself.
    pub agent_store: Arc<dyn AgentStore>,
    /// Revokes the agent's signing credentials.
    pub credential_store: Arc<dyn AgentCredentialStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Contains an agent: revokes it, its keys and everything it handed on.
pub struct ContainAgentUseCase {
    ports: ContainAgentPorts,
}

impl ContainAgentUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: ContainAgentPorts) -> Self {
        Self { ports }
    }
}

impl Command for ContainAgentUseCase {
    type Caller = CallerContext;
    type Input = AgentId;
    type Output = Result<u32, AppError>;

    /// Revokes the agent, its credentials, and every delegation it holds
    /// with everything cut from them, and returns how many delegations fell.
    ///
    /// Containing an agent already contained changes nothing and reports
    /// zero, though the attempt is still recorded.
    ///
    /// The agent is stopped before its delegations are walked. The other way
    /// round leaves a window in which the agent sees its delegations die and
    /// mints a new one from a key still live.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::NotFound` when the tenant has no such agent, or the
    ///   caller neither owns it nor may delete agents, so that an agent of
    ///   someone else's answers as one that does not exist.
    /// - `AppError::Conflict` when the agent changed since it was read, as
    ///   when it bootstrapped meanwhile; nothing is torn down, and asking
    ///   again contains it.
    /// - `AppError::Internal` on persistence or audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        agent_id: AgentId,
    ) -> Result<u32, AppError> {
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let control = AgentControl::new(&authority);
        let store = self.ports.agent_store.as_ref();
        let reach = AgentReach::Acting(AgentAction::Delete);
        let mut agent = owned_agent(store, &tenant, &agent_id, &control, reach).await?;
        stop_agent(&self.ports, &tenant, &control, &mut agent).await?;
        revoke_credentials(&self.ports, &tenant, &control, &agent).await?;
        let revoked_count =
            torn_down(self.ports.delegation_store.as_ref(), &tenant, &agent_id).await?;
        agent
            .record_containment(&control, revoked_count)
            .map_err(AppError::from_domain)?;
        auditor
            .dispatch_by(&ctx.actor(), agent.take_events(&tenant))
            .await
            .or_internal()?;
        Ok(revoked_count)
    }
}

/// Revokes the agent for good, so signing in stops working. A caller who
/// neither owns the agent nor may delete agents is refused, even when the
/// agent is already revoked and only its delegations are left. An agent
/// already revoked is not written again, so containment is safe to repeat.
async fn stop_agent(
    ports: &ContainAgentPorts,
    tenant: &ScopedTenant,
    control: &AgentControl<'_>,
    agent: &mut AgentIdentity<ResolvedTenant>,
) -> Result<(), AppError> {
    let read = AgentVersion::of(agent);
    let already_revoked = agent.status().is_revoked();
    agent.contain(control).map_err(AppError::from_domain)?;
    if already_revoked {
        return Ok(());
    }
    ports
        .agent_store
        .save_unchanged_since(tenant, agent, read)
        .await
        .map(|_| ())
        .map_err(AppError::from_domain)
}

/// Revokes every signing credential the agent could sign in with again. A
/// revoked key cannot be undone, so the old identity is never handed back.
/// What each key raised is left with it: the containment is the one record.
async fn revoke_credentials(
    ports: &ContainAgentPorts,
    tenant: &ScopedTenant,
    control: &AgentControl<'_>,
    agent: &AgentIdentity<ResolvedTenant>,
) -> Result<(), AppError> {
    let credentials = ports
        .credential_store
        .list_for_agent(tenant, agent.id())
        .await
        .or_internal()?;
    for mut credential in credentials
        .into_iter()
        .filter(|credential| credential.status() != KeyStatus::Revoked)
    {
        credential
            .revoke(control, agent)
            .map_err(AppError::from_domain)?;
        ports
            .credential_store
            .save(tenant, &credential)
            .await
            .or_internal()?;
    }
    Ok(())
}

/// How many delegations fell when every one the agent holds was torn down
/// with everything cut or minted from it.
///
/// One statement per delegation the agent holds, not two per node across
/// the whole radius: containment stays quick on exactly the sprawling
/// graphs that make it urgent.
async fn torn_down(
    store: &dyn DelegationStore,
    tenant: &ScopedTenant,
    agent_id: &AgentId,
) -> Result<u32, AppError> {
    let roots = store.list_for_agent(tenant, agent_id).await.or_internal()?;
    let mut revoked_count: u32 = 0;
    for root in &roots {
        let revoked = store
            .revoke_subtree(tenant, root.id())
            .await
            .or_internal()?;
        revoked_count =
            revoked_count.saturating_add(u32::try_from(revoked.len()).unwrap_or(u32::MAX));
    }
    Ok(revoked_count)
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::agents::authority::capability::CapabilitySet;
    use ianua_domain::domains::agents::authority::delegation::Delegation;
    use ianua_domain::domains::agents::identity::credential::AgentCredential;
    use ianua_domain::domains::agents::identity::status::AgentStatus;
    use ianua_domain::domains::authorization::permission::{RoutingAction, SystemPermission};
    use ianua_domain::types::{AgentCredentialId, PrincipalRef, UserId};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::agents::{
        FakeAgentCredentialStore, FakeAgentStore, FakeDelegationStore, caller_person,
        child_delegation, key_row, root_delegation,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// An agent's world: the agent, its keys and the delegation graph.
    struct World {
        agents: Arc<FakeAgentStore>,
        credentials: Arc<FakeAgentCredentialStore>,
        delegations: Arc<FakeDelegationStore>,
        sink: Arc<FakeEventDispatcher>,
    }

    impl World {
        /// One agent of Ann's, in `status`.
        fn with_callers_agent(id: AgentId, status: AgentStatus) -> Self {
            let agents = Arc::new(FakeAgentStore::empty());
            agents.add_owned(id, caller_person(), status);
            Self {
                agents,
                credentials: Arc::new(FakeAgentCredentialStore::empty()),
                delegations: Arc::new(FakeDelegationStore::empty()),
                sink: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn keep(&self, delegation: &Delegation<ResolvedTenant>) {
            block_on(self.delegations.save(&test_ctx().tenant(), delegation)).unwrap();
        }

        fn key_for(&self, agent: AgentId, kid: &str) -> AgentCredentialId {
            let credential = AgentCredential::reconstitute(key_row(agent, kid)).unwrap();
            block_on(self.credentials.save(&test_ctx().tenant(), &credential)).unwrap();
            *credential.id()
        }

        fn contain(
            &self,
            authorities: FakeTenantAuthorities,
            id: AgentId,
        ) -> Result<u32, AppError> {
            let use_case = ContainAgentUseCase::new(ContainAgentPorts {
                delegation_store: self.delegations.clone(),
                agent_store: self.agents.clone(),
                credential_store: self.credentials.clone(),
                tenant_authorities: Arc::new(authorities),
            });
            block_on(use_case.execute(&test_ctx(), &test_auditor(self.sink.clone()), id))
        }

        fn is_revoked(&self, id: &ianua_domain::types::DelegationId) -> bool {
            self.delegations
                .all()
                .iter()
                .any(|stored| stored.id() == id && stored.is_revoked())
        }

        fn status_of(&self, id: &AgentId) -> AgentStatus {
            self.agents.find_by_id_direct(id).unwrap().status()
        }
    }

    fn owner() -> FakeTenantAuthorities {
        FakeTenantAuthorities::holding(&[])
    }

    fn view_routes() -> CapabilitySet {
        CapabilitySet::new(vec![SystemPermission::Routing(RoutingAction::View)], vec![])
    }

    fn from_bob(agent: AgentId) -> Delegation<ResolvedTenant> {
        root_delegation(PrincipalRef::User(UserId::new()), agent, view_routes())
    }

    /// Ann contains her agent, which passed its delegation to a helper that
    /// passed it on again. All three delegations fall, and the containment
    /// is recorded with the count.
    #[test]
    fn the_agents_whole_subtree_falls() {
        let agent = AgentId::new();
        let world = World::with_callers_agent(agent, AgentStatus::Active);
        let root = from_bob(agent);
        let child = child_delegation(&root, AgentId::new(), view_routes());
        let grandchild = child_delegation(&child, AgentId::new(), view_routes());
        [&root, &child, &grandchild]
            .into_iter()
            .for_each(|d| world.keep(d));

        let count = world.contain(owner(), agent).unwrap();

        assert_eq!(count, 3);
        assert!(
            [root.id(), child.id(), grandchild.id()]
                .iter()
                .all(|id| world.is_revoked(id))
        );
        assert_eq!(
            world.sink.records.lock().unwrap().as_slice(),
            ["agents.agent_contained"]
        );
    }

    /// Ann contains an agent that holds no delegations. Nothing falls, and
    /// the containment is still recorded.
    #[test]
    fn an_agent_with_no_delegations_is_contained_with_a_zero_count() {
        let agent = AgentId::new();
        let world = World::with_callers_agent(agent, AgentStatus::Active);

        let count = world.contain(owner(), agent).unwrap();

        assert_eq!(count, 0);
        assert_eq!(
            world.sink.records.lock().unwrap().as_slice(),
            ["agents.agent_contained"]
        );
    }

    /// Ann contains her agent. A delegation Bob gave another agent is left
    /// alone.
    #[test]
    fn unrelated_delegations_survive() {
        let agent = AgentId::new();
        let world = World::with_callers_agent(agent, AgentStatus::Active);
        let survivor = from_bob(AgentId::new());
        world.keep(&from_bob(agent));
        world.keep(&survivor);

        world.contain(owner(), agent).unwrap();

        assert!(!world.is_revoked(survivor.id()));
    }

    /// Ann contains her agent. It is revoked for good, not suspended, so no
    /// resume hands it back and it cannot go back to the token endpoint.
    #[test]
    fn the_agent_is_revoked_for_good() {
        let agent = AgentId::new();
        let world = World::with_callers_agent(agent, AgentStatus::Active);

        world.contain(owner(), agent).unwrap();

        assert_eq!(world.status_of(&agent), AgentStatus::Revoked);
    }

    /// The drift monitor already suspended Ann's agent, the likeliest one to
    /// be contained. Containing it still revokes it.
    #[test]
    fn a_suspended_agent_is_revoked() {
        let agent = AgentId::new();
        let world = World::with_callers_agent(agent, AgentStatus::Suspended);

        world.contain(owner(), agent).unwrap();

        assert_eq!(world.status_of(&agent), AgentStatus::Revoked);
    }

    /// Ann contains her agent, which signs in with a key. The key is
    /// revoked, so the agent cannot sign in again.
    #[test]
    fn every_signing_credential_is_revoked() {
        let agent = AgentId::new();
        let world = World::with_callers_agent(agent, AgentStatus::Active);
        let key = world.key_for(agent, "kid-1");

        world.contain(owner(), agent).unwrap();

        assert_eq!(world.credentials.status_of(&key), Some(KeyStatus::Revoked));
    }

    /// Ann contains her agent. Another agent's key is left working.
    #[test]
    fn another_agents_credentials_are_left_alone() {
        let agent = AgentId::new();
        let world = World::with_callers_agent(agent, AgentStatus::Active);
        let other = world.key_for(AgentId::new(), "kid-2");

        world.contain(owner(), agent).unwrap();

        assert_eq!(world.credentials.status_of(&other), Some(KeyStatus::Active));
    }

    /// Ann presses the kill-switch twice. The second press changes nothing,
    /// reports zero and is not an error.
    #[test]
    fn containing_twice_is_harmless() {
        let agent = AgentId::new();
        let world = World::with_callers_agent(agent, AgentStatus::Active);
        world.keep(&from_bob(agent));
        world.key_for(agent, "kid-1");
        world.contain(owner(), agent).unwrap();

        let second = world.contain(owner(), agent);

        assert_eq!(second.unwrap(), 0);
        assert_eq!(world.status_of(&agent), AgentStatus::Revoked);
    }

    /// Ann contains an agent the tenant does not have. It is not found, and
    /// nothing is recorded.
    #[test]
    fn an_unknown_agent_is_not_found() {
        let world = World::with_callers_agent(AgentId::new(), AgentStatus::Active);

        let result = world.contain(owner(), AgentId::new());

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(world.sink.records.lock().unwrap().is_empty());
    }

    /// Bob, who may delete agents, contains Ann's leaking agent. It is
    /// revoked.
    #[test]
    fn someone_allowed_to_delete_agents_contains_anothers() {
        let agent = AgentId::new();
        let world = World::with_callers_agent(AgentId::new(), AgentStatus::Active);
        world.agents.add_active(agent);
        let bob = FakeTenantAuthorities::holding(&[SystemPermission::Agents(AgentAction::Delete)]);

        world.contain(bob, agent).unwrap();

        assert_eq!(world.status_of(&agent), AgentStatus::Revoked);
    }

    /// A viewer cannot contain another person's agent; it appears missing,
    /// stays active, and retains its unrevoked delegation.
    #[test]
    fn a_viewer_cannot_contain_anothers_agent() {
        let agent = AgentId::new();
        let world = World::with_callers_agent(AgentId::new(), AgentStatus::Active);
        world.agents.add_active(agent);
        let delegation = from_bob(agent);
        world.keep(&delegation);
        let sam = FakeTenantAuthorities::holding(&[SystemPermission::Agents(AgentAction::View)]);

        let result = world.contain(sam, agent);

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(world.status_of(&agent), AgentStatus::Active);
        assert!(!world.is_revoked(delegation.id()));
    }

    /// A revoked agent still requires containment authority; a viewer's
    /// attempt returns missing and leaves its delegation unrevoked.
    #[test]
    fn a_viewer_cannot_tear_down_a_revoked_agents_delegations() {
        let agent = AgentId::new();
        let world = World::with_callers_agent(AgentId::new(), AgentStatus::Active);
        world.agents.add_with_status(agent, AgentStatus::Revoked);
        let delegation = from_bob(agent);
        world.keep(&delegation);
        let sam = FakeTenantAuthorities::holding(&[SystemPermission::Agents(AgentAction::View)]);

        let result = world.contain(sam, agent);

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(!world.is_revoked(delegation.id()));
    }

    /// A signed-out owner cannot contain their agent, which remains active.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let agent = AgentId::new();
        let world = World::with_callers_agent(agent, AgentStatus::Active);

        let result = world.contain(FakeTenantAuthorities::refusing(Refusal::SignedOut), agent);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(world.status_of(&agent), AgentStatus::Active);
    }
}
