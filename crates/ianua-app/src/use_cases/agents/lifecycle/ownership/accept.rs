//! Accept agent: the person an agent was offered to takes it over.
//!
//! Bob was offered Ann's agent. He accepts it, signed in himself, and
//! becomes its owner. What he holds now is read from his own sign-in, so a
//! right he lost since the offer was made no longer counts.

use std::sync::Arc;

use ianua_domain::domains::agents::identity::agent::AgentIdentity;
use ianua_domain::domains::agents::identity::control::AgentControl;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::AgentId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::agents::{AgentStore, AgentVersion};
use crate::use_case::Command;
use crate::use_cases::agents::lookup::{AgentReach, owned_agent};

/// The ports [`AcceptAgentUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct AcceptAgentPorts {
    /// Loads and saves agents.
    pub agent_store: Arc<dyn AgentStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Hands offered agents to the people who accept them.
pub struct AcceptAgentUseCase {
    ports: AcceptAgentPorts,
}

impl AcceptAgentUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: AcceptAgentPorts) -> Self {
        Self { ports }
    }
}

impl Command for AcceptAgentUseCase {
    type Caller = CallerContext;
    type Input = AgentId;
    type Output = Result<AgentIdentity<ResolvedTenant>, AppError>;

    /// Makes the caller the owner of `agent_id`, which was offered to them,
    /// records `agents.agent_ownership_transferred` naming both owners, and
    /// returns the agent as it stands.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::NotFound` when the tenant has no such agent, or no offer
    ///   of it is standing or lapsed for the caller, so that an agent offered
    ///   to someone else answers as one that does not exist.
    /// - `AppError::Conflict` when the offer lapsed, or the agent changed
    ///   since it was read.
    /// - `AppError::Forbidden` when the caller may no longer create agents.
    /// - `AppError::Internal` on persistence or audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        agent_id: AgentId,
    ) -> Result<AgentIdentity<ResolvedTenant>, AppError> {
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let control = AgentControl::new(&authority);
        let store = self.ports.agent_store.as_ref();
        let mut agent =
            owned_agent(store, &tenant, &agent_id, &control, AgentReach::Offered).await?;
        let read = AgentVersion::of(&agent);
        agent
            .accept_ownership(&control)
            .map_err(AppError::from_domain)?;
        self.ports
            .agent_store
            .save_unchanged_since(&tenant, &agent, read)
            .await
            .map_err(AppError::from_domain)?;
        auditor
            .dispatch_by(&ctx.actor(), agent.take_events(&tenant))
            .await
            .or_internal()?;
        Ok(agent)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::agents::identity::agent::{
        AgentIdentityRow, OFFER_LIFETIME, OwnershipOffer,
    };
    use ianua_domain::domains::authorization::permission::{AgentAction, SystemPermission};
    use ianua_domain::shared::clock;
    use ianua_domain::types::Human;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::agents::{FakeAgentStore, agent_row, caller_person, someone};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// Owen's agent, offered to `recipient`, and the store keeping it.
    fn offered_to(recipient: Human) -> (Arc<FakeAgentStore>, AgentId) {
        let id = AgentId::new();
        let registered = agent_row(id, someone("owen@example.test"));
        let now = clock::now();
        let row = AgentIdentityRow {
            offer: OwnershipOffer::Open {
                recipient,
                offered_at: now,
                expires_at: now.saturating_add(OFFER_LIFETIME),
            },
            ..registered
        };
        let agents = Arc::new(FakeAgentStore::empty());
        block_on(agents.save(
            &test_ctx().tenant(),
            &AgentIdentity::reconstitute(row).unwrap(),
        ))
        .unwrap();
        (agents, id)
    }

    fn accept(
        ports: AcceptAgentPorts,
        sink: &Arc<FakeEventDispatcher>,
        agent_id: AgentId,
    ) -> Result<AgentIdentity<ResolvedTenant>, AppError> {
        block_on(AcceptAgentUseCase::new(ports).execute(
            &test_ctx(),
            &test_auditor(sink.clone()),
            agent_id,
        ))
    }

    fn owner_of(agents: &FakeAgentStore, id: &AgentId) -> Human {
        agents.find_by_id_direct(id).unwrap().owner().clone()
    }

    /// Owen offered his agent to Ann. She accepts it, owns it now, and the
    /// move is recorded.
    #[test]
    fn the_person_offered_an_agent_accepts_it() {
        let (agents, id) = offered_to(caller_person());
        let sink = Arc::new(FakeEventDispatcher::new());
        let ports = AcceptAgentPorts {
            agent_store: agents.clone(),
            ..AcceptAgentPorts::fakes()
        };

        let agent = accept(ports, &sink, id).unwrap();

        assert_eq!(agent.owner().account(), caller_person().account());
        assert_eq!(owner_of(&agents, &id).account(), caller_person().account());
        assert_eq!(
            sink.records.lock().unwrap().as_slice(),
            ["agents.agent_ownership_transferred"]
        );
    }

    /// Accepting an offer addressed to someone else returns missing;
    /// the original owner remains and no transfer is recorded.
    #[test]
    fn an_agent_offered_to_someone_else_is_not_taken() {
        let owen = someone("owen@example.test");
        let (agents, id) = offered_to(someone("bob@example.test"));
        let sink = Arc::new(FakeEventDispatcher::new());
        let ports = AcceptAgentPorts {
            agent_store: agents.clone(),
            ..AcceptAgentPorts::fakes()
        };

        let result = accept(ports, &sink, id);

        assert!(matches!(result, Err(AppError::NotFound(_))), "{result:?}");
        assert!(owner_of(&agents, &id).is_same_person_as(&owen));
        assert!(sink.records.lock().unwrap().is_empty());
    }

    /// A recipient without the create right cannot accept an offered agent
    /// and does not become its stored owner.
    #[test]
    fn a_recipient_who_may_no_longer_create_agents_is_refused() {
        let (agents, id) = offered_to(caller_person());
        let ports = AcceptAgentPorts {
            agent_store: agents.clone(),
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
                SystemPermission::Agents(AgentAction::View),
            ])),
        };

        let result = accept(ports, &Arc::new(FakeEventDispatcher::new()), id);

        assert!(matches!(result, Err(AppError::Forbidden(_))), "{result:?}");
        assert_ne!(owner_of(&agents, &id).account(), caller_person().account());
    }

    /// An agent with no ownership offer produces the same missing response
    /// as an unknown id when the caller tries to accept it.
    #[test]
    fn an_agent_not_offered_answers_as_an_unknown_one() {
        let id = AgentId::new();
        let agents = Arc::new(FakeAgentStore::empty());
        agents.add_owned_by(id, someone("owen@example.test"));
        let ports = || AcceptAgentPorts {
            agent_store: agents.clone(),
            ..AcceptAgentPorts::fakes()
        };

        let not_offered = accept(ports(), &Arc::new(FakeEventDispatcher::new()), id);
        let unknown = accept(
            ports(),
            &Arc::new(FakeEventDispatcher::new()),
            AgentId::new(),
        );

        assert!(
            matches!(not_offered, Err(AppError::NotFound(_))),
            "{not_offered:?}"
        );
        assert_eq!(format!("{not_offered:?}"), format!("{unknown:?}"));
    }

    /// A signed-out recipient cannot accept an offered agent and does not
    /// become its owner.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let (agents, id) = offered_to(caller_person());
        let ports = AcceptAgentPorts {
            agent_store: agents.clone(),
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
        };

        let result = accept(ports, &Arc::new(FakeEventDispatcher::new()), id);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_ne!(owner_of(&agents, &id).account(), caller_person().account());
    }
}
