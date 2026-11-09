//! Withdraw agent offer: an offer of an agent ends unaccepted.
//!
//! Ann changes her mind about handing her agent to Bob and withdraws the
//! offer, or Bob does not want it and declines. Either way the agent stays
//! Ann's and nobody may accept the offer any more.

use std::sync::Arc;

use ianua_domain::domains::agents::identity::control::AgentControl;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::AgentId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::agents::{AgentStore, AgentVersion};
use crate::use_case::Command;
use crate::use_cases::agents::lookup::{AgentReach, owned_agent};

/// The ports [`WithdrawAgentOfferUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct WithdrawAgentOfferPorts {
    /// Loads and saves agents.
    pub agent_store: Arc<dyn AgentStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Ends offers of agents nobody accepted.
pub struct WithdrawAgentOfferUseCase {
    ports: WithdrawAgentOfferPorts,
}

impl WithdrawAgentOfferUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: WithdrawAgentOfferPorts) -> Self {
        Self { ports }
    }
}

impl Command for WithdrawAgentOfferUseCase {
    type Caller = CallerContext;
    type Input = AgentId;
    type Output = Result<(), AppError>;

    /// Ends the offer standing on `agent_id` and records
    /// `agents.agent_ownership_offer_withdrawn`. The owner, someone allowed
    /// to manage agents, or the person it was offered to may end it.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::NotFound` when the tenant has no such agent, or the
    ///   caller is neither the one it was offered to, its owner, nor allowed
    ///   to manage agents, so that an agent of someone else's answers as one
    ///   that does not exist.
    /// - `AppError::Conflict` when no offer stands on it, or it changed
    ///   since it was read.
    /// - `AppError::Internal` on persistence or audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        agent_id: AgentId,
    ) -> Result<(), AppError> {
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let control = AgentControl::new(&authority);
        let store = self.ports.agent_store.as_ref();
        let reach = AgentReach::EndingOffer;
        let mut agent = owned_agent(store, &tenant, &agent_id, &control, reach).await?;
        let read = AgentVersion::of(&agent);
        agent
            .withdraw_offer(&control)
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
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::agents::identity::agent::{
        AgentIdentity, AgentIdentityRow, OFFER_LIFETIME, OwnershipOffer,
    };
    use ianua_domain::domains::authorization::permission::{AgentAction, SystemPermission};
    use ianua_domain::shared::clock;
    use ianua_domain::types::Human;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::agents::{FakeAgentStore, agent_row, caller_person, someone};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// An agent `owner` owns, offered to `recipient`, and the store keeping
    /// it.
    fn offered(owner: Human, recipient: Human) -> (Arc<FakeAgentStore>, AgentId) {
        let id = AgentId::new();
        let registered = agent_row(id, owner);
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

    fn withdraw(
        ports: WithdrawAgentOfferPorts,
        sink: &Arc<FakeEventDispatcher>,
        agent_id: AgentId,
    ) -> Result<(), AppError> {
        block_on(WithdrawAgentOfferUseCase::new(ports).execute(
            &test_ctx(),
            &test_auditor(sink.clone()),
            agent_id,
        ))
    }

    fn ports_over(agents: &Arc<FakeAgentStore>) -> WithdrawAgentOfferPorts {
        WithdrawAgentOfferPorts {
            agent_store: agents.clone(),
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[])),
        }
    }

    fn offer_of(agents: &FakeAgentStore, id: &AgentId) -> OwnershipOffer {
        agents.find_by_id_direct(id).unwrap().offer().clone()
    }

    /// Ann withdraws the offer of her agent to Bob. It is no longer on
    /// offer, and the end is recorded.
    #[test]
    fn the_owner_withdraws_an_offer() {
        let (agents, id) = offered(caller_person(), someone("bob@example.test"));
        let sink = Arc::new(FakeEventDispatcher::new());

        withdraw(ports_over(&agents), &sink, id).unwrap();

        assert_eq!(offer_of(&agents, &id), OwnershipOffer::Unoffered);
        assert_eq!(
            sink.records.lock().unwrap().as_slice(),
            ["agents.agent_ownership_offer_withdrawn"]
        );
    }

    /// Owen offered his agent to Ann, who does not want it. She declines,
    /// holding no agent permission at all.
    #[test]
    fn the_recipient_declines_an_offer() {
        let (agents, id) = offered(someone("owen@example.test"), caller_person());

        withdraw(
            ports_over(&agents),
            &Arc::new(FakeEventDispatcher::new()),
            id,
        )
        .unwrap();

        assert_eq!(offer_of(&agents, &id), OwnershipOffer::Unoffered);
    }

    /// A viewer outside the ownership offer cannot withdraw it; the agent
    /// appears missing, the offer stands, and no withdrawal is recorded.
    #[test]
    fn a_stranger_to_the_offer_cannot_end_it() {
        let (agents, id) = offered(someone("owen@example.test"), someone("bob@example.test"));
        let ports = WithdrawAgentOfferPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
                SystemPermission::Agents(AgentAction::View),
            ])),
            ..ports_over(&agents)
        };
        let sink = Arc::new(FakeEventDispatcher::new());

        let result = withdraw(ports, &sink, id);

        assert!(matches!(result, Err(AppError::NotFound(_))), "{result:?}");
        assert_ne!(offer_of(&agents, &id), OwnershipOffer::Unoffered);
        assert!(sink.records.lock().unwrap().is_empty());
    }

    /// Ann withdraws an offer from an agent of hers nobody was offered. It
    /// is a conflict.
    #[test]
    fn an_agent_not_on_offer_is_a_conflict() {
        let id = AgentId::new();
        let agents = Arc::new(FakeAgentStore::empty());
        agents.add_owned_by(id, caller_person());

        let result = withdraw(
            ports_over(&agents),
            &Arc::new(FakeEventDispatcher::new()),
            id,
        );

        assert!(matches!(result, Err(AppError::Conflict(_))), "{result:?}");
    }

    /// A signed-out owner cannot withdraw their offer, which remains stored.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let (agents, id) = offered(caller_person(), someone("bob@example.test"));
        let ports = WithdrawAgentOfferPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..ports_over(&agents)
        };

        let result = withdraw(ports, &Arc::new(FakeEventDispatcher::new()), id);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_ne!(offer_of(&agents, &id), OwnershipOffer::Unoffered);
    }
}
