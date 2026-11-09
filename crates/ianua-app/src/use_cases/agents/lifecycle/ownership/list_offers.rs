//! List agent offers: the agents offered to the caller and waiting for
//! their answer.
//!
//! Bob hears Ann offered him her agent. He looks here for what waits for
//! him, then accepts or declines it. Each person sees only the offers made
//! to their own account, and none that lapsed.

use std::sync::Arc;

use ianua_domain::domains::agents::identity::agent::AgentIdentity;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::clock;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::agents::AgentStore;
use crate::use_case::Query;

/// The ports [`ListAgentOffersUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ListAgentOffersPorts {
    /// Reads agents.
    pub agent_store: Arc<dyn AgentStore>,
    /// Who the caller is in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Lists the agents waiting for the caller to accept them.
pub struct ListAgentOffersUseCase {
    ports: ListAgentOffersPorts,
}

impl ListAgentOffersUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: ListAgentOffersPorts) -> Self {
        Self { ports }
    }
}

impl Query for ListAgentOffersUseCase {
    type Caller = CallerContext;
    type Input = ();
    type Output = Result<Vec<AgentIdentity<ResolvedTenant>>, AppError>;

    /// The agents of the caller's tenant offered to the caller's own
    /// account, while each offer still stands.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        (): (),
    ) -> Result<Vec<AgentIdentity<ResolvedTenant>>, AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let offered = self
            .ports
            .agent_store
            .list_offered_to(&ctx.tenant(), authority.who().account())
            .await
            .or_internal()?;
        let now = clock::now();
        Ok(offered
            .into_iter()
            .filter(|agent| {
                agent
                    .offer()
                    .open_to(now)
                    .is_some_and(|to| to.is_same_account_as(authority.who()))
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::agents::identity::agent::{
        AgentIdentityRow, OFFER_LIFETIME, OwnershipOffer,
    };
    use ianua_domain::types::{AgentId, Human};
    use time::OffsetDateTime;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::agents::{FakeAgentStore, agent_row, caller_person, someone};
    use crate::test_support::{block_on, test_ctx};

    /// Keeps an agent of Owen's offered to `recipient` at `offered_at`.
    fn keep_offered(
        agents: &FakeAgentStore,
        recipient: Human,
        offered_at: OffsetDateTime,
    ) -> AgentId {
        let id = AgentId::new();
        let row = AgentIdentityRow {
            offer: OwnershipOffer::Open {
                recipient,
                offered_at,
                expires_at: offered_at.saturating_add(OFFER_LIFETIME),
            },
            created_at: offered_at,
            updated_at: offered_at,
            ..agent_row(id, someone("owen@example.test"))
        };
        block_on(agents.save(
            &test_ctx().tenant(),
            &AgentIdentity::reconstitute(row).unwrap(),
        ))
        .unwrap();
        id
    }

    fn list(ports: ListAgentOffersPorts) -> Result<Vec<AgentIdentity<ResolvedTenant>>, AppError> {
        block_on(ListAgentOffersUseCase::new(ports).execute(&test_ctx(), ()))
    }

    /// Owen offered Ann one agent and Bob another, and an older offer to
    /// Ann lapsed. Ann sees only the one waiting for her now.
    #[test]
    fn a_person_sees_the_offers_waiting_for_them() {
        let agents = Arc::new(FakeAgentStore::empty());
        let now = clock::now();
        let mine = keep_offered(&agents, caller_person(), now);
        keep_offered(&agents, someone("bob@example.test"), now);
        keep_offered(
            &agents,
            caller_person(),
            now.saturating_sub(OFFER_LIFETIME.saturating_mul(2)),
        );
        let ports = ListAgentOffersPorts {
            agent_store: agents,
            ..ListAgentOffersPorts::fakes()
        };

        let offered = list(ports).unwrap();

        let ids: Vec<AgentId> = offered.iter().map(|agent| *agent.id()).collect();
        assert_eq!(ids, [mine]);
    }

    /// A signed-out caller cannot read pending ownership offers.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let ports = ListAgentOffersPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..ListAgentOffersPorts::fakes()
        };

        let result = list(ports);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
