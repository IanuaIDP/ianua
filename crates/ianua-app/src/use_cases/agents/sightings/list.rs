//! List sightings: the agents seen at work that nobody registered.

use std::sync::Arc;

use ianua_domain::domains::agents::identity::sighting::{AgentSighting, SightingState};
use ianua_domain::domains::authorization::permission::{AgentAction, SystemPermission};
use ianua_domain::isolation::scope::ResolvedTenant;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::agents::AgentSightingStore;
use crate::use_case::Query;

/// Which sightings to list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shown {
    /// Only those nobody has dealt with yet.
    Unreviewed,
    /// Every sighting, dealt with or not.
    All,
}

/// The ports [`ListUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ListPorts {
    /// Loads the sightings.
    pub sighting_store: Arc<dyn AgentSightingStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Lists the tenant's agent sightings.
pub struct ListUseCase {
    ports: ListPorts,
}

impl ListUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: ListPorts) -> Self {
        Self { ports }
    }
}

impl Query for ListUseCase {
    type Caller = CallerContext;
    type Input = Shown;
    type Output = Result<Vec<AgentSighting<ResolvedTenant>>, AppError>;

    /// The sightings `shown` asks for, last seen first, for a caller who
    /// may view agents.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not view agents.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        shown: Shown,
    ) -> Result<Vec<AgentSighting<ResolvedTenant>>, AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        authority
            .ensure_holds(SystemPermission::Agents(AgentAction::View))
            .map_err(AppError::from_domain)?;
        let sightings = self
            .ports
            .sighting_store
            .list(&ctx.tenant())
            .await
            .or_internal()?;
        Ok(sightings
            .into_iter()
            .filter(|sighting| is_shown(shown, sighting.state()))
            .collect())
    }
}

/// Whether a sighting in `state` is among those `shown` asks for.
fn is_shown(shown: Shown, state: SightingState) -> bool {
    match shown {
        Shown::All => true,
        Shown::Unreviewed => state == SightingState::Unreviewed,
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::agents::identity::control::AgentControl;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::agents::{
        FakeAgentSightingStore, agent_manager, sighted_client, someone_else,
    };
    use crate::test_support::{block_on, test_ctx};

    /// One sighting nobody has dealt with, and one an agent manager
    /// dismissed.
    fn ports() -> ListPorts {
        let mut dismissed = sighted_client("cli_7", "backup-job");
        let manager = agent_manager(someone_else());
        dismissed.dismiss(&AgentControl::new(&manager)).unwrap();
        ListPorts {
            sighting_store: Arc::new(FakeAgentSightingStore::holding([
                sighted_client("cli_42", "invoice-bot"),
                dismissed,
            ])),
            ..ListPorts::fakes()
        }
    }

    fn list(
        ports: ListPorts,
        shown: Shown,
    ) -> Result<Vec<AgentSighting<ResolvedTenant>>, AppError> {
        block_on(ListUseCase::new(ports).execute(&test_ctx(), shown))
    }

    /// Ann lists the sightings still to deal with. She sees the one nobody
    /// looked at, not the one dismissed.
    #[test]
    fn unreviewed_sightings_are_listed_on_their_own() {
        let listed = list(ports(), Shown::Unreviewed).unwrap();

        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].fingerprint().as_str(), "cli_42");
    }

    /// Ann lists every sighting. She sees both.
    #[test]
    fn every_sighting_is_listed() {
        assert_eq!(list(ports(), Shown::All).unwrap().len(), 2);
    }

    /// Sightings cannot be listed by a caller without the agent view right.
    #[test]
    fn a_caller_who_may_not_view_agents_is_refused() {
        let ports = ListPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[])),
            ..ports()
        };

        let result = list(ports, Shown::All);

        assert!(matches!(result, Err(AppError::Forbidden(_))), "{result:?}");
    }

    /// A signed-out caller is refused the sighting list.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let ports = ListPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..ports()
        };

        let result = list(ports, Shown::All);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
