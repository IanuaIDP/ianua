//! Dismiss sighting: a person judges a sighted caller no agent at all.
//!
//! A batch job or a person's script can look like an agent from the
//! outside. Someone allowed to manage agents dismisses its sighting, so it
//! leaves the list still to deal with. Dismissing grants nothing: the
//! caller is still allowed or refused by the usual rules.

use std::sync::Arc;

use ianua_domain::domains::agents::identity::control::AgentControl;
use ianua_domain::domains::agents::identity::sighting::AgentSighting;
use ianua_domain::domains::authorization::permission::{AgentAction, SystemPermission};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::AgentSightingId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::agents::AgentSightingStore;
use crate::use_case::Command;
use crate::use_cases::agents::lookup::existing_sighting;

/// The ports [`DismissUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct DismissPorts {
    /// Loads and keeps the sighting.
    pub sighting_store: Arc<dyn AgentSightingStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Dismisses sightings of callers that are no agent.
pub struct DismissUseCase {
    ports: DismissPorts,
}

impl DismissUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: DismissPorts) -> Self {
        Self { ports }
    }
}

impl Command for DismissUseCase {
    type Caller = CallerContext;
    type Input = AgentSightingId;
    type Output = Result<AgentSighting<ResolvedTenant>, AppError>;

    /// Dismisses `sighting_id`, records `agents.agent_sighting_dismissed`,
    /// and returns the sighting.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not manage agents, before
    ///   any sighting is read.
    /// - `AppError::NotFound` when the tenant has no such sighting.
    /// - `AppError::Domain` when someone dealt with it already.
    /// - `AppError::Internal` on persistence or audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        sighting_id: AgentSightingId,
    ) -> Result<AgentSighting<ResolvedTenant>, AppError> {
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        authority
            .ensure_holds(SystemPermission::Agents(AgentAction::Manage))
            .map_err(AppError::from_domain)?;
        let store = self.ports.sighting_store.as_ref();
        let mut sighting = existing_sighting(store, &tenant, &sighting_id).await?;
        sighting
            .dismiss(&AgentControl::new(&authority))
            .map_err(AppError::from_domain)?;
        store.save(&tenant, &sighting).await.or_internal()?;
        auditor
            .dispatch_by(&ctx.actor(), sighting.take_events(&tenant))
            .await
            .or_internal()?;
        Ok(sighting)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::agents::identity::sighting::SightingState;
    use ianua_domain::domains::authorization::permission::{AgentAction, SystemPermission};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::agents::{FakeAgentSightingStore, sighted_client};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// A sighting of client `cli_7`, and the store keeping it.
    fn seen() -> (Arc<FakeAgentSightingStore>, AgentSightingId) {
        let sighting = sighted_client("cli_7", "backup-job");
        let id = *sighting.id();
        (Arc::new(FakeAgentSightingStore::holding([sighting])), id)
    }

    fn dismiss(
        ports: DismissPorts,
        sink: &Arc<FakeEventDispatcher>,
        id: AgentSightingId,
    ) -> Result<AgentSighting<ResolvedTenant>, AppError> {
        block_on(DismissUseCase::new(ports).execute(&test_ctx(), &test_auditor(sink.clone()), id))
    }

    fn ports_over(store: &Arc<FakeAgentSightingStore>) -> DismissPorts {
        DismissPorts {
            sighting_store: store.clone(),
            ..DismissPorts::fakes()
        }
    }

    /// Ann judges `cli_7`, the nightly backup, no agent. Its sighting is
    /// dismissed and the dismissal recorded.
    #[test]
    fn a_sighting_is_dismissed() {
        let (store, id) = seen();
        let sink = Arc::new(FakeEventDispatcher::new());

        dismiss(ports_over(&store), &sink, id).unwrap();

        assert!(matches!(
            store.all()[0].state(),
            SightingState::Dismissed { .. }
        ));
        assert_eq!(
            sink.records.lock().unwrap().as_slice(),
            ["agents.agent_sighting_dismissed"]
        );
    }

    /// A sighting dismissed already is not dismissed again.
    #[test]
    fn a_sighting_dealt_with_is_not_dismissed_again() {
        let (store, id) = seen();
        let sink = Arc::new(FakeEventDispatcher::new());
        dismiss(ports_over(&store), &sink, id).unwrap();

        let again = dismiss(ports_over(&store), &sink, id);

        assert!(matches!(again, Err(AppError::Domain(_))), "{again:?}");
    }

    /// Ann dismisses a sighting the tenant does not have. It is not found.
    #[test]
    fn an_unknown_sighting_is_not_found() {
        let (store, _) = seen();

        let result = dismiss(
            ports_over(&store),
            &Arc::new(FakeEventDispatcher::new()),
            AgentSightingId::new(),
        );

        assert!(matches!(result, Err(AppError::NotFound(_))), "{result:?}");
    }

    /// The view right does not authorize dismissing a sighting; the attempt
    /// is refused and the sighting stays unreviewed.
    #[test]
    fn a_caller_who_may_not_manage_agents_is_refused() {
        let (store, id) = seen();
        let ports = DismissPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
                SystemPermission::Agents(AgentAction::View),
            ])),
            ..ports_over(&store)
        };

        let result = dismiss(ports, &Arc::new(FakeEventDispatcher::new()), id);

        assert!(matches!(result, Err(AppError::Forbidden(_))), "{result:?}");
        assert_eq!(store.all()[0].state(), SightingState::Unreviewed);
    }

    /// A signed-out caller cannot dismiss a sighting, which stays unreviewed.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let (store, id) = seen();
        let ports = DismissPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..ports_over(&store)
        };

        let result = dismiss(ports, &Arc::new(FakeEventDispatcher::new()), id);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(store.all()[0].state(), SightingState::Unreviewed);
    }
}
