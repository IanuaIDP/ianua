//! Handing on the agents of a person who leaves.
//!
//! An agent always has a person answerable for it. When its owner's
//! account goes, the person removing it takes over each agent the account
//! owned, so no agent is left acting with nobody to answer for it.

use ianua_domain::domains::agents::identity::agent::Handover;
use ianua_domain::domains::agents::identity::control::AgentControl;
use ianua_domain::shared::events::event::DomainEvent;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::HumanAccount;

use crate::error::{AppError, OrInternal};
use crate::ports::agents::{AgentStore, AgentVersion};
use crate::tenancy::ScopedTenant;

/// Hands every agent `departing` owns to the person `taker` names, saves
/// them, and gives back the record of each hand-over.
///
/// Every agent is handed on before any is saved, so a refusal leaves them
/// all with their owner and the account in place.
///
/// # Errors
///
/// - `AppError::Forbidden` when `taker` may not manage agents, or may not
///   create them and so may not own one.
/// - `AppError::Conflict` when one of the agents changed since it was read.
/// - `AppError::Internal` on storage failure.
pub(crate) async fn agents_handed_on(
    agents: &dyn AgentStore,
    tenant: &ScopedTenant,
    taker: &AgentControl<'_>,
    departing: HumanAccount,
) -> Result<Vec<DomainEvent>, AppError> {
    let mut owned: Vec<_> = agents
        .list_owned_by(tenant, departing)
        .await
        .or_internal()?
        .into_iter()
        .map(|agent| (AgentVersion::of(&agent), agent))
        .collect();
    for (_, agent) in &mut owned {
        agent
            .transfer_ownership(taker, taker, Handover::OwnerLeft)
            .map_err(AppError::from_domain)?;
    }
    let mut recorded = Vec::new();
    for (read, agent) in &mut owned {
        agents
            .save_unchanged_since(tenant, agent, *read)
            .await
            .map_err(AppError::from_domain)?;
        recorded.extend(agent.take_events(tenant));
    }
    Ok(recorded)
}
