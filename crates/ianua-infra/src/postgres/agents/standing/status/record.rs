//! An agent's standing, from its row: the row is read back through the
//! agent store's own mapping, so the standing is the aggregate's answer,
//! never one worked out here.

use ianua_domain::domains::agents::identity::standing::AgentStanding;
use ianua_domain::shared::errors::DomainError;
use time::OffsetDateTime;

use crate::postgres::agents::identity::agents::record::AgentRecord;

/// The standing at `now` of the agent `record` holds. One with no row is
/// gone, and so is revoked.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when the row does not read back
/// as an agent.
pub(super) fn into_standing(
    record: Option<AgentRecord>,
    now: OffsetDateTime,
) -> Result<AgentStanding, DomainError> {
    let Some(record) = record else {
        return Ok(AgentStanding::Revoked);
    };
    Ok(record.into_agent()?.standing(now))
}
