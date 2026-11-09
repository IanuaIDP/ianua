//! The agents' monitors as the worker runs them on the events the gateway
//! raises: each reads the agent's action from its event and runs once for
//! that event, however often the bus hands it out. Its execution marker
//! is kept in one unit of work with everything the monitor changed and
//! recorded, so a run that failed leaves no note and the event, handed
//! out again, is judged again.

pub(crate) mod convergence;
pub(crate) mod drift;
pub(crate) mod egress;

use std::future::Future;
use std::sync::Arc;

use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::events::data::EventData;
use ianua_domain::types::event_type::AgentsEvent;
use ianua_domain::types::{AgentId, AuditRecordId, DelegationId, EventType};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::error::{AppError, OrInternal};
use crate::ports::runtime::UnitOfWork;
use crate::ports::shared::{EventReaction, EventReactions, Noted, PublishedEvent, ReactionNote};
use crate::services::kept_together::kept_together;
use crate::tenancy::ScopedTenant;

/// How long a monitor's event execution marker is kept: past a week
/// the bus hands none of its events out again.
const NOTES_KEPT: Duration = Duration::days(8);

/// What hearing an event came to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Heard {
    /// The monitor ran on it.
    Acted,
    /// The monitor had run on it already, when the bus handed it out
    /// before.
    Before,
    /// It is not an event the monitor watches.
    Ignored,
}

/// The ports every monitor heard on the bus needs beside its own.
#[derive(ianua_macros::Fakes)]
pub struct HeardPorts {
    /// Notes each event a monitor acted on.
    pub reactions: Arc<dyn EventReactions>,
    /// Keeps the note with what the monitor changed and recorded.
    pub unit_of_work: Arc<dyn UnitOfWork>,
}

/// An agent's action as its event carries it.
pub(crate) struct HeardAction {
    /// The tenant it happened in.
    pub(crate) tenant: ScopedTenant,
    /// The event's payload.
    pub(crate) payload: EventData,
    /// The acting agent.
    pub(crate) agent_id: AgentId,
    /// The delegation it acted under.
    pub(crate) delegation_id: DelegationId,
}

impl HeardAction {
    /// The action `event` carries when it is one of `kinds`, `None` for any
    /// other event.
    ///
    /// # Errors
    ///
    /// `AppError::Domain` when the event is one of `kinds` but does not
    /// name its agent and delegation.
    pub(crate) fn of(
        event: &PublishedEvent,
        kinds: &[AgentsEvent],
    ) -> Result<Option<Self>, AppError> {
        let watched = kinds
            .iter()
            .any(|kind| event.event.event_type() == EventType::Agents(*kind));
        let Some(tenant_id) = event.event.tenant_id().copied().filter(|_| watched) else {
            return Ok(None);
        };
        let payload = event.event.payload();
        let agent_id = id_in(&payload, "agent_id").map(AgentId::from_uuid);
        let delegation_id = id_in(&payload, "delegation_id").map(DelegationId::from_uuid);
        let (Some(agent_id), Some(delegation_id)) = (agent_id, delegation_id) else {
            return Err(unreadable("the event names no agent or delegation"));
        };
        Ok(Some(Self {
            tenant: ScopedTenant::for_background(tenant_id),
            payload,
            agent_id,
            delegation_id,
        }))
    }

    /// The text field `key`.
    ///
    /// # Errors
    ///
    /// `AppError::Domain` when the event does not carry it.
    pub(crate) fn text(&self, key: &str) -> Result<&str, AppError> {
        self.payload
            .get(key)
            .ok_or_else(|| unreadable("the event lacks a field its monitor reads"))
    }

    /// When the action happened, to the microsecond the event keeps.
    ///
    /// # Errors
    ///
    /// `AppError::Domain` when the event carries no time that reads.
    pub(crate) fn at(&self) -> Result<OffsetDateTime, AppError> {
        let micros: i128 = self
            .text("at_us")?
            .parse()
            .map_err(|_| unreadable("the event's time does not read"))?;
        OffsetDateTime::from_unix_timestamp_nanos(micros.saturating_mul(1_000))
            .map_err(|_| unreadable("the event's time does not read"))
    }
}

/// Runs `work` for event `record` as `reaction`, unless it ran for that
/// event already, keeping the note with what `work` keeps.
///
/// # Errors
///
/// The error `work` failed with, or `AppError::Internal` when the note
/// cannot be kept; nothing is kept then.
pub(crate) async fn once<T: Send>(
    ports: &HeardPorts,
    tenant: &ScopedTenant,
    reaction: EventReaction,
    record: AuditRecordId,
    work: impl Future<Output = Result<T, AppError>> + Send,
) -> Result<Heard, AppError> {
    let note = ReactionNote {
        reaction,
        record,
        forget_before: clock::now() - NOTES_KEPT,
    };
    let noted_then_worked = async {
        if ports.reactions.note(tenant, &note).await.or_internal()? == Noted::Before {
            return Ok(Heard::Before);
        }
        work.await?;
        Ok(Heard::Acted)
    };
    kept_together(ports.unit_of_work.as_ref(), noted_then_worked).await
}

/// The id field `key` of `payload`.
fn id_in(payload: &EventData, key: &str) -> Option<Uuid> {
    Uuid::parse_str(payload.get(key)?).ok()
}

/// The refusal of an event a monitor watches that does not read.
fn unreadable(why: &str) -> AppError {
    AppError::from_domain(DomainError::invalid(why))
}
