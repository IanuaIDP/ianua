//! A sighting as its row holds it: read back into the aggregate, and
//! written out from it.

use ianua_domain::domains::agents::identity::sighting::{
    AgentSighting, AgentSightingRow, SightingFingerprint, SightingSource, SightingState,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::model::aggregate::Aggregate as _;
use ianua_domain::types::{AgentId, AgentSightingId, UntrustedText};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::agents::sightings::words::SightingStateKind;
use crate::postgres::foundation::stored::{Stored, StoredWord as _};

const SIGHTING: Stored = Stored("agent sighting");

/// A sighting as it is read. The store's checked queries fill it.
pub(super) struct SightingRecord {
    pub(super) id: Uuid,
    pub(super) source: String,
    pub(super) fingerprint: String,
    pub(super) calls_itself: String,
    pub(super) seen_count: i64,
    pub(super) first_seen_at: OffsetDateTime,
    pub(super) last_seen_at: OffsetDateTime,
    pub(super) state: String,
    pub(super) registered_agent_id: Option<Uuid>,
    pub(super) decided_at: Option<OffsetDateTime>,
    pub(super) updated_at: OffsetDateTime,
}

impl SightingRecord {
    /// The sighting the record holds, rebuilt through the domain's checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a value no longer passes
    /// its rules, a word is unknown, the state misses what it needs, or the
    /// row breaks a rule the sighting keeps.
    pub(super) fn into_sighting(self) -> Result<AgentSighting<ResolvedTenant>, DomainError> {
        let state = self.state()?;
        AgentSighting::reconstitute(AgentSightingRow {
            id: AgentSightingId::from_uuid(self.id),
            source: SightingSource::from_stored(&self.source)?,
            fingerprint: SIGHTING
                .value("fingerprint", SightingFingerprint::new(self.fingerprint))?,
            calls_itself: UntrustedText::record(&self.calls_itself),
            seen_count: u32::try_from(self.seen_count)
                .map_err(|_| DomainError::corrupt_row(SIGHTING.0, "a count out of range"))?,
            first_seen_at: self.first_seen_at,
            last_seen_at: self.last_seen_at,
            state,
            updated_at: self.updated_at,
        })
    }

    /// Whether a person dealt with it, from its state word and the columns
    /// beside it.
    fn state(&self) -> Result<SightingState, DomainError> {
        let kind = SIGHTING.choice::<SightingStateKind>(&self.state)?;
        match (kind, self.registered_agent_id, self.decided_at) {
            (SightingStateKind::Unreviewed, None, None) => Ok(SightingState::Unreviewed),
            (SightingStateKind::Registered, Some(agent), Some(at)) => {
                Ok(SightingState::Registered {
                    agent_id: AgentId::from_uuid(agent),
                    at,
                })
            }
            (SightingStateKind::Dismissed, None, Some(at)) => Ok(SightingState::Dismissed { at }),
            (_, _, _) => Err(DomainError::corrupt_row(
                SIGHTING.0,
                "a state its columns contradict",
            )),
        }
    }
}

/// A sighting's columns, as they are written.
pub(super) struct SightingColumns<'a> {
    pub(super) id: &'a Uuid,
    pub(super) source: &'static str,
    pub(super) fingerprint: &'a str,
    pub(super) calls_itself: &'a str,
    pub(super) seen_count: i64,
    pub(super) first_seen_at: OffsetDateTime,
    pub(super) last_seen_at: OffsetDateTime,
    pub(super) state: &'static str,
    pub(super) registered_agent_id: Option<Uuid>,
    pub(super) decided_at: Option<OffsetDateTime>,
    pub(super) updated_at: OffsetDateTime,
}

impl<'a> SightingColumns<'a> {
    /// The columns `sighting` is written to.
    pub(super) fn of(sighting: &'a AgentSighting<ResolvedTenant>) -> Self {
        let state = sighting.state();
        Self {
            id: sighting.id().as_uuid(),
            source: sighting.source().as_str(),
            fingerprint: sighting.fingerprint().as_str(),
            calls_itself: sighting.calls_itself().as_str(),
            seen_count: i64::from(sighting.seen_count()),
            first_seen_at: sighting.first_seen_at(),
            last_seen_at: sighting.last_seen_at(),
            state: SightingStateKind::from(state).word(),
            registered_agent_id: registered_as(state),
            decided_at: state.decided_at(),
            updated_at: sighting.updated_at(),
        }
    }
}

/// The agent a registered sighting became.
fn registered_as(state: SightingState) -> Option<Uuid> {
    match state {
        SightingState::Registered { agent_id, .. } => Some(*agent_id.as_uuid()),
        SightingState::Unreviewed | SightingState::Dismissed { .. } => None,
    }
}
