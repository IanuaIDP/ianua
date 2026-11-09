//! Sighting bodies: the agents seen at work that nobody registered, and a
//! person registering or dismissing one.

use ianua_app::use_cases::agents::sightings::{RegisterRequest, Shown};
use ianua_domain::domains::agents::identity::sighting::{AgentSighting, SightingState};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::types::{AgentId, AgentSightingId};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::ApiError;

/// Query parameters for listing sightings.
#[derive(Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct SightingQueryParams {
    /// `unreviewed` for those nobody has dealt with yet, the default, or
    /// `all`.
    pub shown: Option<String>,
}

impl SightingQueryParams {
    /// Which sightings this query asks for.
    ///
    /// # Errors
    ///
    /// - A validation error when `shown` is neither `unreviewed` nor `all`.
    pub(crate) fn shown(&self) -> Result<Shown, ApiError> {
        match self
            .shown
            .as_deref()
            .map(str::to_ascii_lowercase)
            .as_deref()
        {
            None | Some("unreviewed") => Ok(Shown::Unreviewed),
            Some("all") => Ok(Shown::All),
            Some(other) => Err(ApiError::validation(message!(
                "api-unknown-sightings-filter-expected-unreviewed-or",
                format!("unknown sightings filter: {other} (expected unreviewed or all)")
            ))),
        }
    }
}

/// Request body for registering a sighting as an agent.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct RegisterSightingBody {
    /// The agent the sighted caller is: one created for it, or one the
    /// tenant already has.
    pub agent_id: Uuid,
}

impl RegisterSightingBody {
    /// The registration of `sighting_id` this body asks for.
    #[must_use]
    pub(crate) fn into_request(self, sighting_id: AgentSightingId) -> RegisterRequest {
        RegisterRequest {
            sighting_id,
            agent_id: AgentId::from_uuid(self.agent_id),
        }
    }
}

/// An agent seen at work that nobody registered.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct SightingResponse {
    /// Unique identifier.
    pub id: Uuid,
    /// Where it was seen: `gateway`, `oauth_client` or `cloud_scan`.
    pub source: String,
    /// What tells this caller apart from others, such as an OAuth client
    /// id or a workload's subject.
    pub fingerprint: String,
    /// What it called itself. The caller wrote it: show it as text, never
    /// as markup.
    pub calls_itself: String,
    /// How many times it was seen.
    pub seen_count: u32,
    /// When it was first seen.
    #[serde(with = "time::serde::rfc3339")]
    pub first_seen_at: OffsetDateTime,
    /// When it was last seen.
    #[serde(with = "time::serde::rfc3339")]
    pub last_seen_at: OffsetDateTime,
    /// `unreviewed`, `registered` or `dismissed`.
    pub status: String,
    /// The agent it was registered as, once it was.
    pub agent_id: Option<Uuid>,
    /// When a person dealt with it, once they did.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub decided_at: Option<OffsetDateTime>,
}

impl From<&AgentSighting<ResolvedTenant>> for SightingResponse {
    fn from(sighting: &AgentSighting<ResolvedTenant>) -> Self {
        let state = sighting.state();
        let (status, agent_id) = match state {
            SightingState::Unreviewed => ("unreviewed", None),
            SightingState::Registered { agent_id, .. } => ("registered", Some(*agent_id.as_uuid())),
            SightingState::Dismissed { .. } => ("dismissed", None),
        };
        Self {
            id: *sighting.id().as_uuid(),
            source: sighting.source().as_str().to_owned(),
            fingerprint: sighting.fingerprint().as_str().to_owned(),
            calls_itself: sighting.calls_itself().as_str().to_owned(),
            seen_count: sighting.seen_count(),
            first_seen_at: sighting.first_seen_at(),
            last_seen_at: sighting.last_seen_at(),
            status: status.to_owned(),
            agent_id,
            decided_at: state.decided_at(),
        }
    }
}
