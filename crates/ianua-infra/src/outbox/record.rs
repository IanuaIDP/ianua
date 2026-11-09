//! A record still to be published, as the outbox and its audit record hold
//! it, and the envelope the bus carries of it.

use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::bus::{EventEnvelope, EventScope};

/// A tenant's record still to be published.
pub(super) struct TenantPending {
    pub(super) id: Uuid,
    pub(super) tenant_id: Uuid,
    pub(super) organization_id: Option<Uuid>,
    pub(super) actor: String,
    pub(super) event_type: String,
    pub(super) payload: Value,
    pub(super) occurred_at: OffsetDateTime,
    pub(super) chain_depth: i16,
}

/// An organization's or the platform's record still to be published.
pub(super) struct PlatformPending {
    pub(super) id: Uuid,
    pub(super) organization_id: Option<Uuid>,
    pub(super) actor: String,
    pub(super) event_type: String,
    pub(super) payload: Value,
    pub(super) occurred_at: OffsetDateTime,
}

impl TenantPending {
    /// The envelope the bus carries of the record, with the depth of the
    /// workflow chain whose work raised it. A depth past what an envelope
    /// holds is carried as the most it holds, which no chain reaches, so
    /// the consumer refuses it rather than reading it as none.
    pub(super) fn into_envelope(self) -> EventEnvelope {
        EventEnvelope {
            id: self.id,
            scope: EventScope::Tenant(self.tenant_id),
            organization_id: self.organization_id,
            event_type: self.event_type,
            actor: self.actor,
            payload: self.payload,
            occurred_at: self.occurred_at,
            chain_depth: u8::try_from(self.chain_depth).unwrap_or(u8::MAX),
        }
    }
}

impl PlatformPending {
    /// The envelope the bus carries of the record: an organization's when
    /// it names one, else the platform's.
    pub(super) fn into_envelope(self) -> EventEnvelope {
        EventEnvelope {
            id: self.id,
            scope: self
                .organization_id
                .map_or(EventScope::Platform, EventScope::Organization),
            organization_id: self.organization_id,
            event_type: self.event_type,
            actor: self.actor,
            payload: self.payload,
            occurred_at: self.occurred_at,
            chain_depth: 0,
        }
    }
}
