//! An audit record with its place in the tenant's chain, read back as
//! evidence.

use ianua_domain::domains::audit::evidence::EvidenceRecord;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{EventType, EvidenceId};
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::audit::payload::opened;

/// A chained record as it is read.
pub(super) struct ChainedRecord {
    pub(super) seq: i64,
    pub(super) id: Uuid,
    pub(super) event_type: String,
    pub(super) payload: Value,
    pub(super) occurred_at: OffsetDateTime,
    pub(super) entry_hash: Vec<u8>,
    pub(super) prev_hash: Vec<u8>,
}

impl ChainedRecord {
    /// The evidence the record holds.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the event type is one
    /// this release does not know, or the payload does not read.
    pub(super) fn into_evidence(self) -> Result<EvidenceRecord, DomainError> {
        let event_type = EventType::parse(&self.event_type)
            .ok_or_else(|| DomainError::corrupt_row("audit record", "an unknown event type"))?;
        Ok(EvidenceRecord {
            seq: self.seq,
            id: EvidenceId::from_uuid(self.id),
            event_type,
            payload: opened(self.payload)?,
            occurred_at: self.occurred_at,
            entry_hash: self.entry_hash,
            prev_hash: self.prev_hash,
        })
    }
}
