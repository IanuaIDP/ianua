//! Audit records as a reviewer checks them.
//!
//! What an agent says about itself is only a claim. What counts is what ianua
//! recorded. A reviewer finds each record in the chain by its sequence number
//! and checks it against the records next to it. Verdicts cite these numbers,
//! never the agent's own account.

use time::OffsetDateTime;

use crate::shared::events::data::EventData;
use crate::types::{EventType, EvidenceId};

/// One audit record with its place in the tenant's chain.
#[derive(Debug, Clone)]
pub struct EvidenceRecord {
    /// The record's position in the tenant's chain.
    pub seq: i64,
    /// The record's id.
    pub id: EvidenceId,
    /// What happened.
    pub event_type: EventType,
    /// The event's details.
    pub payload: EventData,
    /// When it happened.
    pub occurred_at: OffsetDateTime,
    /// The record's own hash: `SHA-256(prev_hash ‖ record)`.
    pub entry_hash: Vec<u8>,
    /// The hash of the record before it.
    pub prev_hash: Vec<u8>,
}
