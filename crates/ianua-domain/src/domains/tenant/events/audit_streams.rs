//! Events about streaming a tenant's audit records to its SIEM.
//!
//! None carries where a stream points or what it is sent: only its id, its
//! name and the kind of destination. An endpoint's path or a credential in
//! the trail would hand the stream to whoever reads the trail.

use time::OffsetDateTime;

use crate::domains::audit::streaming::StreamDestinationKind;
use crate::domains::tenant::audit_streams::PauseReason;
use crate::shared::events::data::EventData;
use crate::shared::events::event::tenant_event;
use crate::types::{AuditStreamId, Label};

/// A tenant started streaming its audit records to a SIEM.
#[derive(Debug)]
pub struct AuditStreamCreated {
    /// The new delivery configuration for forwarding audit records.
    pub(crate) stream_id: AuditStreamId,
    /// What it is called.
    pub(crate) name: Label,
    /// The kind of destination.
    pub(crate) kind: StreamDestinationKind,
    /// When it was created.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    AuditStreamCreated => crate::types::event_type::TenantEvent::AuditStreamCreated,
    fn payload(&self) -> EventData {
        EventData::new()
            .field("stream_id", self.stream_id.to_string())
            .field("name", self.name.to_string())
            .field("destination", self.kind.as_str())
    }
}

/// An audit stream's name, destination or filter changed.
#[derive(Debug)]
pub struct AuditStreamChanged {
    /// The delivery configuration whose destination or filter changed.
    pub(crate) stream_id: AuditStreamId,
    /// What it is called now.
    pub(crate) name: Label,
    /// The kind of destination it had.
    pub(crate) old_kind: StreamDestinationKind,
    /// The kind of destination it has now.
    pub(crate) new_kind: StreamDestinationKind,
    /// When it changed.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    AuditStreamChanged => crate::types::event_type::TenantEvent::AuditStreamChanged,
    fn payload(&self) -> EventData {
        EventData::new()
            .field("stream_id", self.stream_id.to_string())
            .field("name", self.name.to_string())
            .change("destination", self.old_kind.as_str(), self.new_kind.as_str())
    }
}

/// An audit stream stopped sending.
#[derive(Debug)]
pub struct AuditStreamPaused {
    /// The delivery configuration stopped from forwarding audit records.
    pub(crate) stream_id: AuditStreamId,
    /// Why it stopped.
    pub(crate) reason: PauseReason,
    /// When it stopped.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    AuditStreamPaused => crate::types::event_type::TenantEvent::AuditStreamPaused,
    fn payload(&self) -> EventData {
        EventData::new()
            .field("stream_id", self.stream_id.to_string())
            .field("reason", self.reason.as_str())
    }
}

/// A paused audit stream started sending again.
#[derive(Debug)]
pub struct AuditStreamResumed {
    /// The delivery configuration allowed to forward audit records again.
    pub(crate) stream_id: AuditStreamId,
    /// When it resumed.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    AuditStreamResumed => crate::types::event_type::TenantEvent::AuditStreamResumed,
    fn payload(&self) -> EventData {
        EventData::new().field("stream_id", self.stream_id.to_string())
    }
}

/// An audit stream was removed.
#[derive(Debug)]
pub struct AuditStreamRemoved {
    /// The delivery configuration permanently removed from the tenant.
    pub(crate) stream_id: AuditStreamId,
    /// What it was called.
    pub(crate) name: Label,
    /// When it was removed.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    AuditStreamRemoved => crate::types::event_type::TenantEvent::AuditStreamRemoved,
    fn payload(&self) -> EventData {
        EventData::new()
            .field("stream_id", self.stream_id.to_string())
            .field("name", self.name.to_string())
    }
}
