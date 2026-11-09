//! Events about the places a tenant ships its request records to.
//!
//! None of them carries the destination's address or credential. The
//! address's path may hold a token, and the credential is sealed. They name
//! the kind of destination instead.

use time::OffsetDateTime;

use crate::shared::events::data::{EventData, RefKind, Reference};
use crate::shared::events::event::tenant_event;
use crate::types::event_type::ProxyEvent;
use crate::types::{Label, LogShippingTargetId};

const LOG_TARGET: RefKind = RefKind::new("log_target");

/// References the target an event acted on, labelled with its name then.
fn target_reference(target_id: &LogShippingTargetId, name: &Label) -> Reference {
    Reference::new(LOG_TARGET, target_id.to_string(), name.to_string())
}

/// A tenant added a place its request records are shipped to.
#[derive(Debug)]
pub struct LogTargetCreated {
    /// The new target.
    pub(crate) target_id: LogShippingTargetId,
    /// The display label captured when record delivery was configured.
    pub(crate) name: Label,
    /// The kind of destination, such as `bucket`.
    pub(crate) destination: &'static str,
    /// When it was created.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    LogTargetCreated => ProxyEvent::LogTargetCreated,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference("log_target", target_reference(&self.target_id, &self.name))
            .field("destination", self.destination)
    }
}

/// Where, what or in which shape a target ships changed, or its name.
#[derive(Debug)]
pub struct LogTargetChanged {
    /// The delivery configuration whose destination, shape or selection changed.
    pub(crate) target_id: LogShippingTargetId,
    /// Its name now.
    pub(crate) name: Label,
    /// The kind of destination now.
    pub(crate) destination: &'static str,
    /// Which records it ships now, such as `denied_only`.
    pub(crate) records: &'static str,
    /// When it changed.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    LogTargetChanged => ProxyEvent::LogTargetChanged,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference("log_target", target_reference(&self.target_id, &self.name))
            .field("destination", self.destination)
            .field("records", self.records)
    }
}

/// A tenant stopped shipping records to a target for now.
#[derive(Debug)]
pub struct LogTargetPaused {
    /// The delivery configuration temporarily stopped from shipping records.
    pub(crate) target_id: LogShippingTargetId,
    /// The display label captured when record delivery was paused.
    pub(crate) name: Label,
    /// When it was paused.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    LogTargetPaused => ProxyEvent::LogTargetPaused,
    fn payload(&self) -> EventData {
        EventData::new().reference("log_target", target_reference(&self.target_id, &self.name))
    }
}

/// A tenant started shipping records to a paused target again.
#[derive(Debug)]
pub struct LogTargetResumed {
    /// The delivery configuration allowed to ship records again.
    pub(crate) target_id: LogShippingTargetId,
    /// The display label captured when record delivery resumed.
    pub(crate) name: Label,
    /// When it was resumed.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    LogTargetResumed => ProxyEvent::LogTargetResumed,
    fn payload(&self) -> EventData {
        EventData::new().reference("log_target", target_reference(&self.target_id, &self.name))
    }
}

/// A tenant removed a place its records were shipped to.
#[derive(Debug)]
pub struct LogTargetDeleted {
    /// The delivery configuration permanently removed from the tenant.
    pub(crate) target_id: LogShippingTargetId,
    /// Its name when it was deleted, kept for the audit trail.
    pub(crate) name: Label,
    /// When it was deleted.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    LogTargetDeleted => ProxyEvent::LogTargetDeleted,
    fn payload(&self) -> EventData {
        EventData::new().reference("log_target", target_reference(&self.target_id, &self.name))
    }
}
