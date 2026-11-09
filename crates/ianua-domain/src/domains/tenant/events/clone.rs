//! Events about copying one tenant's setup into another.
//!
//! Each is filed under the tenant being filled, since that is the tenant
//! whose setup changes.

use time::OffsetDateTime;

use crate::domains::tenant::clone::{CloneFailure, ClonePart};
use crate::shared::events::data::{EventData, RefKind, Reference};
use crate::shared::events::event::tenant_event;
use crate::types::{EventLabel, TenantCloneId, TenantId};

/// Copying another tenant's setup into this one started.
#[derive(Debug)]
pub(crate) struct TenantCloneStarted {
    /// The setup-copy operation begun for the destination tenant.
    pub(crate) clone_id: TenantCloneId,
    /// The tenant copied from, which the payload links to.
    pub(crate) source_id: TenantId,
    /// The source tenant's name as it was then.
    pub(crate) source_label: EventLabel,
    /// What is copied.
    pub(crate) parts: Vec<ClonePart>,
    /// When it started.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    TenantCloneStarted => crate::types::event_type::TenantEvent::CloneStarted,
    fn payload(&self) -> EventData {
        EventData::new()
            .field("clone_id", self.clone_id.to_string())
            .reference(
                "source",
                Reference::new(
                    RefKind::TENANT,
                    self.source_id.to_string(),
                    self.source_label.as_str(),
                ),
            )
            .field("parts", parts_named(&self.parts))
    }
}

/// Every part of a clone was copied.
#[derive(Debug)]
pub(crate) struct TenantCloneCompleted {
    /// The setup-copy operation that finished every selected part.
    pub(crate) clone_id: TenantCloneId,
    /// When the last part was copied.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    TenantCloneCompleted => crate::types::event_type::TenantEvent::CloneCompleted,
    fn payload(&self) -> EventData {
        EventData::new().field("clone_id", self.clone_id.to_string())
    }
}

/// A clone stopped before every part was copied.
#[derive(Debug)]
pub(crate) struct TenantCloneFailed {
    /// The setup-copy operation that stopped with work incomplete.
    pub(crate) clone_id: TenantCloneId,
    /// Why it stopped.
    pub(crate) reason: CloneFailure,
    /// When it stopped.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    TenantCloneFailed => crate::types::event_type::TenantEvent::CloneFailed,
    fn payload(&self) -> EventData {
        EventData::new()
            .field("clone_id", self.clone_id.to_string())
            .field("reason", self.reason.as_str())
    }
}

/// The parts' stored names, joined by commas, such as `settings,routes`.
fn parts_named(parts: &[ClonePart]) -> String {
    parts
        .iter()
        .map(|part| part.as_str())
        .collect::<Vec<_>>()
        .join(",")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::events::event::DomainEventCore;

    /// Ann clones Acme's production setup with its settings and routes. The
    /// record lists both parts by name.
    #[test]
    fn a_started_clone_lists_the_parts_it_copies() {
        let event = TenantCloneStarted {
            clone_id: TenantCloneId::new(),
            source_id: TenantId::new(),
            source_label: EventLabel::of("Acme production"),
            parts: vec![ClonePart::Settings, ClonePart::Routes],
            occurred_at: crate::shared::clock::now(),
        };

        assert_eq!(event.payload().get("parts"), Some("settings,routes"));
    }

    /// A clone stops because its source was archived. The record names the
    /// reason.
    #[test]
    fn a_failed_clone_names_why() {
        let event = TenantCloneFailed {
            clone_id: TenantCloneId::new(),
            reason: CloneFailure::SourceGone,
            occurred_at: crate::shared::clock::now(),
        };

        assert_eq!(event.payload().get("reason"), Some("source_gone"));
    }
}
