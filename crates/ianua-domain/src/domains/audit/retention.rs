//! What one retention purge removed from a tenant's audit records.
//!
//! The purge deletes records written before a cutoff straight from
//! storage, with none of them loaded, so this stands in for them. It
//! raises `tenant.audit_records_purged`, naming the cutoff and how many
//! went, so the trail itself shows that records were removed, when, and up
//! to which day: an auditor who finds the oldest record a year old can tell
//! a purge the tenant's retention asked for from records gone missing.

use time::OffsetDateTime;

use crate::isolation::scope::ResolvedTenant;
use crate::shared::events::data::EventData;
use crate::shared::events::event::{DomainEvent, tenant_event};
use crate::shared::events::raised::{Raised, SavedFor};

/// Audit records written before a cutoff were removed, as the tenant's
/// retention asks.
#[derive(Debug)]
pub struct AuditRecordsPurged {
    /// Records written before this were removed.
    pub(crate) cutoff: OffsetDateTime,
    /// How many were removed.
    pub(crate) removed: u64,
    /// When the purge ran.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    AuditRecordsPurged => crate::types::event_type::TenantEvent::AuditRecordsPurged,
    fn payload(&self) -> EventData {
        EventData::new()
            .field("cutoff", self.cutoff.to_string())
            .field("count", self.removed.to_string())
    }
}

/// One purge of a tenant's audit records: the cutoff it removed records
/// before, and how many went.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetentionPurge {
    cutoff: OffsetDateTime,
    removed: u64,
}

impl RetentionPurge {
    /// A purge that removed `removed` records written before `cutoff`.
    #[must_use]
    pub fn new(cutoff: OffsetDateTime, removed: u64) -> Self {
        Self { cutoff, removed }
    }

    /// Records written before this were removed.
    #[must_use]
    pub fn cutoff(&self) -> OffsetDateTime {
        self.cutoff
    }

    /// How many records went.
    #[must_use]
    pub fn removed(&self) -> u64 {
        self.removed
    }

    /// What this purge of the records of `purged_for` raises:
    /// `tenant.audit_records_purged`, naming the cutoff and the count, when
    /// any record went, and nothing when none did.
    ///
    /// The purge removes rows without loading them, so nothing is saved
    /// first. The tenant purged is the one the record names.
    #[must_use]
    pub fn events(&self, purged_for: &impl SavedFor) -> Vec<DomainEvent> {
        if self.removed < 1 {
            return Vec::new();
        }
        let mut raised = Raised::<ResolvedTenant>::default();
        raised.raise(AuditRecordsPurged {
            cutoff: self.cutoff,
            removed: self.removed,
            occurred_at: crate::shared::clock::now(),
        });
        raised.take(purged_for)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::isolation::scope::TenantScope;
    use crate::shared::config::SlugLimits;
    use crate::types::{TenantId, TenantSlug};

    fn acme() -> ResolvedTenant {
        ResolvedTenant::new(
            TenantId::new(),
            TenantSlug::new("acme", &SlugLimits::default()).unwrap(),
        )
    }

    /// Acme keeps its records a year. The nightly purge removes 42 written
    /// before the cutoff. The trail records it for Acme, with the cutoff
    /// and the count.
    #[test]
    fn a_purge_that_removed_records_raises_a_summary_for_the_tenant() {
        let acme = acme();
        let cutoff = OffsetDateTime::UNIX_EPOCH;

        let events = RetentionPurge::new(cutoff, 42).events(&acme);

        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].event_type().as_str(),
            "tenant.audit_records_purged"
        );
        assert_eq!(events[0].tenant_id(), Some(acme.tenant_id()));
        assert_eq!(events[0].payload().get("count"), Some("42"));
        assert_eq!(
            events[0].payload().get("cutoff"),
            Some(cutoff.to_string().as_str())
        );
    }

    /// A purge that found nothing past the retention raises nothing, so a
    /// nightly run leaves no noise in the trail.
    #[test]
    fn a_purge_that_removed_nothing_raises_nothing() {
        let events = RetentionPurge::new(OffsetDateTime::UNIX_EPOCH, 0).events(&acme());

        assert!(events.is_empty());
    }
}
