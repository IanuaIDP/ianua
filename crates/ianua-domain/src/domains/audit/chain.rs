//! The result of checking the audit chain for tampering.
//!
//! Every audit record holds a hash of the record before it in the same
//! tenant. Walking the chain and recomputing each hash shows that no record
//! was removed, reordered or edited. This module holds only the result of
//! that walk. The walk itself reads stored rows, so it lives in an adapter.
//! A broken chain raises `tenant.audit_chain_broken`, so whoever watches the
//! tenant hears of it.

use time::OffsetDateTime;

use crate::isolation::scope::ResolvedTenant;
use crate::shared::events::data::EventData;
use crate::shared::events::event::{DomainEvent, tenant_event};
use crate::shared::events::raised::{Raised, SavedFor};

/// A scheduled check found the tenant's audit chain broken.
///
/// A record was edited, removed or added outside the chain. The event is
/// published so webhooks and alerts hear of it, not only someone who calls
/// the verify endpoint. A broken [`AuditChainVerification`] raises it, for
/// the tenant whose chain was walked.
#[derive(Debug)]
pub(crate) struct TenantAuditChainBroken {
    /// How many records verified before the break.
    pub(crate) entries_checked: u64,
    /// The sequence number of the first record that failed verification.
    pub(crate) broken_at_seq: i64,
    /// When verification found it.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    TenantAuditChainBroken => crate::types::event_type::TenantEvent::AuditChainBroken,
    fn payload(&self) -> EventData {
        EventData::new()
            .field("entries_checked", self.entries_checked.to_string())
            .field("broken_at_seq", self.broken_at_seq.to_string())
    }
}

/// Whether a chain held up, and where it broke when it did not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainFinding {
    /// Every link recomputed.
    Intact,
    /// The sequence number of the first link that did not.
    BrokenAt(i64),
}

/// The result of checking a tenant's hash-linked audit chain.
///
/// A broken chain always says where it broke. An intact one never names a
/// record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditChainVerification {
    finding: ChainFinding,
    entries_checked: u64,
}

impl AuditChainVerification {
    /// An intact chain of `entries_checked` records.
    #[must_use]
    pub fn intact(entries_checked: u64) -> Self {
        Self {
            finding: ChainFinding::Intact,
            entries_checked,
        }
    }

    /// A chain broken at `broken_at_seq`, after `entries_checked` records.
    #[must_use]
    pub fn broken(entries_checked: u64, broken_at_seq: i64) -> Self {
        Self {
            finding: ChainFinding::BrokenAt(broken_at_seq),
            entries_checked,
        }
    }

    /// Whether the chain held up, and where it broke.
    #[must_use]
    pub fn finding(&self) -> ChainFinding {
        self.finding
    }

    /// Whether the chain is intact.
    #[must_use]
    pub fn is_verified(&self) -> bool {
        self.finding == ChainFinding::Intact
    }

    /// How many records were walked.
    #[must_use]
    pub fn entries_checked(&self) -> u64 {
        self.entries_checked
    }

    /// The sequence number of the first tampered record, if any.
    #[must_use]
    pub fn broken_at_seq(&self) -> Option<i64> {
        match self.finding {
            ChainFinding::Intact => None,
            ChainFinding::BrokenAt(seq) => Some(seq),
        }
    }

    /// What this walk of the chain of `walked_for` raises: for a broken
    /// chain, `tenant.audit_chain_broken` naming how far it verified and
    /// where it broke, and for an intact one nothing.
    ///
    /// A walk changes nothing it reads, so nothing is saved first. The
    /// tenant whose chain was walked is the one the record names.
    #[must_use]
    pub fn events(&self, walked_for: &impl SavedFor) -> Vec<DomainEvent> {
        let ChainFinding::BrokenAt(broken_at_seq) = self.finding else {
            return Vec::new();
        };
        let mut raised = Raised::<ResolvedTenant>::default();
        raised.raise(TenantAuditChainBroken {
            entries_checked: self.entries_checked,
            broken_at_seq,
            occurred_at: crate::shared::clock::now(),
        });
        raised.take(walked_for)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::isolation::scope::TenantScope;

    /// One chain recomputes in full and another breaks at record 743. Only
    /// the first counts as verified.
    #[test]
    fn an_intact_chain_is_told_apart_from_a_broken_one() {
        let intact = AuditChainVerification::intact(1_000);
        let broken = AuditChainVerification::broken(742, 743);

        assert!(intact.is_verified());
        assert!(!broken.is_verified());
    }

    /// A walk checks 742 records and finds 743 tampered. The result reports
    /// both numbers. An intact walk reports its count and no broken record.
    #[test]
    fn a_verification_says_how_far_it_walked_and_where_it_broke() {
        let intact = AuditChainVerification::intact(1_000);
        let broken = AuditChainVerification::broken(742, 743);

        assert_eq!(intact.entries_checked(), 1_000);
        assert_eq!(
            intact.broken_at_seq(),
            None,
            "an intact chain names no broken record"
        );

        assert_eq!(broken.entries_checked(), 742);
        assert_eq!(broken.broken_at_seq(), Some(743));
    }

    fn acme() -> ResolvedTenant {
        ResolvedTenant::new(
            crate::types::TenantId::new(),
            crate::types::TenantSlug::new("acme", &crate::shared::config::SlugLimits::default())
                .unwrap(),
        )
    }

    /// Acme's chain breaks at record 743 after 742 verified. The walk raises
    /// `tenant.audit_chain_broken` for Acme, naming both numbers.
    #[test]
    fn a_broken_chain_raises_its_break_for_the_tenant_walked() {
        let acme = acme();

        let events = AuditChainVerification::broken(742, 743).events(&acme);

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type().as_str(), "tenant.audit_chain_broken");
        assert_eq!(events[0].tenant_id(), Some(acme.tenant_id()));
        assert_eq!(events[0].payload().get("entries_checked"), Some("742"));
        assert_eq!(events[0].payload().get("broken_at_seq"), Some("743"));
    }

    /// Acme's chain recomputes in full. The walk raises nothing.
    #[test]
    fn an_intact_chain_raises_nothing() {
        assert!(
            AuditChainVerification::intact(1_000)
                .events(&acme())
                .is_empty()
        );
    }
}
