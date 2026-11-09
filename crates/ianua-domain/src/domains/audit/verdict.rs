//! The last verification of a tenant's audit chain, as the sweep keeps it.
//!
//! The scheduled sweep walks each chain and keeps what it found: when, how
//! the chain stood, and the last link it verified. An auditor reads that
//! instead of walking the chain inside their request, and the next sweep
//! starts after the kept link. A break is announced the first time a sweep
//! finds it, not again on every sweep that finds the same one.

use time::OffsetDateTime;

use crate::domains::audit::checkpoint::ChainStart;
use crate::domains::audit::walk::{ChainStanding, ChainWalk, ChainWalked};
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::SavedFor;
use crate::shared::model::row_check::RowCheck;

/// What the last sweep found in a tenant's audit chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainVerdict {
    verified_at: OffsetDateTime,
    standing: ChainStanding,
    checkpoint: ChainStart,
}

/// A kept verdict as storage keeps it, checked again by
/// [`ChainVerdict::reconstitute`].
pub struct ChainVerdictRow {
    /// When the sweep walked the chain.
    pub verified_at: OffsetDateTime,
    /// How the chain stood.
    pub standing: ChainStanding,
    /// The last link verified.
    pub checkpoint: ChainStart,
}

impl ChainVerdict {
    /// What `walked` found, at `verified_at`.
    #[must_use]
    pub fn of(walked: &ChainWalked, verified_at: OffsetDateTime) -> Self {
        Self {
            verified_at,
            standing: walked.standing(),
            checkpoint: walked.checkpoint().clone(),
        }
    }

    /// Rebuilds a kept verdict from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the row breaks at a record
    ///   before the first or not after its checkpoint, or says the chain is
    ///   intact so far with nothing verified.
    pub fn reconstitute(row: ChainVerdictRow) -> Result<Self, DomainError> {
        let through = row.checkpoint.verified_through().unwrap_or(0);
        let break_follows = match row.standing {
            ChainStanding::BrokenAt(seq) => seq >= 1 && seq > through,
            ChainStanding::Intact | ChainStanding::IntactSoFar => true,
        };
        RowCheck::of("audit chain verdict")
            .holds(
                break_follows,
                "a break at or before the last link it verified",
            )
            .holds(
                row.standing != ChainStanding::IntactSoFar || through > 0,
                "intact so far with nothing verified",
            )
            .finish()?;
        Ok(Self {
            verified_at: row.verified_at,
            standing: row.standing,
            checkpoint: row.checkpoint,
        })
    }

    /// When the sweep walked the chain.
    #[must_use]
    pub fn verified_at(&self) -> OffsetDateTime {
        self.verified_at
    }

    /// How the chain stood.
    #[must_use]
    pub fn standing(&self) -> ChainStanding {
        self.standing
    }

    /// The last link verified.
    #[must_use]
    pub fn checkpoint(&self) -> &ChainStart {
        &self.checkpoint
    }
}

/// What is known of a chain before a sweep walks it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainHistory {
    /// No sweep has walked it yet.
    NeverVerified,
    /// The last sweep's verdict.
    Verified(ChainVerdict),
}

impl ChainHistory {
    /// The walk this sweep takes: from the last verified link, or from the
    /// start when nothing was verified.
    #[must_use]
    pub fn walk(&self) -> ChainWalk {
        match self {
            Self::NeverVerified => ChainWalk::starting(ChainStart::Genesis),
            Self::Verified(verdict) => ChainWalk::starting(verdict.checkpoint.clone()),
        }
    }

    /// What `walked` raises for the chain of `walked_for`:
    /// `tenant.audit_chain_broken` for a break the last verdict did not
    /// already hold, and nothing otherwise.
    #[must_use]
    pub fn alarm(&self, walked: &ChainWalked, walked_for: &impl SavedFor) -> Vec<DomainEvent> {
        let known = match self {
            Self::NeverVerified => false,
            Self::Verified(verdict) => verdict.standing == walked.standing(),
        };
        if known {
            return Vec::new();
        }
        walked.verification().events(walked_for)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::audit::checkpoint::{ChainCheckpoint, ChainHash};
    use crate::domains::audit::walk::{ChainStretch, WalkStep};
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::model::row_check::refused_as_corrupt;

    fn link(seq: i64) -> ChainCheckpoint {
        ChainCheckpoint::from_stored(seq, ChainHash::from_stored(&[5; 32]).unwrap()).unwrap()
    }

    fn acme() -> ResolvedTenant {
        ResolvedTenant::new(
            crate::types::TenantId::new(),
            crate::types::TenantSlug::new("acme", &crate::shared::config::SlugLimits::default())
                .unwrap(),
        )
    }

    fn broken_at(history: &ChainHistory, seq: i64) -> ChainWalked {
        match history.walk().take(ChainStretch::Broken {
            checked: 0,
            at_seq: seq,
        }) {
            WalkStep::Done(walked) => walked,
            WalkStep::Onward(walk) => panic!("a break went on: {walk:?}"),
        }
    }

    fn row(standing: ChainStanding, checkpoint: ChainStart) -> ChainVerdictRow {
        ChainVerdictRow {
            verified_at: crate::shared::clock::now(),
            standing,
            checkpoint,
        }
    }

    /// The last sweep verified Acme's chain through record 500. This sweep
    /// starts after it.
    #[test]
    fn a_sweep_starts_after_the_last_verified_link() {
        let verdict =
            ChainVerdict::reconstitute(row(ChainStanding::Intact, ChainStart::After(link(500))))
                .unwrap();

        let walk = ChainHistory::Verified(verdict).walk();

        assert_eq!(walk.start().verified_through(), Some(500));
    }

    /// Acme's chain was never walked. This sweep starts at the first
    /// record.
    #[test]
    fn a_first_sweep_starts_at_the_first_record() {
        assert_eq!(
            ChainHistory::NeverVerified.walk().start(),
            &ChainStart::Genesis
        );
    }

    /// A sweep finds Acme's chain broken at record 743 for the first time.
    /// It raises the alarm.
    #[test]
    fn a_new_break_raises_the_alarm() {
        let history = ChainHistory::NeverVerified;
        let walked = broken_at(&history, 743);

        let events = history.alarm(&walked, &acme());

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type().as_str(), "tenant.audit_chain_broken");
    }

    /// The last sweep already found the break at 743 and this one finds it
    /// again. Nobody is told twice.
    #[test]
    fn a_known_break_is_not_announced_again() {
        let earlier = broken_at(&ChainHistory::NeverVerified, 743);
        let history =
            ChainHistory::Verified(ChainVerdict::of(&earlier, crate::shared::clock::now()));
        let again = broken_at(&history, 743);

        assert!(history.alarm(&again, &acme()).is_empty());
    }

    /// A stored verdict breaks at record 400 but says record 500 verified.
    /// It is refused as corrupt.
    #[test]
    fn a_stored_break_before_its_checkpoint_is_refused() {
        let stored = row(ChainStanding::BrokenAt(400), ChainStart::After(link(500)));

        assert!(refused_as_corrupt(&ChainVerdict::reconstitute(stored)));
    }

    /// A stored verdict says intact so far but verified nothing. It is
    /// refused as corrupt.
    #[test]
    fn a_stored_partial_verdict_with_nothing_verified_is_refused() {
        let stored = row(ChainStanding::IntactSoFar, ChainStart::Genesis);

        assert!(refused_as_corrupt(&ChainVerdict::reconstitute(stored)));
    }
}
