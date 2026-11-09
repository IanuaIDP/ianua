//! A walk of a tenant's audit chain, one bounded stretch at a time.
//!
//! An adapter rehashes one stretch of records after where the walk stands
//! and says what it found. The walk adds it up: it moves its start past an
//! intact stretch, stops at the end of the chain or at a break, and can be
//! paused partway so a long chain is finished on a later sweep.

use crate::domains::audit::chain::AuditChainVerification;
use crate::domains::audit::checkpoint::{ChainCheckpoint, ChainStart};

/// What an adapter found rehashing one stretch of the chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainStretch {
    /// Every record of the stretch held; `last` is the last of them.
    Intact {
        /// How many records the stretch held.
        checked: u64,
        /// The last record verified.
        last: ChainCheckpoint,
    },
    /// No record follows the start, and the chain's signed head matches
    /// the last link: the walk reached the end.
    Ended,
    /// A record did not rehash, or the signed head did not match.
    Broken {
        /// How many records verified in the stretch before the break.
        checked: u64,
        /// The sequence number of the first record that did not.
        at_seq: i64,
    },
}

/// How a walk left the chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainStanding {
    /// Every record verified, up to the signed head.
    Intact,
    /// Every record walked verified, but the walk paused before the end.
    IntactSoFar,
    /// The first record that did not verify.
    BrokenAt(i64),
}

impl ChainStanding {
    /// The standing's name, stable across releases.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Intact => "intact",
            Self::IntactSoFar => "intact_so_far",
            Self::BrokenAt(_) => "broken",
        }
    }
}

/// A walk under way: where the next stretch starts and how many records
/// verified so far.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainWalk {
    start: ChainStart,
    checked: u64,
}

/// What taking one stretch did to a walk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WalkStep {
    /// The stretch held; the walk goes on from its last record.
    Onward(ChainWalk),
    /// The walk reached the end or a break.
    Done(ChainWalked),
}

/// A finished or paused walk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainWalked {
    standing: ChainStanding,
    checked: u64,
    checkpoint: ChainStart,
}

impl ChainWalk {
    /// A walk starting at `start`, nothing verified yet.
    #[must_use]
    pub fn starting(start: ChainStart) -> Self {
        Self { start, checked: 0 }
    }

    /// Where the next stretch starts.
    #[must_use]
    pub fn start(&self) -> &ChainStart {
        &self.start
    }

    /// The walk once `stretch` is added to it.
    #[must_use]
    pub fn take(self, stretch: ChainStretch) -> WalkStep {
        match stretch {
            ChainStretch::Intact { checked, last } => WalkStep::Onward(Self {
                start: ChainStart::After(last),
                checked: self.checked.saturating_add(checked),
            }),
            ChainStretch::Ended => WalkStep::Done(self.ending(ChainStanding::Intact, 0)),
            ChainStretch::Broken { checked, at_seq } => {
                WalkStep::Done(self.ending(ChainStanding::BrokenAt(at_seq), checked))
            }
        }
    }

    /// The walk stopped here, intact so far, to go on next time.
    #[must_use]
    pub fn paused(self) -> ChainWalked {
        self.ending(ChainStanding::IntactSoFar, 0)
    }

    fn ending(self, standing: ChainStanding, more: u64) -> ChainWalked {
        ChainWalked {
            standing,
            checked: self.checked.saturating_add(more),
            checkpoint: self.start,
        }
    }
}

impl ChainWalked {
    /// How the walk left the chain.
    #[must_use]
    pub fn standing(&self) -> ChainStanding {
        self.standing
    }

    /// How many records this walk verified.
    #[must_use]
    pub fn checked(&self) -> u64 {
        self.checked
    }

    /// The last link the walk verified, where the next walk starts.
    #[must_use]
    pub fn checkpoint(&self) -> &ChainStart {
        &self.checkpoint
    }

    /// The walk as a verification, which raises the alarm for a break.
    #[must_use]
    pub fn verification(&self) -> AuditChainVerification {
        match self.standing {
            ChainStanding::BrokenAt(seq) => AuditChainVerification::broken(self.checked, seq),
            ChainStanding::Intact | ChainStanding::IntactSoFar => {
                AuditChainVerification::intact(self.checked)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::audit::checkpoint::ChainHash;

    fn link(seq: i64) -> ChainCheckpoint {
        ChainCheckpoint::from_stored(seq, ChainHash::from_stored(&[3; 32]).unwrap()).unwrap()
    }

    fn onward(step: WalkStep) -> ChainWalk {
        match step {
            WalkStep::Onward(walk) => walk,
            WalkStep::Done(walked) => panic!("the walk ended early: {walked:?}"),
        }
    }

    fn done(step: WalkStep) -> ChainWalked {
        match step {
            WalkStep::Done(walked) => walked,
            WalkStep::Onward(walk) => panic!("the walk went on: {walk:?}"),
        }
    }

    /// Two stretches of 500 hold and then the chain ends. The walk is
    /// intact, counts 1,000 records and keeps record 1,000 as its
    /// checkpoint.
    #[test]
    fn intact_stretches_move_the_checkpoint_to_the_end() {
        let walk = ChainWalk::starting(ChainStart::Genesis);
        let walk = onward(walk.take(ChainStretch::Intact {
            checked: 500,
            last: link(500),
        }));
        let walk = onward(walk.take(ChainStretch::Intact {
            checked: 500,
            last: link(1_000),
        }));

        let walked = done(walk.take(ChainStretch::Ended));

        assert_eq!(walked.standing(), ChainStanding::Intact);
        assert_eq!(walked.checked(), 1_000);
        assert_eq!(walked.checkpoint(), &ChainStart::After(link(1_000)));
    }

    /// Record 743 was rewritten. The walk stops there, broken, and keeps
    /// the last intact stretch's end as its checkpoint so the next walk
    /// finds the break again.
    #[test]
    fn a_break_ends_the_walk_at_the_last_intact_link() {
        let walk = onward(
            ChainWalk::starting(ChainStart::Genesis).take(ChainStretch::Intact {
                checked: 500,
                last: link(500),
            }),
        );

        let walked = done(walk.take(ChainStretch::Broken {
            checked: 242,
            at_seq: 743,
        }));

        assert_eq!(walked.standing(), ChainStanding::BrokenAt(743));
        assert_eq!(walked.checked(), 742);
        assert_eq!(walked.checkpoint(), &ChainStart::After(link(500)));
        assert_eq!(walked.verification().broken_at_seq(), Some(743));
    }

    /// The sweep's budget runs out after one stretch. The walk pauses
    /// intact so far, and the next one starts after that stretch.
    #[test]
    fn a_paused_walk_is_intact_so_far() {
        let walk = onward(
            ChainWalk::starting(ChainStart::Genesis).take(ChainStretch::Intact {
                checked: 500,
                last: link(500),
            }),
        );

        let walked = walk.paused();

        assert_eq!(walked.standing(), ChainStanding::IntactSoFar);
        assert_eq!(walked.checkpoint().verified_through(), Some(500));
        assert!(walked.verification().is_verified());
    }
}
