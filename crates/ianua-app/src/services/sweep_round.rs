//! What one round of a sweep over many items came to.
//!
//! A sweep changes each item in a unit of its own with the record of the
//! change, so an item is changed and recorded, or left as it was. One that
//! could not be kept is counted here and found again by the next round,
//! which looks at what is due then.

/// How one round of a sweep went.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SweepRound {
    changed: u32,
    failed: u32,
}

impl SweepRound {
    /// The round with one more item changed and recorded.
    #[must_use]
    pub(crate) fn with_changed(self) -> Self {
        Self {
            changed: self.changed.saturating_add(1),
            ..self
        }
    }

    /// The round with one more item whose change and record could not be
    /// kept, so it was left as it was for the next round.
    #[must_use]
    pub(crate) fn with_failed(self) -> Self {
        Self {
            failed: self.failed.saturating_add(1),
            ..self
        }
    }

    /// How many items the round changed and recorded.
    #[must_use]
    pub fn changed(&self) -> u32 {
        self.changed
    }

    /// How many items it left as they were, for the next round.
    #[must_use]
    pub fn failed(&self) -> u32 {
        self.failed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two items changed and one failed: the round says so.
    #[test]
    fn a_round_counts_what_it_changed_and_what_it_left() {
        let round = SweepRound::default()
            .with_changed()
            .with_failed()
            .with_changed();

        assert_eq!((round.changed(), round.failed()), (2, 1));
    }
}
