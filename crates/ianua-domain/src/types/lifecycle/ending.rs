//! Whether something that runs until it is ended still runs, said outright.

use time::OffsetDateTime;

/// Whether a channel, an assignment or the like is still open, or when it
/// was ended.
///
/// A bare missing end time looks the same as one left out by mistake, and
/// either way the thing would stay open. So "ongoing" is a value someone
/// writes, and an end always carries the instant it happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ending {
    /// Still open.
    Ongoing,
    /// Ended at this instant.
    Ended {
        /// When it ended.
        at: OffsetDateTime,
    },
}

impl Ending {
    /// The ending a stored end time records. No time means ongoing.
    #[must_use]
    pub fn from_stored(ended_at: Option<OffsetDateTime>) -> Self {
        ended_at.map_or(Self::Ongoing, |at| Self::Ended { at })
    }

    /// Whether it has ended.
    #[must_use]
    pub fn has_ended(self) -> bool {
        matches!(self, Self::Ended { .. })
    }

    /// When it ended, if it did. Storage keeps it in this form.
    #[must_use]
    pub fn ended_at(self) -> Option<OffsetDateTime> {
        match self {
            Self::Ongoing => None,
            Self::Ended { at } => Some(at),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A stored end time reads back as ended at that time. No stored time
    /// reads back as ongoing, which has not ended.
    #[test]
    fn a_stored_time_reads_back_as_ended_then() {
        let now = crate::shared::clock::now();

        assert_eq!(Ending::from_stored(Some(now)), Ending::Ended { at: now });
        assert_eq!(Ending::from_stored(None), Ending::Ongoing);
        assert!(!Ending::Ongoing.has_ended());
    }
}
