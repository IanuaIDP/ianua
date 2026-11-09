//! The 30-second window a one-time code belongs to.

use time::OffsetDateTime;

/// How long one code stays the current one.
pub const STEP_SECONDS: i64 = 30;

/// One window of the TOTP clock. It is the count of 30-second steps since the
/// Unix epoch.
///
/// A code is good for its step. The verifier also accepts the step on each
/// side of now, to allow for clock drift. So one code stays acceptable for
/// about 90 seconds. Recording the steps already used stops someone who saw
/// a code once from sending it again.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TimeStep(u64);

impl TimeStep {
    /// The step that contains `at`. `None` before the epoch, where no code
    /// was ever issued.
    #[must_use]
    pub fn containing(at: OffsetDateTime) -> Option<Self> {
        u64::try_from(at.unix_timestamp() / STEP_SECONDS)
            .ok()
            .map(Self)
    }

    /// A step by its number, as stored.
    #[must_use]
    pub fn from_number(number: u64) -> Self {
        Self(number)
    }

    /// The step's number since the epoch.
    #[must_use]
    pub fn number(self) -> u64 {
        self.0
    }

    /// The step before this one. `None` for step 0.
    #[must_use]
    pub fn previous(self) -> Option<Self> {
        self.0.checked_sub(1).map(Self)
    }

    /// The step after this one.
    #[must_use]
    pub fn next(self) -> Self {
        Self(self.0.saturating_add(1))
    }

    /// The first second of the step, as Unix time.
    #[must_use]
    pub fn starts_at(self) -> u64 {
        self.0.saturating_mul(STEP_SECONDS.unsigned_abs())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BOUNDARY: i64 = 1_800_000_000;

    fn at(unix: i64) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(unix).unwrap()
    }

    /// A time on a step boundary and one 29 seconds later fall in the same
    /// step. Thirty seconds later is the next step, and its previous step is
    /// the first.
    #[test]
    fn a_step_covers_thirty_seconds() {
        let first = TimeStep::containing(at(BOUNDARY)).unwrap();
        let same = TimeStep::containing(at(BOUNDARY + 29)).unwrap();
        let after = TimeStep::containing(at(BOUNDARY + 30)).unwrap();

        assert_eq!(first, same);
        assert_eq!(after, first.next());
        assert_eq!(after.previous(), Some(first));
    }

    /// A code checked 17 seconds into a step belongs to a step that starts on
    /// the boundary, not at the moment of the check.
    #[test]
    fn a_step_starts_on_its_own_boundary() {
        let step = TimeStep::containing(at(BOUNDARY + 17)).unwrap();

        assert_eq!(step.starts_at(), BOUNDARY.unsigned_abs());
    }

    /// A time 60 seconds before the Unix epoch has no step, because no code
    /// was ever issued then.
    #[test]
    fn before_the_epoch_there_is_no_step() {
        assert_eq!(TimeStep::containing(at(-60)), None);
    }

    /// Step 0 has no previous step. Asking for one gives `None` instead of
    /// wrapping round to a huge number.
    #[test]
    fn the_first_step_has_nothing_before_it() {
        assert_eq!(TimeStep::from_number(0).previous(), None);
    }
}
