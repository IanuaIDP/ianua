//! When something stops being valid, or that it never does, said outright.

use time::OffsetDateTime;

/// When a credential or grant stops being valid, or that it never does.
///
/// A bare missing expiry looks the same as one left out by mistake, and
/// either way the credential would work forever. So "never" is a value
/// someone has to write. Expiry is judged in one place, and at the instant
/// itself the thing is already expired.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum Expiry {
    /// It does not expire.
    Never,
    /// It stops being valid at this instant.
    At(OffsetDateTime),
}

impl Expiry {
    /// Whether it has expired by `now`. It counts as expired from its expiry
    /// instant on.
    #[must_use]
    pub fn has_passed(&self, now: OffsetDateTime) -> bool {
        match self {
            Self::Never => false,
            Self::At(at) => now >= *at,
        }
    }

    /// The instant, when there is one.
    #[must_use]
    pub fn instant(&self) -> Option<OffsetDateTime> {
        match self {
            Self::Never => None,
            Self::At(at) => Some(*at),
        }
    }

    /// Whichever of this and `other` comes first: what holds while both
    /// must. Never is later than any instant.
    #[must_use]
    pub fn earliest(self, other: Self) -> Self {
        match (self, other) {
            (Self::At(mine), Self::At(theirs)) => Self::At(mine.min(theirs)),
            (Self::At(at), Self::Never) | (Self::Never, Self::At(at)) => Self::At(at),
            (Self::Never, Self::Never) => Self::Never,
        }
    }
}

#[cfg(test)]
mod tests {
    use time::Duration;

    use super::*;

    fn at() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap()
    }

    /// A grant expires at a set instant. A second before, it is valid. At
    /// that instant and after, it has expired.
    #[test]
    fn it_has_expired_from_its_instant_on() {
        let expiry = Expiry::At(at());

        assert!(!expiry.has_passed(at() - Duration::seconds(1)));
        assert!(expiry.has_passed(at()));
        assert!(expiry.has_passed(at() + Duration::seconds(1)));
    }

    /// A key that runs out tomorrow, held by a token that runs out in an
    /// hour, works for the hour. Never yields to any instant.
    #[test]
    fn the_earliest_expiry_holds_while_both_must() {
        let hour = Expiry::At(at() + Duration::hours(1));
        let day = Expiry::At(at() + Duration::days(1));

        assert_eq!(day.earliest(hour), hour);
        assert_eq!(hour.earliest(day), hour);
        assert_eq!(Expiry::Never.earliest(day), day);
        assert_eq!(Expiry::Never.earliest(Expiry::Never), Expiry::Never);
    }

    /// A grant that never expires is still valid a hundred years on.
    #[test]
    fn never_does_not_pass() {
        assert!(!Expiry::Never.has_passed(at() + Duration::days(36_500)));
    }
}
