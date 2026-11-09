//! Whether something meant to be used once has been, said outright.

use time::OffsetDateTime;

/// Whether a single-use thing has been used, and when.
///
/// It covers emailed tokens, authorization codes, passkey ceremonies and
/// recovery codes. A bare missing time looks the same as one left out by
/// mistake, and either way the thing would work again. So "unused" is a
/// value someone writes, and a use always carries the instant it happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Usage {
    /// Not used yet.
    Unused,
    /// Used at this instant.
    Used {
        /// When it was used.
        at: OffsetDateTime,
    },
}

impl Usage {
    /// The usage a stored use time records. No time means unused.
    #[must_use]
    pub fn from_stored(used_at: Option<OffsetDateTime>) -> Self {
        used_at.map_or(Self::Unused, |at| Self::Used { at })
    }

    /// Whether it has been used.
    #[must_use]
    pub fn is_used(self) -> bool {
        matches!(self, Self::Used { .. })
    }

    /// When it was used, if it was. Storage keeps it in this form.
    #[must_use]
    pub fn used_at(self) -> Option<OffsetDateTime> {
        match self {
            Self::Unused => None,
            Self::Used { at } => Some(at),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A stored use time reads back as used at that time. No stored time
    /// reads back as unused, which counts as not used.
    #[test]
    fn a_stored_time_reads_back_as_used_then() {
        let now = crate::shared::clock::now();

        assert_eq!(Usage::from_stored(Some(now)), Usage::Used { at: now });
        assert_eq!(Usage::from_stored(None), Usage::Unused);
        assert_eq!(Usage::Used { at: now }.used_at(), Some(now));
        assert!(!Usage::Unused.is_used());
    }
}
