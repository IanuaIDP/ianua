//! When a person last changed how they sign in, or that they never did.

use time::OffsetDateTime;

/// When a person last changed how they sign in, or that they never have.
///
/// A change is a password set or reset, or a second factor added or
/// removed. Trust granted before it ends, such as a remembered device or a
/// pending email change. Every such rule asks through
/// [`CredentialChange::since`], so "never changed" reads the same in each.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CredentialChange {
    /// Never changed since the account was made.
    #[default]
    Never,
    /// Last changed at this instant.
    At {
        /// When the change happened.
        at: OffsetDateTime,
    },
}

impl CredentialChange {
    /// The change a stored time records. No time means never.
    #[must_use]
    pub fn from_stored(changed_at: Option<OffsetDateTime>) -> Self {
        changed_at.map_or(Self::Never, |at| Self::At { at })
    }

    /// Whether the credentials changed at or after `instant`, which ends any
    /// trust granted at `instant`.
    #[must_use]
    pub fn since(self, instant: OffsetDateTime) -> bool {
        match self {
            Self::Never => false,
            Self::At { at } => at >= instant,
        }
    }

    /// When they last changed, if ever. Storage keeps it in this form.
    #[must_use]
    pub fn changed_at(self) -> Option<OffsetDateTime> {
        match self {
            Self::Never => None,
            Self::At { at } => Some(at),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Bob resets his password at the same instant a device was trusted.
    /// That trust ends. A change a second earlier than the trust does not
    /// end it, and no change never does.
    #[test]
    fn a_change_at_the_same_instant_counts_as_since() {
        let now = crate::shared::clock::now();

        assert!(CredentialChange::At { at: now }.since(now));
        assert!(!CredentialChange::At { at: now }.since(now + time::Duration::seconds(1)));
        assert!(!CredentialChange::Never.since(now));
    }
}
