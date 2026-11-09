//! Something observed about a request or a sign-in, or that it was not.

/// A fact a check may read, or that nobody observed it.
///
/// Facts include the client's address, its country and how strongly it
/// signed in. This is not an `Option`. A check written against an `Option`
/// reaches for `unwrap_or`, `is_some_and` or `map_or` and quietly picks what
/// an unknown fact means, often "allowed". Here an unknown fact is a case of
/// its own. A check has to `match` it. Storage and display read it through
/// [`Fact::known`], which says what it gives up.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Fact<T> {
    /// It was observed, and this is what it was.
    Known(T),
    /// Nobody observed it. The edge reported nothing, the lookup failed, or
    /// the caller sent none.
    #[default]
    Unknown,
}

impl<T> Fact<T> {
    /// The fact as storage or a page shows it, with nothing when unknown.
    ///
    /// Not for checks. A check that reads this has to decide what nothing
    /// means, and `Fact` is there to make a check state that decision.
    #[must_use]
    pub fn known(&self) -> Option<&T> {
        match self {
            Self::Known(value) => Some(value),
            Self::Unknown => None,
        }
    }

    /// A fact read back from storage or a caller, where absence was written
    /// as nothing.
    #[must_use]
    pub fn from_option(value: Option<T>) -> Self {
        value.map_or(Self::Unknown, Self::Known)
    }

    /// The same fact about something derived from it.
    #[must_use]
    pub fn map<U>(self, derive: impl FnOnce(T) -> U) -> Fact<U> {
        match self {
            Self::Known(value) => Fact::Known(derive(value)),
            Self::Unknown => Fact::Unknown,
        }
    }

    /// The fact borrowed.
    #[must_use]
    pub fn as_ref(&self) -> Fact<&T> {
        match self {
            Self::Known(value) => Fact::Known(value),
            Self::Unknown => Fact::Unknown,
        }
    }
}

impl<T: Clone> Fact<&T> {
    /// The fact with its value copied out.
    #[must_use]
    pub fn cloned(self) -> Fact<T> {
        self.map(Clone::clone)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// No stored value reads as unknown, and a stored 3 reads back as known
    /// 3. Mapping a known 2 by doubling gives a known 4.
    #[test]
    fn absence_reads_as_unknown_and_back() {
        assert_eq!(Fact::<u8>::from_option(None), Fact::Unknown);
        assert_eq!(Fact::from_option(Some(3)).known(), Some(&3));
        assert_eq!(Fact::Known(2).map(|n| n * 2), Fact::Known(4));
    }
}
