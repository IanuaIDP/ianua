//! A limit that is either set or lifted, said in so many words.

/// A limit on what something may do, or the explicit absence of one.
///
/// Used where a missing value would otherwise mean "no limit". With an
/// `Option`, a bug, a forgotten field or a stored row missing a key all read
/// as "no limit", and the rule stops applying without anyone seeing. Here
/// lifting a limit is a value someone has to write. A stored row without it
/// does not load.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum Restriction<T> {
    /// No limit applies.
    Unrestricted,
    /// Held to this limit.
    To(T),
}

impl<T> Restriction<T> {
    /// The limit, when there is one.
    #[must_use]
    pub fn limit(&self) -> Option<&T> {
        match self {
            Self::Unrestricted => None,
            Self::To(limit) => Some(limit),
        }
    }

    /// Whether a limit applies.
    #[must_use]
    pub fn is_restricted(&self) -> bool {
        matches!(self, Self::To(_))
    }

    /// What `self` may be when it sits under `ceiling`.
    ///
    /// Under no ceiling, anything asked for stands. Under a ceiling, asking
    /// for no limit gets the ceiling's own limit, so leaving a limit out never
    /// lifts it. A limit asked for must fit inside the ceiling's by `fits`, or
    /// the answer is `None`.
    #[must_use]
    pub fn under(self, ceiling: &Self, fits: impl Fn(&T, &T) -> bool) -> Option<Self>
    where
        T: Clone,
    {
        match (ceiling, self) {
            (Self::Unrestricted, asked) => Some(asked),
            (Self::To(limit), Self::Unrestricted) => Some(Self::To(limit.clone())),
            (Self::To(limit), Self::To(asked)) => fits(&asked, limit).then_some(Self::To(asked)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at_most(asked: &u32, limit: &u32) -> bool {
        asked <= limit
    }

    /// Under an unrestricted ceiling, both "no limit" and "at most 5" are
    /// kept as asked.
    #[test]
    fn anything_stands_under_no_limit() {
        assert_eq!(
            Restriction::Unrestricted.under(&Restriction::<u32>::Unrestricted, at_most),
            Some(Restriction::Unrestricted)
        );
        assert_eq!(
            Restriction::To(5).under(&Restriction::Unrestricted, at_most),
            Some(Restriction::To(5))
        );
    }

    /// An unrestricted request under a ceiling of five inherits that ceiling
    /// instead of lifting the parent's limit.
    #[test]
    fn asking_for_no_limit_under_one_takes_that_limit() {
        assert_eq!(
            Restriction::Unrestricted.under(&Restriction::To(5), at_most),
            Some(Restriction::To(5))
        );
    }

    /// Under a ceiling of 5, asking for 3 is kept. Asking for 9 gets `None`,
    /// since it would be more than the ceiling allows.
    #[test]
    fn a_limit_must_fit_inside_the_ceiling() {
        assert_eq!(
            Restriction::To(3).under(&Restriction::To(5), at_most),
            Some(Restriction::To(3))
        );
        assert_eq!(Restriction::To(9).under(&Restriction::To(5), at_most), None);
    }

    proptest::proptest! {
        /// For any limit asked for, or none, under any ceiling, the result
        /// is either refused or a limit no larger than the ceiling.
        #[test]
        fn nothing_held_under_a_limit_escapes_it(asked in proptest::option::of(0u32..100), limit in 0u32..100) {
            let asked = asked.map_or(Restriction::Unrestricted, Restriction::To);

            if let Some(held) = asked.under(&Restriction::To(limit), at_most) {
                proptest::prop_assert!(held.limit().is_some_and(|held| *held <= limit));
            }
        }
    }
}
