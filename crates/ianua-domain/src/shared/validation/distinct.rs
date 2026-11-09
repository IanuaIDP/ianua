//! Lists that must not name the same thing twice.

use std::collections::HashSet;
use std::hash::Hash;

/// The first value that appears a second time, if any does.
///
/// Every list that must hold each value once asks this, so a repeated host,
/// record value, list item or field name is caught the same way everywhere.
/// Values are compared as given, usually references into the list.
#[must_use]
pub fn first_repeat<T: Eq + Hash + Copy>(values: impl IntoIterator<Item = T>) -> Option<T> {
    let mut seen = HashSet::new();
    values.into_iter().find(|value| !seen.insert(*value))
}

/// `values` with every repeat dropped, each value kept where it first appears.
///
/// For lists where naming a value twice means the same as naming it once.
#[must_use]
pub(crate) fn without_repeats<T: Eq + Hash + Clone>(values: Vec<T>) -> Vec<T> {
    let mut seen = HashSet::new();
    values
        .into_iter()
        .filter(|value| seen.insert(value.clone()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The list `b, a, b, c, a` becomes `b, a, c`. Order follows each
    /// value's first appearance.
    #[test]
    fn repeats_are_dropped_and_first_places_kept() {
        assert_eq!(
            without_repeats(vec!["b", "a", "b", "c", "a"]),
            ["b", "a", "c"]
        );
    }

    /// In `a, b, a, b` both values repeat. The first one seen twice, `a`, is
    /// the one reported.
    #[test]
    fn the_second_sighting_of_a_value_is_reported() {
        assert_eq!(first_repeat(["a", "b", "a", "b"]), Some("a"));
    }

    /// Three different values, and an empty list, report no repeat.
    #[test]
    fn a_list_of_distinct_values_has_no_repeat() {
        assert_eq!(first_repeat(["a", "b", "c"]), None);
        assert_eq!(first_repeat(Vec::<&str>::new()), None);
    }
}
