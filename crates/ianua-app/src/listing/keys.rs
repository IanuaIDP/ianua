//! The values a row is ordered by, and the orders a list can be paged in.
//!
//! A row of a list of `F` names its value on each field ([`SortKeys`]). An
//! order ([`KeyOrder`]) names itself and the direction of each value, and
//! reads a row's values ([`RowKeys`]). A [`SortOrder`] is such an order for
//! every row that has [`SortKeys`]; an order a store builds another way,
//! such as a sort by a custom attribute, implements the two traits itself.

use time::OffsetDateTime;
use uuid::Uuid;

use crate::listing::{SortDirection, SortField, SortOrder};

/// One value a row is ordered by.
///
/// The derived order compares two values of one kind as their field sorts;
/// a list never compares two kinds except against [`SortKey::Missing`].
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SortKey {
    /// A whole number, such as a count or a sequence.
    Integer(i64),
    /// Text, such as a name or a status word.
    Text(String),
    /// A moment, such as a creation time.
    Time(OffsetDateTime),
    /// A UUID used as a stable ordering value.
    Id(Uuid),
    /// No value. It sorts after every value, as Postgres puts `NULL` last in
    /// an ascending order and first in a descending one.
    Missing,
}

impl From<&str> for SortKey {
    fn from(text: &str) -> Self {
        Self::Text(text.to_owned())
    }
}

impl From<String> for SortKey {
    fn from(text: String) -> Self {
        Self::Text(text)
    }
}

impl From<OffsetDateTime> for SortKey {
    fn from(at: OffsetDateTime) -> Self {
        Self::Time(at)
    }
}

impl From<Uuid> for SortKey {
    fn from(id: Uuid) -> Self {
        Self::Id(id)
    }
}

impl From<&Uuid> for SortKey {
    fn from(id: &Uuid) -> Self {
        Self::Id(*id)
    }
}

impl From<i64> for SortKey {
    fn from(number: i64) -> Self {
        Self::Integer(number)
    }
}

impl From<u64> for SortKey {
    fn from(number: u64) -> Self {
        Self::Integer(i64::try_from(number).unwrap_or(i64::MAX))
    }
}

impl From<u32> for SortKey {
    fn from(number: u32) -> Self {
        Self::Integer(i64::from(number))
    }
}

impl<T: Into<SortKey>> From<Option<T>> for SortKey {
    fn from(value: Option<T>) -> Self {
        value.map_or(Self::Missing, Into::into)
    }
}

/// A row a list of `F` can order: its value on each field, and an id no
/// other row shares to break ties.
///
/// Stores and fakes both build a page's
/// [`Cursor`](crate::listing::Cursor) from it, so they agree on where a page
/// ends.
pub trait SortKeys<F: SortField> {
    /// The row's value on `field`.
    fn sort_key(&self, field: F) -> SortKey;

    /// The row's unique id, ordering rows whose sort values tie.
    fn tiebreak(&self) -> SortKey;
}

/// An order a list is keyset paged in.
pub trait KeyOrder {
    /// The order written out, which a cursor keeps to know the order it was
    /// made for.
    fn signature(&self) -> String;

    /// The direction of each value a row is ordered by, primary first, the
    /// tiebreaking id last.
    fn directions(&self) -> Vec<SortDirection>;
}

/// An order that reads its values off a row of `T`.
pub trait RowKeys<T>: KeyOrder {
    /// The values `row` is ordered by, one per
    /// [`direction`](KeyOrder::directions).
    fn row_keys(&self, row: &T) -> Vec<SortKey>;
}

/// A sort order is its query string, its terms' directions, and the id in
/// the last term's direction, so `ORDER BY a DESC, id DESC` is one row
/// comparison.
impl<F: SortField> KeyOrder for SortOrder<F> {
    fn signature(&self) -> String {
        self.to_string()
    }

    fn directions(&self) -> Vec<SortDirection> {
        let terms = self.terms();
        let last = terms
            .last()
            .map(|term| term.direction())
            .unwrap_or_default();
        terms
            .iter()
            .map(|term| term.direction())
            .chain(std::iter::once(last))
            .collect()
    }
}

impl<F: SortField, T: SortKeys<F>> RowKeys<T> for SortOrder<F> {
    fn row_keys(&self, row: &T) -> Vec<SortKey> {
        self.terms()
            .iter()
            .map(|term| row.sort_key(term.field()))
            .chain(std::iter::once(row.tiebreak()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::define_sort_field;

    define_sort_field! {
        /// Test field.
        enum Field {
            /// Order by name.
            Name => "name",
        }
        default = Name;
    }

    /// A row without a value sorts after every row that has one.
    #[test]
    fn a_missing_value_sorts_after_any_value() {
        assert!(SortKey::from("zzz") < SortKey::Missing);
    }

    /// A list newest first breaks ties between rows of one moment highest id
    /// first, in the direction of its last term.
    #[test]
    fn the_id_follows_the_last_term_direction() {
        let sort = SortOrder::<Field>::parse(Some("-name")).unwrap();

        assert_eq!(
            sort.directions(),
            [SortDirection::Desc, SortDirection::Desc]
        );
    }
}
