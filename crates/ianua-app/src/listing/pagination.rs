//! Keyset paging: what a list asks a store for, and the page it answers.

use std::cmp::Ordering;

use crate::listing::{
    Cursor, InvalidCursor, KeyOrder, Limit, RowKeys, SortDirection, SortField, SortKey, SortOrder,
};

/// Where a page starts and how many rows it holds.
///
/// Every list use case and every list port takes one. The first page has no
/// cursor; each later page starts after the [`Cursor`] the page before it
/// answered.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PageRequest {
    after: Option<Cursor>,
    limit: Limit,
}

impl PageRequest {
    /// The page after `after`, or the first page when it is `None`, holding
    /// at most `limit` rows.
    #[must_use]
    pub fn new(after: Option<Cursor>, limit: Limit) -> Self {
        Self { after, limit }
    }

    /// The first page, holding at most `limit` rows.
    #[must_use]
    pub fn first(limit: Limit) -> Self {
        Self::new(None, limit)
    }

    /// The cursor this page starts after, or `None` for the first page.
    #[must_use]
    pub fn after(&self) -> Option<&Cursor> {
        self.after.as_ref()
    }

    /// The most rows the page holds.
    #[must_use]
    pub fn limit(&self) -> Limit {
        self.limit
    }

    /// The page after `page`, the same size, or `None` when `page` was the
    /// last one. Sweeps walk a whole list this way.
    #[must_use]
    pub fn following<T>(&self, page: &Page<T>) -> Option<Self> {
        page.next
            .as_ref()
            .map(|cursor| Self::new(Some(cursor.clone()), self.limit))
    }

    /// This page read in `order`, checked to be a place in it.
    ///
    /// Every store and fake goes through here before it reads, so a cursor
    /// made for one order never seeks in another.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidCursor::OtherOrder`] when the cursor was made for
    /// another order.
    pub fn keyset<'a, O: KeyOrder>(&'a self, order: &'a O) -> Result<Keyset<'a, O>, InvalidCursor> {
        let directions = order.directions();
        let after = self
            .after
            .as_ref()
            .map(|cursor| fitted(cursor, order, directions.len()))
            .transpose()?;
        Ok(Keyset {
            order,
            directions,
            after,
            limit: self.limit,
        })
    }
}

/// The cursor's keys, when it was made for `order`, whose rows sort by
/// `keys` values each.
fn fitted<'a, O: KeyOrder>(
    cursor: &'a Cursor,
    order: &O,
    keys: usize,
) -> Result<&'a [SortKey], InvalidCursor> {
    let made_for_order = cursor.order() == order.signature();
    if !made_for_order || cursor.keys().len() != keys {
        return Err(InvalidCursor::OtherOrder);
    }
    Ok(cursor.keys())
}

/// One page of one list, checked against its order: what a store reads.
///
/// A store orders by [`order`](Self::order), each value in the direction
/// [`directions`](Self::directions) gives, the row's id last; reads the rows
/// strictly after [`after`](Self::after); takes [`fetch`](Self::fetch) of
/// them; and hands them to [`seal`](Self::seal).
#[derive(Debug, Clone)]
pub struct Keyset<'a, O> {
    order: &'a O,
    directions: Vec<SortDirection>,
    after: Option<&'a [SortKey]>,
    limit: Limit,
}

impl<'a, O: KeyOrder> Keyset<'a, O> {
    /// The order the rows are read in.
    #[must_use]
    pub fn order(&self) -> &'a O {
        self.order
    }

    /// The values of the row the page before ended on, one per
    /// [`direction`](Self::directions), its id last; or `None` on the first
    /// page.
    #[must_use]
    pub fn after(&self) -> Option<&'a [SortKey]> {
        self.after
    }

    /// The most rows the page holds.
    #[must_use]
    pub fn limit(&self) -> Limit {
        self.limit
    }

    /// The rows to read: one past the page, to learn whether another
    /// follows.
    #[must_use]
    pub fn fetch(&self) -> u64 {
        self.limit.fetch()
    }

    /// The direction of each value a row is ordered by, the id last.
    #[must_use]
    pub fn directions(&self) -> &[SortDirection] {
        &self.directions
    }

    /// The page `rows` make, given in order and at most
    /// [`fetch`](Self::fetch) of them: the first [`limit`](Self::limit), and a
    /// cursor at the last of those when a row was left over.
    #[must_use]
    pub fn seal<T>(&self, rows: Vec<T>) -> Page<T>
    where
        O: RowKeys<T>,
    {
        self.seal_by(rows, |row| self.order.row_keys(row))
    }

    /// The page `rows` make, as [`seal`](Self::seal) does, for a store that
    /// reads a row's values beside it rather than off it: `keys` gives them.
    #[must_use]
    pub fn seal_by<T>(&self, mut rows: Vec<T>, keys: impl Fn(&T) -> Vec<SortKey>) -> Page<T> {
        if rows.len() <= self.limit.as_usize() {
            return Page::last(rows, self.limit);
        }
        rows.truncate(self.limit.as_usize());
        let next = rows.last().map(|row| Cursor::at(self.order, keys(row)));
        Page {
            items: rows,
            next,
            limit: self.limit,
        }
    }

    /// The page an in-memory list makes, read the way a keyset query reads
    /// a table: ordered, sought past the cursor, then cut and sealed.
    ///
    /// For lists a use case already holds whole, and for the fakes.
    #[must_use]
    pub fn cut<T>(&self, rows: Vec<T>) -> Page<T>
    where
        O: RowKeys<T>,
    {
        let mut keyed: Vec<(Vec<SortKey>, T)> = rows
            .into_iter()
            .map(|row| (self.order.row_keys(&row), row))
            .collect();
        keyed.sort_by(|(a, _), (b, _)| self.compare(a, b));
        let fetch = usize::try_from(self.fetch()).unwrap_or(usize::MAX);
        let kept = keyed
            .into_iter()
            .filter(|(keys, _)| self.is_past_cursor(keys))
            .take(fetch)
            .map(|(_, row)| row)
            .collect();
        self.seal(kept)
    }

    fn is_past_cursor(&self, keys: &[SortKey]) -> bool {
        self.after
            .is_none_or(|after| self.compare(keys, after) == Ordering::Greater)
    }

    fn compare(&self, a: &[SortKey], b: &[SortKey]) -> Ordering {
        self.directions
            .iter()
            .zip(a.iter().zip(b))
            .map(|(direction, (x, y))| direction.apply(x.cmp(y)))
            .find(|ordering| ordering.is_ne())
            .unwrap_or(Ordering::Equal)
    }
}

/// What a list query asks a store for: which rows, in what order, and which
/// page of them.
#[derive(Debug, Clone, Copy)]
pub struct Listing<'a, F, S: SortField> {
    /// Which rows.
    pub filter: F,
    /// In what order.
    pub sort: &'a SortOrder<S>,
    /// Which page of them.
    pub page: &'a PageRequest,
}

impl<'a, F, S: SortField> Listing<'a, F, S> {
    /// The page this listing asks for, checked against its sort.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidCursor::OtherOrder`] when the cursor was made for
    /// another sort order.
    pub fn keyset(&self) -> Result<Keyset<'a, SortOrder<S>>, InvalidCursor> {
        self.page.keyset(self.sort)
    }
}

/// One page of a list, and where the next one starts.
#[derive(Debug, Clone, PartialEq)]
pub struct Page<T> {
    /// The rows on this page, in the list's order.
    pub items: Vec<T>,
    /// Where the next page starts, or `None` when this is the last page.
    pub next: Option<Cursor>,
    /// The most rows a page of this list holds.
    pub limit: Limit,
}

impl<T> Page<T> {
    /// A page with nothing after it.
    #[must_use]
    pub fn last(items: Vec<T>, limit: Limit) -> Self {
        Self {
            items,
            next: None,
            limit,
        }
    }

    /// Whether another page follows this one.
    #[must_use]
    pub fn has_next(&self) -> bool {
        self.next.is_some()
    }

    /// Whether this page holds no rows.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// The same page with every row turned into another type.
    #[must_use]
    pub fn map<U>(self, convert: impl FnMut(T) -> U) -> Page<U> {
        Page {
            items: self.items.into_iter().map(convert).collect(),
            next: self.next,
            limit: self.limit,
        }
    }

    /// The same page with every row turned into another type, or the first
    /// row's failure.
    ///
    /// # Errors
    ///
    /// Returns the error `convert` returns for the first row it refuses.
    pub fn try_map<U, E>(self, convert: impl FnMut(T) -> Result<U, E>) -> Result<Page<U>, E> {
        Ok(Page {
            items: self
                .items
                .into_iter()
                .map(convert)
                .collect::<Result<_, _>>()?,
            next: self.next,
            limit: self.limit,
        })
    }
}

#[cfg(test)]
mod tests {
    use time::OffsetDateTime;
    use uuid::Uuid;

    use super::*;
    use crate::define_sort_field;
    use crate::listing::SortKeys;

    define_sort_field! {
        /// Test field with a descending default.
        enum Field {
            /// Order by creation time.
            CreatedAt => "created_at",
            /// Order by name.
            Name => "name",
        }
        default = CreatedAt;
        default direction = Desc;
    }

    #[derive(Debug, Clone, PartialEq)]
    struct Row {
        id: u128,
        name: &'static str,
        created_at: i64,
    }

    impl SortKeys<Field> for Row {
        fn sort_key(&self, field: Field) -> SortKey {
            match field {
                Field::CreatedAt => OffsetDateTime::from_unix_timestamp(self.created_at)
                    .unwrap()
                    .into(),
                Field::Name => self.name.into(),
            }
        }

        fn tiebreak(&self) -> SortKey {
            Uuid::from_u128(self.id).into()
        }
    }

    fn rows() -> Vec<Row> {
        let names = ["Ann", "Bob", "Ann", "Cid", "Bob", "Ann", "Dee"];
        names
            .into_iter()
            .zip(0_u128..)
            .map(|(name, id)| Row {
                id,
                name,
                created_at: 1_700_000_000 + i64::try_from(id % 3).unwrap(),
            })
            .collect()
    }

    fn walk(sort: &SortOrder<Field>, limit: u32) -> Vec<Row> {
        let mut request = PageRequest::first(Limit::new(limit).unwrap());
        let mut seen = Vec::new();
        loop {
            let page = request.keyset(sort).unwrap().cut(rows());
            let following = request.following(&page);
            seen.extend(page.items);
            let Some(next) = following else {
                return seen;
            };
            request = next;
        }
    }

    /// Ann pages through seven rows whose names and times tie, a few at a
    /// time, in every order and page size. She sees every row exactly once,
    /// in the order of one full read.
    #[test]
    fn pages_read_on_without_gaps_or_repeats() {
        for order in [
            "name",
            "-name",
            "created_at",
            "-created_at,name",
            "name,-created_at",
        ] {
            let sort = SortOrder::<Field>::parse(Some(order)).unwrap();
            let whole = PageRequest::first(Limit::internal(100))
                .keyset(&sort)
                .unwrap()
                .cut(rows())
                .items;
            for limit in 1..=8 {
                assert_eq!(walk(&sort, limit), whole, "order {order}, limit {limit}");
            }
        }
    }

    /// A cursor from a name-sorted page is refused when the next request sorts by time.
    #[test]
    fn a_cursor_for_another_sort_is_refused() {
        let by_name = SortOrder::<Field>::parse(Some("name")).unwrap();
        let by_time = SortOrder::<Field>::parse(Some("created_at")).unwrap();
        let first = PageRequest::first(Limit::new(2).unwrap());
        let page = first.keyset(&by_name).unwrap().cut(rows());
        let second = first.following(&page).unwrap();

        let refused = second.keyset(&by_time).unwrap_err();

        assert_eq!(refused, InvalidCursor::OtherOrder);
    }

    /// The same cursor is refused when only the direction differs, since
    /// rows sit in another place in a reversed list.
    #[test]
    fn a_cursor_for_the_reversed_sort_is_refused() {
        let ascending = SortOrder::<Field>::parse(Some("name")).unwrap();
        let descending = SortOrder::<Field>::parse(Some("-name")).unwrap();
        let cursor = Cursor::after_row(&ascending, &rows()[0]);
        let request = PageRequest::new(Some(cursor), Limit::default());

        assert_eq!(
            request.keyset(&descending).unwrap_err(),
            InvalidCursor::OtherOrder
        );
    }

    /// A store that read exactly a page of rows answers no next page, so the
    /// caller is not sent to an empty one.
    #[test]
    fn a_full_last_page_has_no_next() {
        let sort = SortOrder::<Field>::default();
        let request = PageRequest::first(Limit::new(7).unwrap());

        let page = request.keyset(&sort).unwrap().cut(rows());

        assert_eq!((page.items.len(), page.has_next()), (7, false));
    }

    /// A store that read one row past the page answers the page without it,
    /// and a cursor at the page's last row.
    #[test]
    fn an_extra_row_becomes_the_next_cursor() {
        let sort = SortOrder::<Field>::parse(Some("name")).unwrap();
        let request = PageRequest::first(Limit::new(2).unwrap());
        let keyset = request.keyset(&sort).unwrap();

        let page = keyset.seal(rows()[..3].to_vec());

        assert_eq!(page.items, rows()[..2].to_vec());
        assert_eq!(page.next, Some(Cursor::after_row(&sort, &rows()[1])));
    }

    /// A list with no rows is one empty page with nothing after it.
    #[test]
    fn an_empty_list_is_one_empty_last_page() {
        let sort = SortOrder::<Field>::default();
        let request = PageRequest::default();

        let page = request.keyset(&sort).unwrap().cut(Vec::<Row>::new());

        assert!(page.is_empty() && !page.has_next());
    }
}
