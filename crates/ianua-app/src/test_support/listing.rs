//! Keyset paging in memory, as the SQL `WHERE (sort, id) > (cursor)`,
//! `ORDER BY` and `LIMIT` do.

use ianua_domain::shared::errors::DomainError;

use crate::listing::{Page, PageRequest, RowKeys};

/// The page of `items` that `request` asks for in `order`: ordered, read on
/// past the cursor, one row past the limit read to learn whether a next page
/// exists.
///
/// # Errors
///
/// Returns a validation error when the cursor was made for another order, as
/// a store does.
pub(crate) fn page<T, O: RowKeys<T>>(
    items: Vec<T>,
    order: &O,
    request: &PageRequest,
) -> Result<Page<T>, DomainError> {
    Ok(request.keyset(order)?.cut(items))
}
