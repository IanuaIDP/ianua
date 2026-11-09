//! Listing: keyset paging and ordering for list queries.
//!
//! A list query names its order ([`SortOrder`]) and where to start
//! ([`PageRequest`]). A store answers one [`Page`] and, when more rows
//! follow, a [`Cursor`] at the last row it gave. The next request passes that
//! cursor back, and the store reads on from it with
//! `WHERE (sort, id) > (cursor)` instead of skipping rows, so the tenth page
//! costs what the first does.

mod cursor;
mod keys;
mod limit;
mod pagination;
mod sorting;

pub use cursor::*;
pub use keys::*;
pub use limit::*;
pub use pagination::*;
pub use sorting::*;
