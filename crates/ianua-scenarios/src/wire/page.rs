//! A page of a list the API answers a page at a time.

use serde::Deserialize;

/// One page of a list, and the cursor of the next.
#[derive(Debug, Clone, Deserialize)]
pub struct Page<T> {
    /// The items on this page, in the list's order.
    pub items: Vec<T>,
    /// The cursor of the next page, or `None` on the last.
    #[serde(default)]
    pub next_cursor: Option<String>,
    /// The most items a page holds.
    pub limit: u32,
}
