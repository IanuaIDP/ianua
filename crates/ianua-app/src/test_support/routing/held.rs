//! What the routing fakes do alike to the records they hold.

use std::sync::Mutex;

/// Drops every record of `held` that `matches`, as a `DELETE ... WHERE`
/// does.
///
/// # Panics
///
/// Panics if another test thread panicked while holding the records.
pub(super) fn remove_where<T>(held: &Mutex<Vec<T>>, matches: impl Fn(&T) -> bool) {
    held.lock().unwrap().retain(|entry| !matches(entry));
}
