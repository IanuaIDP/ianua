// Tests stop immediately when a fixture or an asserted result is invalid.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
#![cfg_attr(not(test), warn(clippy::too_many_lines))]
#![warn(unreachable_pub)]
#![warn(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links, rustdoc::private_intra_doc_links)]
#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(
        clippy::wildcard_enum_match_arm,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::todo,
        clippy::unimplemented,
        clippy::dbg_macro,
        clippy::indexing_slicing,
        clippy::string_slice,
        clippy::arithmetic_side_effects,
        clippy::cast_possible_truncation,
        clippy::cast_possible_wrap,
        clippy::cast_sign_loss
    )
)]
//! The domain layer of Ianua: aggregates, value objects, domain events and
//! the port traits the outer layers implement.
//!
//! It is pure and synchronous. It has no I/O, no async runtime and no
//! database or HTTP types. Async signatures belong to port traits.

/// The bounded contexts, one module each.
pub mod domains;
/// Scope markers that keep the tenant and organization planes apart.
/// Separating one tenant from another happens at run time, in the stores.
pub mod isolation;
/// Code every context shares: errors, events, clock, validation.
pub mod shared;
/// Test doubles for domain ports.
///
/// Only tests reach these, and a test that builds bad data should stop at
/// once, so the no-panic rules of the rest of the crate do not apply here.
#[cfg(any(test, feature = "test-support"))]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::arithmetic_side_effects
)]
pub mod test_support;
/// Value objects shared across contexts: ids, names, event types, secrets.
pub mod types;

/// The procedural macro behind [`message!`], reached only through it.
#[doc(hidden)]
pub mod __private {
    pub use ianua_macros::keyed_refusal;
}

/// A [`Refusal`](shared::errors::Refusal) with its message key and the
/// values its English text was filled with.
///
/// The key names the message in the Fluent resources, so a caller reads
/// the refusal in its own language; the English text is kept for logs and
/// for callers that read no key. The message is literal text, a `format!`
/// call, whose fields become named values, or any expression that reads
/// as text.
///
/// ```
/// let name = "Ann";
/// let refusal = ianua_domain::message!("people-is-taken", format!("{name} is taken"));
/// assert_eq!(refusal.as_str(), "Ann is taken");
/// assert_eq!(refusal.key(), Some("people-is-taken"));
/// ```
#[macro_export]
macro_rules! message {
    ($key:literal, $($message:tt)+) => {
        $crate::__private::keyed_refusal!($crate::shared::errors::Refusal, $key, $($message)+)
    };
}
