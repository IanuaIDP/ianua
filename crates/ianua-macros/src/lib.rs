//! The procedural macros of the Ianua platform.
//!
//! Rust builds a procedural macro only in a crate of its own, so they live
//! here: [`Fakes`](macro@Fakes), which writes the test-only `fakes()`
//! constructor of a use case's ports struct, and
//! [`keyed_refusal!`](macro@keyed_refusal), which builds a refusal with its
//! message key and values. It depends on no crate of the platform: the
//! code it writes names only `crate::test_support::Fake`, under test
//! builds, and the refusal type its caller passes in.

#![cfg_attr(not(test), warn(clippy::too_many_lines))]

mod fakes;
mod refusal;

use proc_macro::TokenStream;

/// A refusal carrying its message key and the values its English text was
/// filled with: `keyed_refusal!(path::to::Refusal, "key", message)`.
///
/// Code names it through the domain's `message!("key", message)`, which
/// supplies the path. The message is literal text, a `format!` call, or
/// any other expression that reads as text.
///
/// # Panics
///
/// Produces a compile error if the input is not a path, a key and a message.
#[proc_macro]
pub fn keyed_refusal(input: TokenStream) -> TokenStream {
    refusal::expand(input.into())
        .unwrap_or_else(|e| e.to_compile_error())
        .into()
}

/// Derives a test-only `fakes()` constructor for a use case's ports struct.
///
/// Every field becomes `crate::test_support::Fake::fake()`, so a test names
/// only the ports it is about and takes the rest from `..Ports::fakes()`.
/// The constructor exists only under `cfg(any(test, feature = "test-support"))`.
///
/// # Panics
///
/// Produces a compile error if the input is not a struct with named fields.
#[proc_macro_derive(Fakes)]
pub fn derive_fakes(item: TokenStream) -> TokenStream {
    fakes::expand(item.into())
        .unwrap_or_else(|e| e.to_compile_error())
        .into()
}
