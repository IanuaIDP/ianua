//! A tenant's custom CSS made safe to place in a page.
//!
//! The stylesheet is read the way a browser reads it, tokens first
//! (`tokens`) and rules from them (`sheet`), both following the CSS
//! Syntax Module Level 3, and written back through an allow-list
//! ([`AllowListCssSanitizer`]). The reader is written here rather than
//! taken from a library: it is small, needs no recursion, and keeps only
//! what the allow-list asks of it, and the domain checks what it writes
//! once more. A library such as `cssparser` can take the place of the two
//! reading modules behind the same `Rule` and `Token` shapes.

mod sanitizer;
mod sheet;
mod tokens;

pub use sanitizer::AllowListCssSanitizer;
